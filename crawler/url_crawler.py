"""
URL Crawler - With URL Filtering to Skip Non-HTML Files
"""

from bs4 import BeautifulSoup
from urllib.parse import urlparse
from collections import deque
import time
import sys
import os
import re

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crawler.utils import NetworkUtils, URLUtils, FileUtils
from crawler.input_detector import InputDetector
from config import DELAY_BETWEEN_REQUESTS, MAX_URLS, URLS_DIR

class URLCrawler:
    """Main URL crawler that discovers and processes all URLs in a domain"""
    
    # File extensions to skip (non-HTML files)
    SKIP_EXTENSIONS = {
        # Images
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.webp', 
        '.tiff', '.tif', '.psd', '.raw',
        
        # Documents
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', 
        '.txt', '.rtf', '.odt', '.ods', '.odp',
        
        # Archives
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.tgz',
        
        # Media
        '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.webm',
        '.m4v', '.mpg', '.mpeg', '.3gp',
        
        # Executables
        '.exe', '.msi', '.dmg', '.app', '.deb', '.rpm', '.bin', '.sh',
        
        # Web resources
        '.css', '.js', '.json', '.xml', '.rss', '.atom', '.map', '.scss', 
        '.less', '.sass', '.styl',
        
        # Fonts
        '.woff', '.woff2', '.ttf', '.eot', '.otf', '.fon',
        
        # Other static files
        '.csv', '.log', '.bak', '.tmp', '.swp', '.sql', '.py', '.java',
        '.c', '.cpp', '.h', '.php', '.asp', '.aspx', '.jsp'
    }
    
    # Extensions that are HTML-like (should crawl)
    HTML_EXTENSIONS = {
        '.html', '.htm', '.php', '.asp', '.aspx', '.jsp', '.do', 
        '.action', '.cgi', '.pl', '.py', '',  # Empty extension
        '.cfm', '.cfml', '.dhtml', '.shtml', '.xhtml'
    }
    
    def __init__(self, start_url):
        self.start_url = start_url
        self.domain = self._clean_domain(URLUtils.get_domain(start_url))
        self.visited_urls = set()
        self.url_queue = deque([start_url])
        self.discovered_urls = {}
        self.skipped_urls = {}  # Track skipped URLs
        self.network_utils = NetworkUtils()
        self.url_utils = URLUtils()
        self.file_utils = FileUtils()
        self.input_detector = InputDetector()
        self.session = self.network_utils.get_session_with_retries()
        self.stats = {
            'html_pages': 0,
            'skipped_files': 0,
            'errors': 0
        }
        
    def _clean_domain(self, domain):
        """Clean domain name for filename usage"""
        if not domain:
            return "unknown_domain"
        
        # Remove any byte string artifacts
        domain = str(domain)
        
        # Remove b'' prefix if present
        if domain.startswith("b'") and domain.endswith("'"):
            domain = domain[2:-1]
        elif domain.startswith('b"') and domain.endswith('"'):
            domain = domain[2:-1]
        
        # Remove any non-alphanumeric characters except dots and hyphens
        domain = re.sub(r'[^\w\-\.]', '_', domain)
        
        # Remove multiple underscores
        domain = re.sub(r'_+', '_', domain)
        
        # Remove leading/trailing underscores
        domain = domain.strip('_')
        
        return domain
    
    def _should_crawl_url(self, url):
        """Determine if URL should be crawled based on extension"""
        if not url:
            return False, "Empty URL"
        
        # Skip JavaScript and anchor links
        if url.startswith('#') or url.startswith('javascript:'):
            return False, "JavaScript or anchor link"
        
        # Parse the URL
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Get file extension
        extension = os.path.splitext(path)[1].lower()
        
        # Check if extension is in skip list
        if extension in self.SKIP_EXTENSIONS:
            return False, f"Skipped extension: {extension}"
        
        # Check if it's HTML-like
        if extension in self.HTML_EXTENSIONS or not extension:
            return True, "HTML page"
        
        # If URL has query parameters without extension, likely dynamic page
        if not extension and parsed.query:
            return True, "Dynamic page with parameters"
        
        # Default to crawl for URLs without extension
        if not extension:
            return True, "No extension - likely HTML"
        
        return True, "Will crawl"
    
    def _is_valid_html_response(self, response):
        """Check if response is HTML content"""
        content_type = response.headers.get('Content-Type', '').lower()
        
        # Check if content type is HTML
        if 'text/html' in content_type:
            return True
        
        # Check for common HTML patterns in content
        if response.text and response.text.strip().startswith('<!DOCTYPE'):
            return True
        
        return False
    
    def crawl(self):
        """Start the crawling process"""
        print(f"Starting crawl for domain: {self.domain}")
        print(f"Start URL: {self.start_url}")
        print(f"Filtering out non-HTML files (images, PDFs, CSS, JS, etc.)")
        print("="*60)
        
        while self.url_queue and len(self.visited_urls) < MAX_URLS:
            current_url = self.url_queue.popleft()
            
            if current_url in self.visited_urls:
                continue
            
            # Check if we should crawl this URL
            should_crawl, reason = self._should_crawl_url(current_url)
            
            if not should_crawl:
                print(f"Skipping {current_url} - {reason}")
                self.visited_urls.add(current_url)
                self.stats['skipped_files'] += 1
                
                # Track skipped URL
                self.skipped_urls[current_url] = {
                    'url': current_url,
                    'reason': reason,
                    'timestamp': time.strftime('%Y%m%d_%H%M%S')
                }
                continue
                
            print(f"Crawling ({len(self.visited_urls)}/{MAX_URLS}): {current_url}")
            
            # Fetch and process URL
            self._process_url(current_url)
            
            # Add delay to be respectful to the server
            time.sleep(DELAY_BETWEEN_REQUESTS)
            
        print(f"\nCrawling completed!")
        print(f"Total URLs crawled: {len(self.visited_urls)}")
        print(f"Total URLs discovered: {len(self.discovered_urls)}")
        print(f"Skipped URLs (non-HTML): {self.stats['skipped_files']}")
        
        # Save results
        self._save_results()
        
        # Save input field data
        input_summary = self.input_detector.save_input_fields(self.domain)
        print(f"\nInput fields detected: {input_summary['total_inputs_found']}")
        print(f"Authentication pages found: {input_summary['total_auth_pages']}")
        
        return self.discovered_urls
    
    def _process_url(self, url):
        """Process a single URL: fetch, parse, extract URLs and inputs"""
        response = self.network_utils.safe_request(url, self.session)
        
        if not response:
            self.visited_urls.add(url)
            self.stats['errors'] += 1
            return
        
        # Check if response is HTML
        if not self._is_valid_html_response(response):
            print(f"  Skipping non-HTML content: {url}")
            self.visited_urls.add(url)
            self.stats['skipped_files'] += 1
            return
        
        # Parse HTML
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Detect input fields on this page
        try:
            page_inputs = self.input_detector.detect_inputs(soup, url)
            print(f"  Found {page_inputs['total_inputs']} input fields and {page_inputs['total_forms']} forms")
            self.stats['html_pages'] += 1
        except Exception as e:
            print(f"  Error detecting inputs: {e}")
        
        # Extract all links
        self._extract_links(soup, url)
        
        # Mark as visited
        self.visited_urls.add(url)
        
    def _extract_links(self, soup, base_url):
        """Extract all links from the page and filter them"""
        links_found = 0
        links_added = 0
        
        for link in soup.find_all(['a', 'link'], href=True):
            href = link.get('href')
            if not href or href.startswith('#') or href.startswith('javascript:'):
                continue
                
            # Normalize URL
            full_url = self.url_utils.normalize_url(href, base_url)
            
            if not full_url:
                continue
                
            # Check if URL belongs to same domain
            if self.url_utils.is_same_domain(full_url, self.start_url):
                links_found += 1
                
                # Check if we should crawl this URL
                should_crawl, reason = self._should_crawl_url(full_url)
                
                if not should_crawl:
                    # Track skipped URL
                    if full_url not in self.skipped_urls:
                        self.skipped_urls[full_url] = {
                            'url': full_url,
                            'reason': reason,
                            'found_on': base_url,
                            'timestamp': time.strftime('%Y%m%d_%H%M%S')
                        }
                    continue
                
                # Remove fragments for deduplication
                parsed = urlparse(full_url)
                clean_url = parsed._replace(fragment='').geturl()
                
                if clean_url not in self.discovered_urls and clean_url not in self.visited_urls:
                    self.discovered_urls[clean_url] = {
                        'url': clean_url,
                        'original_url': full_url,
                        'found_on': base_url,
                        'status': 'pending'
                    }
                    self.url_queue.append(clean_url)
                    links_added += 1
        
        if links_found > 0:
            print(f"    Found {links_found} links, added {links_added} new URLs")
    
    def _remove_fragment(self, url):
        """Remove fragment identifier from URL"""
        parsed = urlparse(url)
        return parsed._replace(fragment='').geturl()
    
    def _save_results(self):
        """Save crawling results to JSON file with clean filename"""
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        
        # Create clean filename
        clean_domain = self._clean_domain(self.domain)
        
        # Save all discovered URLs
        urls_data = {
            'domain': self.domain,
            'start_url': self.start_url,
            'timestamp': timestamp,
            'statistics': self.stats,
            'total_urls': len(self.discovered_urls),
            'crawled_urls': len(self.visited_urls),
            'skipped_urls': len(self.skipped_urls),
            'urls': list(self.discovered_urls.values())
        }
        
        urls_file = URLS_DIR / f'{clean_domain}_all_urls_{timestamp}.json'
        self.file_utils.save_json(urls_data, urls_file)
        
        # Save skipped URLs for reference
        if self.skipped_urls:
            skipped_data = {
                'total_skipped': len(self.skipped_urls),
                'skipped_urls': list(self.skipped_urls.values())
            }
            skipped_file = URLS_DIR / f'{clean_domain}_skipped_urls_{timestamp}.json'
            self.file_utils.save_json(skipped_data, skipped_file)
            print(f"  Skipped URLs saved to: {skipped_file}")
        
        # Save summary
        summary = {
            'domain': self.domain,
            'start_url': self.start_url,
            'timestamp': timestamp,
            'statistics': self.stats,
            'total_urls_discovered': len(self.discovered_urls),
            'total_urls_crawled': len(self.visited_urls),
            'urls_crawled_list': list(self.visited_urls)
        }
        
        summary_file = URLS_DIR / f'{clean_domain}_summary_{timestamp}.json'
        self.file_utils.save_json(summary, summary_file)
        
        print(f"\nResults saved to: {URLS_DIR}")
        print(f"Files:")
        print(f"  - {clean_domain}_all_urls_{timestamp}.json")
        print(f"  - {clean_domain}_summary_{timestamp}.json")
        if self.skipped_urls:
            print(f"  - {clean_domain}_skipped_urls_{timestamp}.json")