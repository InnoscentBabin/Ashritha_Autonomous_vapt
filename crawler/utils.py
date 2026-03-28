"""
Utility functions - Updated with URL filtering
"""

import hashlib
import json
from urllib.parse import urljoin, urlparse
import time
import requests
import re
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from config import USER_AGENT, REQUEST_TIMEOUT, MAX_RETRIES

class NetworkUtils:
    """Network related utility functions"""
    
    @staticmethod
    def get_session_with_retries():
        """Create a requests session with retry strategy"""
        session = requests.Session()
        retry_strategy = Retry(
            total=MAX_RETRIES,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({'User-Agent': USER_AGENT})
        return session
    
    @staticmethod
    def safe_request(url, session):
        """Make a safe HTTP request with timeout"""
        try:
            response = session.get(url, timeout=REQUEST_TIMEOUT, stream=True)
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            print(f"Error fetching {url}: {e}")
            return None

class URLUtils:
    """URL processing utility functions"""
    
    @staticmethod
    def normalize_url(url, base_url):
        """Normalize URL by joining with base URL"""
        try:
            return urljoin(base_url, url.strip())
        except:
            return None
    
    @staticmethod
    def is_same_domain(url, domain):
        """Check if URL belongs to the same domain"""
        try:
            parsed_url = urlparse(url)
            parsed_domain = urlparse(domain)
            return parsed_url.netloc == parsed_domain.netloc or \
                   parsed_url.netloc.endswith(f'.{parsed_domain.netloc}')
        except:
            return False
    
    @staticmethod
    def get_domain(url):
        """Extract domain from URL and clean it"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Clean the domain
            if domain:
                # Remove port number if present
                domain = domain.split(':')[0]
                # Convert to string and clean
                domain = str(domain)
                # Remove any byte string artifacts
                if domain.startswith("b'") and domain.endswith("'"):
                    domain = domain[2:-1]
                elif domain.startswith('b"') and domain.endswith('"'):
                    domain = domain[2:-1]
            
            return domain
        except:
            return None
    
    @staticmethod
    def generate_url_id(url):
        """Generate unique ID for URL"""
        return hashlib.md5(url.encode()).hexdigest()
    
    @staticmethod
    def get_file_extension(url):
        """Extract file extension from URL"""
        parsed = urlparse(url)
        path = parsed.path
        return os.path.splitext(path)[1].lower()
    
    @staticmethod
    def is_html_url(url):
        """Check if URL likely points to HTML content"""
        extension = URLUtils.get_file_extension(url)
        html_extensions = {'.html', '.htm', '.php', '.asp', '.aspx', '.jsp', '.do', ''}
        return extension in html_extensions

class FileUtils:
    """File handling utility functions"""
    
    @staticmethod
    def save_json(data, filepath):
        """Save data to JSON file"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error saving JSON to {filepath}: {e}")
            return False
    
    @staticmethod
    def load_json(filepath):
        """Load data from JSON file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading JSON from {filepath}: {e}")
            return None