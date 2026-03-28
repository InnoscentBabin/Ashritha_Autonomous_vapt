"""
Main Integration Logic - Enhanced with Adaptive Testing
"""

import json
import logging
import os
import time
from datetime import datetime
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs

from ai_engine import AIEngine
from classifier import VulnerabilityClassifier
from sqli import SQLInjectionTester
from xss import XSSTester
from cmdi import CommandInjectionTester
from idor import IDORTester
from auth import AuthTester

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class IntegratedPentestingTool:
    """Complete integrated pentesting tool with adaptive testing"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.tool_name = self.config.get('tool_name', 'ASHRITHA')
        self.ai_model = self.config.get('ai_model', 'gemma3:1b')
        self.ai_engine = AIEngine(model=self.ai_model)
        self.classifier = VulnerabilityClassifier()
        self.crawler = None
        self.crawl_results = {}
        self.vulnerabilities = []
        self.processed_endpoints = set()
        
        # Initialize testers with adaptive engines
        self.testers = {
            'SQL Injection': SQLInjectionTester(self.ai_engine),
            'XSS': XSSTester(self.ai_engine),
            'Command Injection': CommandInjectionTester(self.ai_engine),
            'IDOR': IDORTester(self.ai_engine),
            'Authentication': AuthTester(self.ai_engine)
        }
        
        # Configuration
        self.min_confidence = self.config.get('min_confidence', 'medium')
        self.max_attempts = self.config.get('max_attempts', 5)
        self.adaptive_depth = self.config.get('adaptive_depth', 3)
        self.output_dir = self.config.get('output_dir', 'pentest_results')
        self.quick_mode = self.config.get('quick_mode', False)
        
        logger.info(f"{self.tool_name} initialized with model: {self.ai_model}")
    
    def crawl_website(self, start_url: str, max_urls: int = 50, delay: float = 0.5):
        """Perform crawling"""
        from crawler.url_crawler import URLCrawler
        import config as crawler_config
        
        crawler_config.MAX_URLS = max_urls
        crawler_config.DELAY_BETWEEN_REQUESTS = delay
        
        logger.info(f"[{self.tool_name}] Starting crawler for: {start_url}")
        self.crawler = URLCrawler(start_url)
        self.crawler.crawl()
        
        self.crawl_results = {
            'tool_name': self.tool_name,
            'domain': self.crawler.domain,
            'start_url': start_url,
            'timestamp': datetime.now().isoformat(),
            'input_fields_data': self.crawler.input_detector.input_fields_data,
            'auth_pages': self.crawler.input_detector.auth_pages_data,
            'statistics': {
                'pages_crawled': len(self.crawler.visited_urls),
                'urls_discovered': len(self.crawler.discovered_urls),
                'pages_with_inputs': len(self.crawler.input_detector.input_fields_data),
                'auth_pages': len(self.crawler.input_detector.auth_pages_data)
            }
        }
        
        logger.info(f"[{self.tool_name}] Crawling complete. Found {len(self.crawler.visited_urls)} pages")
    
    def load_crawl_results(self, file_path: str) -> bool:
        """Load previously saved crawl results"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if 'input_fields_data' in data:
                self.crawl_results = data
                logger.info(f"[{self.tool_name}] Loaded crawl data with {len(data.get('input_fields_data', {}))} pages")
            else:
                self.crawl_results = data
                logger.info(f"[{self.tool_name}] Loaded crawl results")
            
            return True
        except Exception as e:
            logger.error(f"[{self.tool_name}] Failed to load crawl results: {e}")
            return False
    
    def convert_to_endpoints(self) -> List[Dict[str, Any]]:
        """Convert crawl data to testable endpoints"""
        endpoints = []
        self.processed_endpoints.clear()
        
        if 'input_fields_data' in self.crawl_results:
            for url, page_data in self.crawl_results['input_fields_data'].items():
                url = self._clean_url(url)
                
                for form in page_data.get('forms', []):
                    endpoint = {
                        'url': url,
                        'method': form.get('method', 'POST').upper(),
                        'parameters': {}
                    }
                    
                    param_limit = 3 if self.quick_mode else 5
                    param_count = 0
                    
                    for input_field in form.get('inputs', []):
                        param_name = input_field.get('name')
                        if param_name and param_count < param_limit:
                            endpoint['parameters'][param_name] = 'test'
                            param_count += 1
                    
                    if endpoint['parameters'] and self._is_unique_endpoint(endpoint):
                        endpoints.append(endpoint)
        
        logger.info(f"[{self.tool_name}] Converted {len(endpoints)} endpoints for testing")
        return endpoints
    
    def _clean_url(self, url):
        """Clean URL"""
        if not url:
            return ""
        url = str(url)
        if url.startswith("b'") and url.endswith("'"):
            url = url[2:-1]
        return url
    
    def _is_unique_endpoint(self, endpoint: Dict[str, Any]) -> bool:
        """Check if endpoint is unique"""
        url = self._clean_url(endpoint.get('url', ''))
        key = f"{url}_{endpoint.get('method', 'GET')}"
        if key in self.processed_endpoints:
            return False
        self.processed_endpoints.add(key)
        return True
    
    def classify_vulnerabilities(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Classify vulnerabilities"""
        if not endpoints:
            return []
        
        logger.info(f"[{self.tool_name}] Classifying {len(endpoints)} endpoints...")
        all_classifications = []
        
        for i, endpoint in enumerate(endpoints, 1):
            clean_url = self._clean_url(endpoint.get('url', ''))
            logger.info(f"  [{i}/{len(endpoints)}] Analyzing: {clean_url}")
            logger.info(f"      Params: {list(endpoint.get('parameters', {}).keys())}")
            
            try:
                classifications = self.classifier.classify_endpoint(endpoint)
                if classifications:
                    all_classifications.extend(classifications)
                    for vuln in classifications:
                        logger.info(f"    ✓ {vuln.get('vulnerability')} on {vuln.get('parameter')} ({vuln.get('confidence')})")
                else:
                    logger.info(f"    ✗ No vulnerabilities detected")
            except Exception as e:
                logger.error(f"    Error: {e}")
            
            time.sleep(0.3)
        
        logger.info(f"[{self.tool_name}] Total classifications: {len(all_classifications)}")
        return all_classifications
    
    def test_vulnerabilities(self, classifications: List[Dict[str, Any]]):
        """Test vulnerabilities with adaptive depth"""
        if not classifications:
            logger.info(f"[{self.tool_name}] No vulnerabilities to test")
            return
        
        logger.info("\n" + "="*60)
        logger.info(f"[{self.tool_name}] Testing {len(classifications)} vulnerabilities (adaptive depth: {self.adaptive_depth})")
        logger.info("="*60)
        
        confidence_order = {'high': 0, 'medium': 1, 'low': 2}
        classifications.sort(key=lambda x: confidence_order.get(x.get('confidence', 'low'), 2))
        
        tested = set()
        
        for vuln in classifications:
            vulnerability = vuln.get('vulnerability')
            confidence = vuln.get('confidence', 'low')
            endpoint = self._clean_url(vuln.get('endpoint', ''))
            parameter = vuln.get('parameter')
            
            test_key = f"{endpoint}_{parameter}_{vulnerability}"
            if test_key in tested:
                continue
            tested.add(test_key)
            
            if self.quick_mode and confidence == 'low':
                logger.info(f"Skipping {vulnerability} on {endpoint} (low confidence)")
                continue
            
            logger.info(f"\nTesting {vulnerability} ({confidence})")
            logger.info(f"  Endpoint: {endpoint}")
            logger.info(f"  Parameter: {parameter}")
            
            tester = self.testers.get(vulnerability)
            if tester:
                try:
                    # Set attempts based on adaptive depth
                    if confidence == 'high':
                        tester.max_attempts = self.adaptive_depth
                    elif confidence == 'medium':
                        tester.max_attempts = max(2, self.adaptive_depth - 1)
                    else:
                        tester.max_attempts = 1
                    
                    result = tester.test(vuln)
                    if result and result.get('vulnerable'):
                        self.vulnerabilities.append(result)
                        self._print_finding(result)
                    else:
                        logger.info(f"  ✗ Not vulnerable")
                        
                except Exception as e:
                    logger.error(f"  Error: {e}")
    
    def _print_finding(self, finding: Dict[str, Any]):
        """Print vulnerability finding"""
        print("\n" + "!"*60)
        print(f"[!] {self.tool_name} - VULNERABILITY CONFIRMED!")
        print("!"*60)
        print(f"Type: {finding.get('vulnerability')}")
        print(f"Endpoint: {self._clean_url(finding.get('endpoint', ''))}")
        print(f"Parameter: {finding.get('parameter')}")
        print(f"Payload: {finding.get('payload')}")
        print(f"Evidence: {finding.get('evidence')}")
        if finding.get('details'):
            print(f"Details: {json.dumps(finding.get('details'), indent=2)}")
        print("!"*60 + "\n")
    
    def save_results(self):
        """Save results"""
        os.makedirs(self.output_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        vuln_file = os.path.join(self.output_dir, f'{self.tool_name.lower()}_vulnerabilities_{timestamp}.json')
        with open(vuln_file, 'w', encoding='utf-8') as f:
            json.dump({
                'tool_name': self.tool_name,
                'timestamp': timestamp,
                'total_vulnerabilities': len(self.vulnerabilities),
                'findings': self.vulnerabilities,
                'config': self.config
            }, f, indent=2, default=str)
        
        logger.info(f"[{self.tool_name}] Results saved to {vuln_file}")
        
        if self.crawl_results:
            crawl_file = os.path.join(self.output_dir, f'{self.tool_name.lower()}_crawl_data_{timestamp}.json')
            with open(crawl_file, 'w', encoding='utf-8') as f:
                json.dump(self.crawl_results, f, indent=2, default=str)
            logger.info(f"[{self.tool_name}] Crawl data saved to {crawl_file}")
        
        self._print_summary()
    
    def _print_summary(self):
        """Print summary"""
        print("\n" + "="*60)
        print(f"{self.tool_name} - FINAL SUMMARY")
        print("="*60)
        print(f"\nVulnerabilities Found: {len(self.vulnerabilities)}")
        
        if self.vulnerabilities:
            vuln_types = {}
            for vuln in self.vulnerabilities:
                vtype = vuln.get('vulnerability')
                vuln_types[vtype] = vuln_types.get(vtype, 0) + 1
            
            print("\nDetails:")
            for vtype, count in vuln_types.items():
                print(f"  - {vtype}: {count}")
        else:
            print("\n  No vulnerabilities confirmed.")
        
        print("="*60 + "\n")