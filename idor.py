"""
IDOR Testing Module
"""

import requests
import logging
import time
from typing import Dict, Any, Optional
from urllib.parse import urlencode

logger = logging.getLogger(__name__)

class IDORTester:
    """IDOR vulnerability tester"""
    
    def __init__(self, ai_engine):
        self.ai_engine = ai_engine
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.max_attempts = 5
        self.timeout = 10
        self.baseline_response = None
    
    def test(self, vulnerability: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Test for IDOR"""
        endpoint = vulnerability.get('endpoint')
        method = vulnerability.get('method', 'GET')
        parameter = vulnerability.get('parameter')
        
        logger.info(f"Testing IDOR on {endpoint}, parameter: {parameter}")
        
        # Get baseline response
        if not self.baseline_response:
            self.baseline_response = self._send_request(endpoint, method, parameter, '1')
        
        # Test ID variations
        test_ids = ['0', '2', '3', '5', '10', '100', '999', 'admin', 'test']
        
        for test_id in test_ids[:self.max_attempts]:
            response = self._send_request(endpoint, method, parameter, test_id)
            
            if response and response.status_code == 200:
                # Check if response is different from baseline
                if self.baseline_response and response.text != self.baseline_response.text:
                    return {
                        'vulnerable': True,
                        'vulnerability': 'IDOR',
                        'endpoint': endpoint,
                        'method': method,
                        'parameter': parameter,
                        'payload': test_id,
                        'evidence': f'Different content returned for ID {test_id}',
                        'details': {
                            'tested_id': test_id,
                            'response_length': len(response.text),
                            'baseline_length': len(self.baseline_response.text)
                        }
                    }
            
            time.sleep(0.5)
        
        return None
    
    def _send_request(self, url: str, method: str, param: str, value: str) -> Optional[requests.Response]:
        """Send HTTP request with modified parameter"""
        try:
            if method.upper() == 'GET':
                if '?' in url:
                    base_url, query = url.split('?', 1)
                    params = dict(p.split('=', 1) for p in query.split('&') if '=' in p)
                    params[param] = value
                    new_url = f"{base_url}?{urlencode(params)}"
                else:
                    new_url = f"{url}?{param}={value}"
                
                return self.session.get(new_url, timeout=self.timeout, allow_redirects=False)
            else:
                data = {param: value}
                return self.session.post(url, data=data, timeout=self.timeout, allow_redirects=False)
                
        except Exception as e:
            logger.debug(f"Request failed: {e}")
            return None