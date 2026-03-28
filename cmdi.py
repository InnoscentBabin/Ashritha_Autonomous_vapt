"""
Command Injection Testing Module
"""

import requests
import logging
import time
from typing import Dict, Any, Optional
from urllib.parse import urlencode

logger = logging.getLogger(__name__)

class CommandInjectionTester:
    """Command Injection vulnerability tester"""
    
    def __init__(self, ai_engine):
        self.ai_engine = ai_engine
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.max_attempts = 5
        self.used_payloads = []
        self.timeout = 10
    
    def test(self, vulnerability: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Test for command injection"""
        endpoint = vulnerability.get('endpoint')
        method = vulnerability.get('method', 'GET')
        parameter = vulnerability.get('parameter')
        
        logger.info(f"Testing Command Injection on {endpoint}, parameter: {parameter}")
        
        # Common command injection payloads
        common_payloads = [
            "; whoami",
            "| whoami",
            "&& whoami",
            "|| whoami",
            "`whoami`",
            "$(whoami)"
        ]
        
        # Test common payloads
        for payload in common_payloads[:3]:
            response = self._send_request(endpoint, method, parameter, payload)
            
            if response and self._quick_check(response.text):
                return {
                    'vulnerable': True,
                    'vulnerability': 'Command Injection',
                    'endpoint': endpoint,
                    'method': method,
                    'parameter': parameter,
                    'payload': payload,
                    'evidence': 'Command output detected',
                    'details': {'quick_test': True}
                }
            
            time.sleep(0.5)
        
        # Test with AI-generated payloads
        for attempt in range(min(self.max_attempts, 3)):
            context = {
                'url': endpoint,
                'parameter': parameter,
                'used_payloads': self.used_payloads
            }
            
            payload = self.ai_engine.generate_payload('Command Injection', context)
            self.used_payloads.append(payload)
            
            response = self._send_request(endpoint, method, parameter, payload)
            
            if response:
                analysis = self.ai_engine.analyze_response(response.text, 'Command Injection')
                
                if analysis.get('vulnerable'):
                    return {
                        'vulnerable': True,
                        'vulnerability': 'Command Injection',
                        'endpoint': endpoint,
                        'method': method,
                        'parameter': parameter,
                        'payload': payload,
                        'evidence': analysis.get('evidence', 'Command injection detected'),
                        'details': {'attempt': attempt + 1}
                    }
            
            time.sleep(0.5)
        
        return None
    
    def _quick_check(self, response_text: str) -> bool:
        """Quick pattern-based command injection check"""
        patterns = [
            'uid=', 'gid=', 'groups=',
            'root:', 'bin:', 'usr:',
            'Microsoft Windows', 'Linux version',
            'command not found', 'Access denied'
        ]
        
        response_lower = response_text.lower()
        return any(pattern.lower() in response_lower for pattern in patterns)
    
    def _send_request(self, url: str, method: str, param: str, payload: str) -> Optional[requests.Response]:
        """Send HTTP request with payload"""
        try:
            if method.upper() == 'GET':
                if '?' in url:
                    base_url, query = url.split('?', 1)
                    params = dict(p.split('=', 1) for p in query.split('&') if '=' in p)
                    params[param] = payload
                    new_url = f"{base_url}?{urlencode(params)}"
                else:
                    new_url = f"{url}?{param}={payload}"
                
                return self.session.get(new_url, timeout=self.timeout)
            else:
                data = {param: payload}
                return self.session.post(url, data=data, timeout=self.timeout)
                
        except Exception as e:
            logger.debug(f"Request failed: {e}")
            return None