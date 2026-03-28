"""
XSS Testing Module - Fully Adaptive
"""

import requests
import logging
import time
import re
from typing import Dict, Any, Optional
from urllib.parse import urlencode

from adaptive_engine import AdaptivePayloadEngine
from response_analyzer import ResponseAnalyzer
from payload_generator import PayloadGenerator

logger = logging.getLogger(__name__)

class XSSTester:
    """Adaptive XSS tester with context-aware payload generation"""
    
    def __init__(self, ai_engine):
        self.ai_engine = ai_engine
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.max_attempts = 5
        self.used_payloads = []
        self.timeout = 10
        self.reflection_context = None
        self.filtered = False
        
        # Initialize new components
        self.adaptive_engine = AdaptivePayloadEngine(ai_engine)
        self.response_analyzer = ResponseAnalyzer()
        self.payload_generator = PayloadGenerator()
    
    def test(self, vulnerability: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Test for XSS with adaptive payloads"""
        endpoint = vulnerability.get('endpoint')
        method = vulnerability.get('method', 'GET')
        parameter = vulnerability.get('parameter')
        
        logger.info(f"Testing XSS on {endpoint}, parameter: {parameter}")
        
        # Phase 1: Detect reflection context
        if not self.reflection_context:
            self.reflection_context = self._detect_reflection_context(endpoint, method, parameter)
            logger.info(f"Reflection context: {self.reflection_context}")
        
        previous_response = None
        previous_payload = None
        
        for attempt in range(self.max_attempts):
            logger.info(f"  Attempt {attempt + 1}/{self.max_attempts}")
            
            # Generate adaptive payload
            context = {
                'parameter': parameter,
                'url': endpoint,
                'method': method,
                'attempt': attempt,
                'previous_response': previous_response,
                'previous_payload': previous_payload,
                'used_payloads': self.used_payloads,
                'reflection_context': self.reflection_context,
                'filtered': self.filtered
            }
            
            payload = self.adaptive_engine.generate_payload('XSS', context)
            self.used_payloads.append(payload)
            
            logger.debug(f"  Testing payload: {payload[:50]}...")
            
            # Send request
            response = self._send_request(endpoint, method, parameter, payload)
            
            if not response:
                continue
            
            # Analyze response
            analysis = self.response_analyzer.analyze_xss_response(response.text, payload)
            
            # Record response
            self.adaptive_engine.record_response(response.text, payload, analysis['vulnerable'])
            
            if analysis['vulnerable']:
                logger.info(f"  ✓ XSS Confirmed!")
                logger.info(f"  Context: {analysis.get('context', 'Unknown')}")
                logger.info(f"  Reflection: {analysis.get('reflection_type', 'direct')}")
                
                return {
                    'vulnerable': True,
                    'vulnerability': 'XSS',
                    'endpoint': endpoint,
                    'method': method,
                    'parameter': parameter,
                    'payload': payload,
                    'evidence': f'XSS payload reflected in {analysis.get("context", "HTML")} context',
                    'details': {
                        'context': analysis.get('context'),
                        'reflection_type': analysis.get('reflection_type'),
                        'filtered': analysis.get('filtered', False),
                        'attempts': attempt + 1
                    }
                }
            
            # Update filtering status
            if analysis.get('filtered'):
                self.filtered = True
                logger.debug("  Filter detected, switching to bypass techniques")
            
            # Update for next iteration
            previous_response = response.text
            previous_payload = payload
            
            time.sleep(0.5)
        
        logger.info(f"  ✗ No XSS found")
        return None
    
    def _detect_reflection_context(self, endpoint: str, method: str, param: str) -> str:
        """Detect where payload is reflected"""
        
        test_payloads = {
            'HTML': '<h1>XSS_TEST_123</h1>',
            'Attribute': '" value="XSS_TEST_123"',
            'JavaScript': 'var x = "XSS_TEST_123";'
        }
        
        for context, payload in test_payloads.items():
            response = self._send_request(endpoint, method, param, payload)
            
            if response and 'XSS_TEST_123' in response.text:
                if '<h1>' in response.text and '</h1>' in response.text:
                    return 'HTML'
                elif 'value="XSS_TEST_123"' in response.text:
                    return 'Attribute'
                elif 'var x = "XSS_TEST_123"' in response.text:
                    return 'JavaScript'
        
        return 'HTML'
    
    def _send_request(self, url: str, method: str, param: str, payload: str) -> Optional[requests.Response]:
        """Send HTTP request with payload"""
        try:
            if method.upper() == 'GET':
                if '?' in url:
                    base_url, query = url.split('?', 1)
                    params = {}
                    for p in query.split('&'):
                        if '=' in p:
                            key, val = p.split('=', 1)
                            params[key] = val
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