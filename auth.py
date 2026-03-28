"""
Authentication Testing Module
"""

import requests
import logging
import time
from typing import Dict, Any, Optional
from urllib.parse import urlencode

logger = logging.getLogger(__name__)

class AuthTester:
    """Authentication vulnerability tester"""
    
    def __init__(self, ai_engine):
        self.ai_engine = ai_engine
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.max_attempts = 5
        self.timeout = 10
        
        # Common default credentials
        self.default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('root', 'root'),
            ('user', 'user'),
            ('test', 'test')
        ]
    
    def test(self, vulnerability: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Test for authentication vulnerabilities"""
        endpoint = vulnerability.get('endpoint')
        method = vulnerability.get('method', 'POST')
        parameters = vulnerability.get('parameters', {})
        
        logger.info(f"Testing Authentication on {endpoint}")
        
        # Identify username and password fields
        username_field = None
        password_field = None
        
        for key in parameters.keys():
            key_lower = key.lower()
            if 'user' in key_lower or 'login' in key_lower or 'email' in key_lower:
                username_field = key
            if 'pass' in key_lower or 'pwd' in key_lower:
                password_field = key
        
        if not username_field or not password_field:
            logger.info("Could not identify username/password fields")
            return None
        
        logger.info(f"Identified fields: {username_field}, {password_field}")
        
        # Test default credentials
        for username, password in self.default_creds[:self.max_attempts]:
            result = self._test_login(endpoint, method, username_field, password_field, username, password)
            
            if result:
                return {
                    'vulnerable': True,
                    'vulnerability': 'Authentication',
                    'endpoint': endpoint,
                    'method': method,
                    'parameter': f'{username_field}/{password_field}',
                    'payload': f'{username}:{password}',
                    'evidence': 'Default credentials successful',
                    'details': {
                        'username': username,
                        'password': password,
                        'type': 'default_credentials'
                    }
                }
            
            time.sleep(0.5)
        
        return None
    
    def _test_login(self, url: str, method: str, user_field: str, pass_field: str,
                   username: str, password: str) -> bool:
        """Test login with given credentials"""
        try:
            data = {user_field: username, pass_field: password}
            
            if method.upper() == 'POST':
                response = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=False)
            else:
                response = self.session.get(url, params=data, timeout=self.timeout, allow_redirects=False)
            
            # Check for successful login indicators
            if response.status_code == 302:
                location = response.headers.get('Location', '')
                if 'login' not in location.lower() and 'auth' not in location.lower():
                    return True
            
            # Check response content
            success_indicators = ['dashboard', 'welcome', 'success', 'logged in']
            response_lower = response.text.lower()
            
            if any(indicator in response_lower for indicator in success_indicators):
                error_indicators = ['invalid', 'incorrect', 'failed']
                if not any(error in response_lower for error in error_indicators):
                    return True
            
            return False
            
        except Exception as e:
            logger.debug(f"Login test failed: {e}")
            return False