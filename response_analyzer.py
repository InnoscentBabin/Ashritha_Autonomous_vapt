"""
Response Analyzer - Analyzes responses to guide payload generation
"""

import re
import logging
from typing import Dict, Any, List, Optional
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class ResponseAnalyzer:
    """Analyzes HTTP responses to extract useful information"""
    
    def __init__(self):
        self.analysis_cache = {}
    
    def analyze_sql_response(self, response_text: str, payload: str) -> Dict[str, Any]:
        """Analyze response for SQL injection indicators"""
        analysis = {
            'vulnerable': False,
            'db_type': None,
            'error_details': None,
            'time_based': False,
            'boolean_based': False,
            'union_based': False,
            'extracted_data': []
        }
        
        response_lower = response_text.lower()
        
        # Check for database errors
        db_patterns = {
            'MySQL': ['mysql', 'sql syntax', 'mysql_fetch', 'you have an error'],
            'PostgreSQL': ['postgresql', 'postgres', 'pg_', 'psql'],
            'Oracle': ['ora-', 'oracle', 'oci_'],
            'SQLite': ['sqlite', 'sqlite3'],
            'MSSQL': ['microsoft sql', 'sql server', 'mssql']
        }
        
        for db_type, patterns in db_patterns.items():
            if any(pattern in response_lower for pattern in patterns):
                analysis['db_type'] = db_type
                analysis['vulnerable'] = True
                
                # Extract error details
                error_match = re.search(r'(error|warning|exception)[:\s]+([^\n.]+)', response_text, re.IGNORECASE)
                if error_match:
                    analysis['error_details'] = error_match.group(2)
                break
        
        # Check for time-based injection
        if 'time' in payload.lower() or 'sleep' in payload.lower() or 'delay' in payload.lower():
            analysis['time_based'] = True
        
        # Check for boolean-based injection
        if 'true' in response_lower or 'false' in response_lower:
            if '1=1' in payload or '1=2' in payload:
                analysis['boolean_based'] = True
        
        # Check for UNION-based injection
        if 'union' in payload.lower() and 'column' in response_lower:
            analysis['union_based'] = True
        
        return analysis
    
    def analyze_xss_response(self, response_text: str, payload: str) -> Dict[str, Any]:
        """Analyze response for XSS indicators"""
        analysis = {
            'vulnerable': False,
            'reflection_type': None,
            'filtered': False,
            'context': None,
            'reflected_payload': None
        }
        
        # Check if payload is reflected
        clean_payload = re.escape(payload)
        
        if payload in response_text:
            analysis['vulnerable'] = True
            analysis['reflected_payload'] = payload
            
            # Determine reflection context
            soup = BeautifulSoup(response_text, 'html.parser')
            
            # Check if in script tag
            if soup.find('script') and payload in str(soup.find('script')):
                analysis['context'] = 'javascript'
                analysis['reflection_type'] = 'script_tag'
            
            # Check if in attribute
            elif re.search(r'=\s*["\'][^"\']*' + re.escape(payload), response_text):
                analysis['context'] = 'attribute'
                analysis['reflection_type'] = 'html_attribute'
            
            # Check if in HTML body
            elif payload in response_text:
                analysis['context'] = 'html'
                analysis['reflection_type'] = 'html_body'
        
        # Check for HTML encoding
        html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
        if html_encoded in response_text:
            analysis['filtered'] = True
            analysis['reflection_type'] = 'html_encoded'
        
        return analysis
    
    def analyze_command_response(self, response_text: str, payload: str) -> Dict[str, Any]:
        """Analyze response for command injection indicators"""
        analysis = {
            'vulnerable': False,
            'os': None,
            'command_output': None,
            'executed_command': None
        }
        
        response_lower = response_text.lower()
        
        # Check for command output
        command_indicators = {
            'Linux/Unix': ['uid=', 'gid=', 'groups=', 'root:', 'home/', '/bin/', 'usr/'],
            'Windows': ['windows', 'win32', 'program files', 'users\\', 'system32', 'cmd.exe']
        }
        
        for os_type, indicators in command_indicators.items():
            if any(indicator in response_lower for indicator in indicators):
                analysis['vulnerable'] = True
                analysis['os'] = os_type
                
                # Extract command output
                if 'whoami' in payload.lower():
                    # Look for username output
                    import re
                    username_pattern = r'([a-z_][a-z0-9_]{2,30})'
                    matches = re.findall(username_pattern, response_text[:200])
                    if matches:
                        analysis['command_output'] = matches[0]
                        analysis['executed_command'] = 'whoami'
                
                break
        
        return analysis
    
    def analyze_idor_response(self, response_text: str, original_id: str, test_id: str) -> Dict[str, Any]:
        """Analyze response for IDOR indicators"""
        analysis = {
            'vulnerable': False,
            'access_granted': False,
            'data_leaked': False,
            'status_code': None
        }
        
        # Check if response is different
        if len(response_text) > 0:
            analysis['access_granted'] = True
            
            # Check for sensitive data
            sensitive_patterns = [
                r'email[\s:=]+[\w\.-]+@[\w\.-]+',
                r'phone[\s:=]+[\d\-\(\)\+]+',
                r'address[\s:=]+[^\n]{10,}',
                r'credit[\s_]?card',
                r'ssn[\s_:]+\d{3}-\d{2}-\d{4}'
            ]
            
            for pattern in sensitive_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    analysis['data_leaked'] = True
                    analysis['vulnerable'] = True
                    break
        
        return analysis
    
    def extract_error_details(self, response_text: str) -> Dict[str, Any]:
        """Extract detailed error information"""
        details = {
            'error_type': None,
            'error_message': None,
            'stack_trace': None,
            'file_paths': []
        }
        
        # Extract error message
        error_match = re.search(r'(error|exception|warning|fatal)[:\s]+([^\n]+)', response_text, re.IGNORECASE)
        if error_match:
            details['error_type'] = error_match.group(1)
            details['error_message'] = error_match.group(2)
        
        # Extract file paths
        path_pattern = r'([a-zA-Z]:\\[^\s\n]+|\/[^\s\n]+\.\w+)'
        paths = re.findall(path_pattern, response_text)
        if paths:
            details['file_paths'] = paths[:3]  # Limit to first 3
        
        # Extract stack trace
        if 'trace' in response_text.lower():
            trace_match = re.search(r'(trace|stack)[:\s]+([^\n]+(?:\n[^\n]+){0,10})', response_text, re.IGNORECASE)
            if trace_match:
                details['stack_trace'] = trace_match.group(2)
        
        return detailsṁ