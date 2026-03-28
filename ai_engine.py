"""
AI Engine for Ollama Integration - Enhanced with model_chat
"""

import ollama
import json
import logging
import time
import re
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class AIEngine:
    """Central AI engine for all Ollama interactions"""
    
    def __init__(self, model: str = "gemma3:1b"):
        self.model = model
        self.payload_history = []
        self.analysis_cache = {}
        self.response_cache = {}
        
    def model_chat(self, prompt: str, max_tokens: int = 200) -> str:
        """Simple chat method for payload generation"""
        try:
            response = ollama.chat(
                model=self.model,
                messages=[{'role': 'user', 'content': prompt}],
                options={
                    'temperature': 0.3,
                    'num_predict': max_tokens,
                }
            )
            return response['message']['content'].strip()
        except Exception as e:
            logger.error(f"Model chat error: {e}")
            return ""
    
    def analyze_vulnerability(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze endpoint for potential vulnerabilities"""
        
        cache_key = f"{endpoint.get('url')}_{endpoint.get('method')}_{list(endpoint.get('parameters', {}).keys())}"
        
        if cache_key in self.analysis_cache:
            return self.analysis_cache[cache_key]
        
        url = endpoint.get('url', '')
        method = endpoint.get('method', 'GET')
        parameters = endpoint.get('parameters', {})
        
        prompt = f"""
Analyze this endpoint for web vulnerabilities:

URL: {url}
Method: {method}
Parameters: {', '.join(parameters.keys())}

For each parameter, identify potential vulnerabilities:
- SQL Injection
- XSS (Cross-Site Scripting)
- Command Injection
- IDOR (Insecure Direct Object Reference)

Return ONLY a JSON array. Example:
[
  {{"parameter": "id", "vulnerability": "SQL Injection", "confidence": "high"}},
  {{"parameter": "search", "vulnerability": "XSS", "confidence": "medium"}}
]

If none, return [].
"""
        
        try:
            response = ollama.chat(
                model=self.model,
                messages=[{'role': 'user', 'content': prompt}],
                options={
                    'temperature': 0.1,
                    'num_predict': 500,
                }
            )
            
            content = response['message']['content'].strip()
            result = self._extract_json_from_gemma(content)
            
            for item in result:
                item['endpoint'] = url
                item['method'] = method
                if 'reason' not in item:
                    item['reason'] = f"AI detected potential {item.get('vulnerability')}"
            
            self.analysis_cache[cache_key] = result
            logger.info(f"Analysis for {url}: found {len(result)} vulnerabilities")
            return result
            
        except Exception as e:
            logger.error(f"AI analysis error: {e}")
            return self._fallback_analysis(endpoint)
    
    def _extract_json_from_gemma(self, content: str) -> List[Dict[str, Any]]:
        """Extract JSON from Gemma's response"""
        try:
            # Remove markdown code blocks
            content = re.sub(r'```json\s*', '', content)
            content = re.sub(r'```\s*', '', content)
            
            # Find JSON array
            array_match = re.search(r'\[\s*\{.*?\}\s*\]', content, re.DOTALL)
            if array_match:
                json_str = array_match.group(0)
                json_str = re.sub(r',\s*}', '}', json_str)
                json_str = re.sub(r',\s*]', ']', json_str)
                return json.loads(json_str)
            
            return []
            
        except json.JSONDecodeError:
            return []
    
    def _fallback_analysis(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fallback pattern-based analysis"""
        vulnerabilities = []
        url = endpoint.get('url', '')
        parameters = endpoint.get('parameters', {})
        
        vuln_patterns = {
            'SQL Injection': ['id', 'user', 'product', 'article', 'page', 'post', 'category', 'username', 'password', 'login', 'email'],
            'XSS': ['search', 'q', 'query', 'name', 'comment', 'message', 'input', 'feedback', 'review'],
            'Command Injection': ['cmd', 'exec', 'command', 'shell', 'ping', 'nslookup', 'host', 'file'],
            'IDOR': ['user_id', 'account_id', 'profile_id', 'document_id', 'file_id', 'order_id']
        }
        
        for param_name in parameters.keys():
            param_lower = param_name.lower()
            
            for vuln_type, keywords in vuln_patterns.items():
                if any(keyword in param_lower for keyword in keywords):
                    vulnerabilities.append({
                        'parameter': param_name,
                        'vulnerability': vuln_type,
                        'confidence': 'high' if any(keyword in param_lower for keyword in keywords[:2]) else 'medium',
                        'reason': f"Parameter '{param_name}' commonly associated with {vuln_type}",
                        'endpoint': url,
                        'method': endpoint.get('method', 'GET')
                    })
        
        seen = set()
        unique = []
        for v in vulnerabilities:
            key = f"{v['parameter']}_{v['vulnerability']}"
            if key not in seen:
                seen.add(key)
                unique.append(v)
        
        return unique