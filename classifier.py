"""
Vulnerability Classifier - Enhanced for Gemma
"""

import logging
from typing import List, Dict, Any
from ai_engine import AIEngine

logger = logging.getLogger(__name__)

class VulnerabilityClassifier:
    """Classifies vulnerabilities using AI - Enhanced for Gemma"""
    
    def __init__(self):
        self.ai_engine = AIEngine()
        self.classification_cache = {}
    
    def classify_endpoint(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Classify a single endpoint"""
        
        # Create cache key
        cache_key = f"{endpoint.get('url')}_{endpoint.get('method')}"
        
        # Check cache
        if cache_key in self.classification_cache:
            logger.debug(f"Using cached classification for {cache_key}")
            return self.classification_cache[cache_key]
        
        # Normalize endpoint
        normalized = self._normalize_endpoint(endpoint)
        
        logger.debug(f"Classifying endpoint: {normalized}")
        
        # Get classification from AI
        classifications = self.ai_engine.analyze_vulnerability(normalized)
        
        # Log classifications for debugging
        if classifications:
            logger.info(f"Found {len(classifications)} potential vulnerabilities:")
            for vuln in classifications:
                logger.info(f"  - {vuln.get('vulnerability')} on {vuln.get('parameter')} (confidence: {vuln.get('confidence')})")
        
        # Cache result
        self.classification_cache[cache_key] = classifications
        
        return classifications
    
    def _normalize_endpoint(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize endpoint data"""
        return {
            'url': endpoint.get('url', ''),
            'method': endpoint.get('method', 'GET').upper(),
            'parameters': endpoint.get('parameters', {})
        }