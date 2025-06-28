"""
Response Analysis Module for WCD Detection
"""

import hashlib
import re
from typing import Dict, Any
import httpx

class ResponseAnalyzer:
    def __init__(self):
        self.cache_indicators = [
            'x-cache', 'x-cache-status', 'cf-cache-status',
            'x-served-by', 'x-cache-hits', 'age'
        ]
        
        self.vulnerability_patterns = [
            # Common error patterns that might indicate caching
            r'404.*not.*found',
            r'403.*forbidden',
            r'401.*unauthorized',
            r'500.*internal.*server.*error'
        ]
    
    def analyze_responses(self, original_response: httpx.Response, 
                         payload_response: httpx.Response,
                         original_url: str, payload_url: str) -> Dict[str, Any]:
        """Analyze original and payload responses for WCD vulnerabilities"""
        
        # Basic response comparison
        original_hash = self._hash_content(original_response.content)
        payload_hash = self._hash_content(payload_response.content)
        
        # Status code analysis
        status_match = original_response.status_code == payload_response.status_code
        content_match = original_hash == payload_hash
        
        # Cache header analysis
        cache_headers = self._extract_cache_info(payload_response)
        
        # Determine vulnerability
        vulnerable = False
        confidence = "low"
        evidence = []
        
        # Check for potential WCD indicators
        if status_match and content_match:
            # Same content and status - potential caching
            if self._has_cache_indicators(payload_response):
                vulnerable = True
                confidence = "high"
                evidence.append("Same content served with cache indicators")
            elif original_response.status_code == 200:
                vulnerable = True
                confidence = "medium"
                evidence.append("Same content served for different URLs")
        
        # Check for authentication bypass
        if self._check_auth_bypass(original_response, payload_response):
            vulnerable = True
            confidence = "high"
            evidence.append("Potential authentication bypass detected")
        
        # Check for content length differences
        if self._significant_content_difference(original_response, payload_response):
            vulnerable = True
            confidence = "medium"
            evidence.append("Significant content difference detected")
        
        # Check response time differences (potential cache hit)
        response_time_diff = self._analyze_response_times(original_response, payload_response)
        if response_time_diff:
            evidence.append(f"Response time difference: {response_time_diff}")
        
        return {
            'vulnerable': vulnerable,
            'confidence': confidence,
            'evidence': '; '.join(evidence) if evidence else 'No evidence found',
            'original_status': original_response.status_code,
            'payload_status': payload_response.status_code,
            'content_match': content_match,
            'status_match': status_match,
            'cache_headers': cache_headers,
            'original_hash': original_hash,
            'payload_hash': payload_hash
        }
    
    def _hash_content(self, content: bytes) -> str:
        """Generate SHA1 hash of content"""
        return hashlib.sha1(content).hexdigest()
    
    def _extract_cache_info(self, response: httpx.Response) -> Dict[str, str]:
        """Extract cache-related headers"""
        cache_info = {}
        for header in self.cache_indicators:
            if header in response.headers:
                cache_info[header] = response.headers[header]
        return cache_info
    
    def _has_cache_indicators(self, response: httpx.Response) -> bool:
        """Check if response has cache indicators"""
        for header in self.cache_indicators:
            if header in response.headers:
                header_value = response.headers[header].lower()
                if any(indicator in header_value for indicator in ['hit', 'cached', 'miss']):
                    return True
        return False
    
    def _check_auth_bypass(self, original_response: httpx.Response, 
                          payload_response: httpx.Response) -> bool:
        """Check for authentication bypass"""
        # If original requires auth (401/403) but payload doesn't
        if original_response.status_code in [401, 403] and payload_response.status_code == 200:
            return True
        
        # Check for auth-related headers
        auth_headers = ['www-authenticate', 'authorization']
        original_has_auth = any(header in original_response.headers for header in auth_headers)
        payload_has_auth = any(header in payload_response.headers for header in auth_headers)
        
        if original_has_auth and not payload_has_auth:
            return True
        
        return False
    
    def _significant_content_difference(self, original_response: httpx.Response,
                                      payload_response: httpx.Response) -> bool:
        """Check for significant content differences"""
        original_length = len(original_response.content)
        payload_length = len(payload_response.content)
        
        if original_length == 0 and payload_length == 0:
            return False
        
        # Calculate percentage difference
        if original_length > 0:
            diff_percentage = abs(original_length - payload_length) / original_length
            return diff_percentage > 0.1  # 10% difference threshold
        
        return payload_length > 0
    
    def _analyze_response_times(self, original_response: httpx.Response,
                               payload_response: httpx.Response) -> str:
        """Analyze response time differences"""
        # Note: httpx doesn't provide response time directly
        # This is a placeholder for potential timing analysis
        return ""
