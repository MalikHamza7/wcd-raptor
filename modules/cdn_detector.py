"""
CDN and Reverse Proxy Detection Module
"""

import httpx
from typing import Dict, Optional
import re

class CDNDetector:
    def __init__(self):
        self.cdn_signatures = {
            'cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id'],
                'server_patterns': [r'cloudflare']
            },
            'fastly': {
                'headers': ['fastly-debug-digest', 'x-served-by', 'x-cache'],
                'server_patterns': [r'fastly']
            },
            'akamai': {
                'headers': ['akamai-origin-hop', 'x-akamai-transformed'],
                'server_patterns': [r'akamaighost']
            },
            'amazon_cloudfront': {
                'headers': ['x-amz-cf-id', 'x-amz-cf-pop'],
                'server_patterns': [r'cloudfront']
            },
            'maxcdn': {
                'headers': ['x-maxcdn-forward'],
                'server_patterns': [r'maxcdn']
            },
            'incapsula': {
                'headers': ['x-iinfo'],
                'server_patterns': [r'incapsula']
            },
            'sucuri': {
                'headers': ['x-sucuri-id'],
                'server_patterns': [r'sucuri']
            },
            'keycdn': {
                'headers': ['server'],
                'server_patterns': [r'keycdn']
            }
        }
    
    def detect(self, url: str, timeout: int = 10) -> Dict:
        """Detect CDN and cache-related information"""
        try:
            client = httpx.Client(timeout=timeout, follow_redirects=True)
            response = client.get(url)
            
            headers = dict(response.headers)
            
            # Detect CDN
            cdn_name = self._identify_cdn(headers)
            
            # Extract cache-related headers
            cache_headers = self._extract_cache_headers(headers)
            
            # Extract detection headers
            detection_headers = self._extract_detection_headers(headers)
            
            client.close()
            
            return {
                'cdn_name': cdn_name,
                'server': headers.get('server', 'Unknown'),
                'cache_headers': cache_headers,
                'detection_headers': detection_headers,
                'all_headers': headers
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'cdn_name': None,
                'server': 'Unknown',
                'cache_headers': {},
                'detection_headers': {}
            }
    
    def _identify_cdn(self, headers: Dict[str, str]) -> Optional[str]:
        """Identify CDN based on headers"""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        for cdn_name, signatures in self.cdn_signatures.items():
            # Check for specific headers
            for header in signatures['headers']:
                if header.lower() in headers_lower:
                    return cdn_name
            
            # Check server header patterns
            server_header = headers_lower.get('server', '')
            for pattern in signatures['server_patterns']:
                if re.search(pattern, server_header, re.IGNORECASE):
                    return cdn_name
        
        return None
    
    def _extract_cache_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Extract cache-related headers"""
        cache_headers = {}
        cache_header_names = [
            'cache-control', 'etag', 'expires', 'last-modified',
            'x-cache', 'x-cache-status', 'cf-cache-status',
            'x-served-by', 'x-cache-hits', 'age'
        ]
        
        for header_name in cache_header_names:
            if header_name in headers:
                cache_headers[header_name] = headers[header_name]
        
        return cache_headers
    
    def _extract_detection_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Extract CDN detection headers"""
        detection_headers = {}
        detection_header_names = [
            'cf-ray', 'x-amz-cf-id', 'x-served-by', 'via',
            'x-forwarded-for', 'x-real-ip', 'x-cache'
        ]
        
        for header_name in detection_header_names:
            if header_name in headers:
                detection_headers[header_name] = headers[header_name]
        
        return detection_headers
