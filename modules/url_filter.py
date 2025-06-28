"""
URL Filtering Module for Cacheable Content Detection
"""

import httpx
from typing import List, Dict, Set
from urllib.parse import urlparse
import re

class URLFilter:
    def __init__(self):
        self.cacheable_extensions = {
            '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg',
            '.ico', '.woff', '.woff2', '.ttf', '.eot', '.pdf',
            '.html', '.htm', '.xml', '.json', '.txt', '.zip'
        }
        
        self.non_cacheable_patterns = [
            r'/api/',
            r'/admin/',
            r'/login',
            r'/logout',
            r'/auth',
            r'/session',
            r'/csrf',
            r'/captcha',
            r'/search\?',
            r'/cart',
            r'/checkout',
            r'/payment'
        ]
        
        self.cacheable_headers = [
            'cache-control', 'etag', 'expires', 'last-modified'
        ]
    
    def is_potentially_cacheable(self, url: str, timeout: int = 10, 
                                user_agent: str = 'WCD-Raptor/1.0') -> bool:
        """Determine if URL is potentially cacheable"""
        
        # Quick pattern-based filtering
        if self._has_non_cacheable_patterns(url):
            return False
        
        # Extension-based filtering
        if self._has_cacheable_extension(url):
            return True
        
        # HTTP header-based filtering
        try:
            return self._check_cache_headers(url, timeout, user_agent)
        except:
            # If we can't check headers, assume it might be cacheable
            return True
    
    def _has_cacheable_extension(self, url: str) -> bool:
        """Check if URL has cacheable extension"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        for ext in self.cacheable_extensions:
            if path.endswith(ext):
                return True
        return False
    
    def _has_non_cacheable_patterns(self, url: str) -> bool:
        """Check if URL matches non-cacheable patterns"""
        for pattern in self.non_cacheable_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False
    
    def _check_cache_headers(self, url: str, timeout: int, user_agent: str) -> bool:
        """Check HTTP headers for cache indicators"""
        try:
            client = httpx.Client(
                timeout=timeout,
                headers={'User-Agent': user_agent},
                follow_redirects=True
            )
            
            # Use HEAD request to avoid downloading content
            response = client.head(url)
            
            # Check for cache-related headers
            headers = dict(response.headers)
            
            # Look for cache-control header
            cache_control = headers.get('cache-control', '').lower()
            if 'no-cache' in cache_control or 'no-store' in cache_control:
                client.close()
                return False
            
            # Look for other cache indicators
            cache_indicators = ['etag', 'expires', 'last-modified']
            has_cache_headers = any(header in headers for header in cache_indicators)
            
            # Check content type
            content_type = headers.get('content-type', '').lower()
            cacheable_types = [
                'text/css', 'application/javascript', 'text/javascript',
                'image/', 'font/', 'application/font', 'text/html'
            ]
            
            has_cacheable_type = any(ct in content_type for ct in cacheable_types)
            
            client.close()
            
            return has_cache_headers or has_cacheable_type
            
        except Exception:
            # If we can't check, assume it might be cacheable
            return True
    
    def filter_urls(self, urls: List[str], timeout: int = 10, 
                   user_agent: str = 'WCD-Raptor/1.0') -> List[str]:
        """Filter list of URLs for potentially cacheable ones"""
        cacheable_urls = []
        
        for url in urls:
            if self.is_potentially_cacheable(url, timeout, user_agent):
                cacheable_urls.append(url)
        
        return cacheable_urls
