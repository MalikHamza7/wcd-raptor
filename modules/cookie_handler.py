"""
Cookie Handling Module
"""

import json
import os
from typing import Dict, Optional
from http.cookiejar import MozillaCookieJar
import httpx

class CookieHandler:
    def __init__(self):
        self.cookies = {}
    
    def load_cookies(self, cookie_file: str):
        """Load cookies from file (Netscape or JSON format)"""
        if not os.path.exists(cookie_file):
            raise FileNotFoundError(f"Cookie file not found: {cookie_file}")
        
        # Try to detect format
        with open(cookie_file, 'r') as f:
            content = f.read().strip()
        
        if content.startswith('{') or content.startswith('['):
            # JSON format
            self._load_json_cookies(cookie_file)
        else:
            # Assume Netscape format
            self._load_netscape_cookies(cookie_file)
    
    def _load_json_cookies(self, cookie_file: str):
        """Load cookies from JSON file"""
        with open(cookie_file, 'r') as f:
            data = json.load(f)
        
        if isinstance(data, list):
            # Array of cookie objects
            for cookie in data:
                if 'name' in cookie and 'value' in cookie:
                    self.cookies[cookie['name']] = cookie['value']
        elif isinstance(data, dict):
            # Simple key-value pairs
            self.cookies.update(data)
    
    def _load_netscape_cookies(self, cookie_file: str):
        """Load cookies from Netscape format file"""
        try:
            jar = MozillaCookieJar(cookie_file)
            jar.load(ignore_discard=True, ignore_expires=True)
            
            for cookie in jar:
                self.cookies[cookie.name] = cookie.value
        except Exception as e:
            # Fallback: try to parse manually
            self._parse_netscape_manually(cookie_file)
    
    def _parse_netscape_manually(self, cookie_file: str):
        """Manually parse Netscape cookie file"""
        with open(cookie_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split('\t')
                    if len(parts) >= 7:
                        name = parts[5]
                        value = parts[6]
                        self.cookies[name] = value
    
    def get_cookies(self) -> Dict[str, str]:
        """Get loaded cookies"""
        return self.cookies
    
    def add_cookie(self, name: str, value: str):
        """Add a single cookie"""
        self.cookies[name] = value
    
    def clear_cookies(self):
        """Clear all cookies"""
        self.cookies.clear()
