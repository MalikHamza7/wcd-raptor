# WCD-Raptor 🦅

**Web Cache Deception Detection Tool with Origin Exploitation Engine**

A modern, fully automated WCD testing tool designed for bug bounty hunters and red teamers to detect and exploit Web Cache Deception vulnerabilities, now featuring advanced origin IP discovery and exploitation capabilities.



## 🎯 Features

### Core Capabilities
- **Multi-Target Support**: Single domain or bulk URL file processing
- **Smart Filtering**: Automatic detection of cacheable endpoints
- **CDN Detection**: Identifies major CDNs (Cloudflare, Fastly, Akamai, etc.)
- **Advanced Payloads**: Extension manipulation, query parameters, path traversal
- **Authentication Bypass**: Detects cache-based auth bypasses
- **Race Condition Testing**: Optional multi-threaded cache race detection
- **🔥 Origin Exploitation Engine (OEE)**: Advanced origin IP discovery and exploitation
- **Comprehensive Reporting**: JSON, CSV, and colored console output

### 🔥 Origin Exploitation Engine (OEE)
The OEE automatically:
- **Discovers Origin IPs**: Multiple techniques including DNS resolution, subdomain enumeration, and historical records
- **Bypasses CDN/WAF**: Direct origin IP testing with proper host headers
- **Detects Sensitive Leaks**: CSRF tokens, API keys, session cookies, debug info
- **Finds Admin Panels**: Exposed dashboards, login portals, management interfaces
- **Framework Fingerprinting**: Laravel, Django, WordPress, Flask, Express detection
- **Deep Path Discovery**: Backup files, config files, logs, version control

### Attack Modules
- Extension appending (`.css`, `.js`, `.jpg`, etc.)
- Query parameter injection (`?fake.js`, `?cb=123`)
- Path manipulation (`/`, `%2e`, `..;/`, double encoding)
- Header variations (X-Forwarded-For, X-Real-IP)
- 403 Bypass techniques
- Cache race conditions
- **🔥 Origin IP exploitation with 200+ attack vectors**

## 📋 Requirements

- Python 3.7+
- Linux/Unix environment (recommended)
- Internet connection for target scanning
- Optional: Authentication cookies for authenticated scans

### Python Dependencies
- httpx >= 0.24.0
- rich >= 13.0.0
- Standard library modules (argparse, pathlib, concurrent.futures)

## 🚀 Installation

\`\`\`bash
# Clone the repository
git clone https://github.com/MalikHamza7/wcd-raptor.git
cd wcd-raptor

# Run the automated installation script
python3 scripts/install.py

# Or install dependencies manually
pip3 install -r requirements.txt
chmod +x wcd_raptor.py
\`\`\`

## 🚀 Quick Start

\`\`\`bash
# Basic scan
python3 wcd_raptor.py --target https://example.com

# Scan with Origin Exploitation Engine
python3 wcd_raptor.py --target https://example.com --exploit

# Bulk scanning with authentication
python3 wcd_raptor.py --url-file targets.txt --cookie-file cookies.txt --exploit
\`\`\`

## 📖 Usage

### Basic Usage

\`\`\`bash
# Single target scan
python3 wcd_raptor.py --target https://example.com

# Enable Origin Exploitation Engine
python3 wcd_raptor.py --target https://example.com --exploit

# Bulk URL scanning with OEE
python3 wcd_raptor.py --url-file urls.txt --exploit

# Deep exploitation mode
python3 wcd_raptor.py --target https://example.com --exploit --exploit-depth deep
\`\`\`

### Advanced Options

\`\`\`bash
# Verbose output with custom threads and origin exploitation
python3 wcd_raptor.py --target https://example.com --exploit --verbose --threads 10

# Extended origin timeout for slow servers
python3 wcd_raptor.py --target https://example.com --exploit --origin-timeout 30

# Complete scan with all features
python3 wcd_raptor.py --target https://example.com --exploit --race-condition --verbose --exploit-depth deep
\`\`\`

### Full Command Reference

\`\`\`
Options:
  --target, -t          Single target domain/URL
  --url-file, -f        File containing list of URLs
  --cookie-file, -c     Cookie file (Netscape or JSON format)
  --output-dir, -o      Output directory (default: output)
  --threads             Number of threads (default: 5)
  --timeout             Request timeout in seconds (default: 10)
  --verbose, -v         Verbose output
  --headless            Minimal output for pipelines
  --race-condition      Enable race condition testing
  --user-agent          Custom User-Agent string
  
  🔥 Origin Exploitation Engine:
  --exploit             Enable Origin Exploitation Engine (OEE)
  --origin-timeout      Origin IP request timeout (default: 15)
  --exploit-depth       Exploitation depth: basic, deep (default: basic)
\`\`\`

## 📁 Output Structure

For each target, WCD-Raptor creates organized output:

\`\`\`
output/
└── example.com/
    ├── raw_urls.txt          # All input URLs
    ├── cacheable_urls.txt    # Filtered cacheable URLs
    ├── cdn_info.txt          # CDN detection results
    ├── origin_ips.txt        # 🔥 Discovered origin IPs
    ├── origin_exploits.json  # 🔥 Origin exploitation results
    ├── results.json          # Detailed JSON results
    └── results.csv           # CSV summary
\`\`\`

## 🔧 Troubleshooting

### Common Issues

**Permission Denied**
\`\`\`bash
chmod +x wcd_raptor.py
\`\`\`

**Module Import Errors**
\`\`\`bash
pip3 install -r requirements.txt --upgrade
\`\`\`

**SSL Certificate Errors**
The tool automatically handles SSL certificate issues when testing origin IPs.

**Rate Limiting**
Adjust thread count with `--threads` parameter (default: 5).
\`\`\`

## 🔥 Origin Exploitation Examples

### CSRF Token Discovery
\`\`\`
✅ CSRF Token Found
Origin IP: 192.168.1.100
Path: /admin/login
Evidence: csrf_token=abc123def456...
Severity: MEDIUM
\`\`\`

### Admin Panel Exposure
\`\`\`
🚨 Admin Panel Exposed
Origin IP: 192.168.1.100
Path: /admin/dashboard
Evidence: Admin panel accessible at https://192.168.1.100/admin/dashboard
Severity: CRITICAL
\`\`\`

### API Documentation Leak
\`\`\`
💥 API Documentation Exposed
Origin IP: 192.168.1.100
Path: /api-docs
Evidence: Swagger documentation exposed
Severity: HIGH
\`\`\`

### Debug Information Leak
\`\`\`
🐞 Debug Information Found
Origin IP: 192.168.1.100
Path: /debug
Evidence: APP_KEY=base64:abc123...
Severity: HIGH
\`\`\`

## 🔍 Detection Methods

### CDN Fingerprinting
- **Cloudflare**: `cf-ray`, `cf-cache-status`
- **Fastly**: `x-served-by`, `fastly-debug-digest`
- **Akamai**: `akamai-origin-hop`
- **Amazon CloudFront**: `x-amz-cf-id`
- **And more...**

### 🔥 Origin IP Discovery
- **DNS Resolution**: A/AAAA record enumeration
- **Subdomain Enumeration**: Common subdomain IP collection
- **Certificate Transparency**: CT log analysis (planned)
- **Historical DNS**: Historical record lookup (planned)
- **Search Engine Discovery**: Shodan/Censys integration (planned)

### Vulnerability Detection
- Content hash comparison (SHA1)
- Status code analysis
- Cache header inspection
- Response time analysis
- Authentication bypass detection
- **🔥 Origin-specific vulnerability patterns**

## 🛡️ Cookie Support

WCD-Raptor supports multiple cookie formats:

### JSON Format
\`\`\`json
{
  "session_id": "abc123",
  "auth_token": "xyz789"
}
\`\`\`

### Netscape Format
\`\`\`
# Netscape HTTP Cookie File
.example.com	TRUE	/	FALSE	1234567890	session_id	abc123
\`\`\`

## 🎨 Example Output

\`\`\`
╭─────────────────────────────────────────────────────────────╮
│                        WCD-RAPTOR                           │
│              Web Cache Deception Detection Tool            │
│              🔥 Now with Origin Exploitation Engine        │
│                                                             │
│              Developed By: Hamza Iqbal                     │
│              Version: 2.0.0                                │
│              License: MIT                                   │
╰─────────────────────────────────────────────────────────────╯

🎯 Scanning target: https://example.com
🔍 CDN Detected: Cloudflare
📊 Found 15 potentially cacheable URLs
🚨 Testing WCD vulnerabilities...
🔥 Starting Origin Exploitation Engine (OEE)...
🎯 Found 2 origin IP(s): 192.168.1.100, 10.0.0.50
🎯 Exploiting origin IP: 192.168.1.100

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
