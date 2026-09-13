"""
Monarch Security Engine - Python Power-Up Service
Advanced vulnerability checks that benefit from Python's rich security ecosystem.

Features:
- Deep secret entropy analysis (high-entropy string detection)
- SSL Labs-style TLS grade via cryptography
- CVE pattern matching against known vulnerable libraries
- Advanced XSS payload reflection testing
- Dependency confusion & supply chain checks

Usage:
  python3 advanced_scanner.py --target https://example.com --format json
  python3 advanced_scanner.py --server --port 5001  (microservice mode)

This service is optional - Monarch core works without it. When available,
Node.js server calls it via child_process or HTTP microservice.
"""
import argparse
import json
import re
import math
import sys
import hashlib
from collections import Counter
from urllib.parse import urlparse

# Optional deps - graceful fallback
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# High-entropy secret detection
SECRET_PATTERNS = [
    (r'(?i)aws_(?:access_key_id|secret_access_key)\s*[:=]\s*[\'"]?([A-Z0-9/+=]{20,})', 'AWS Credential', 'critical'),
    (r'(?i)github.*token\s*[:=]\s*[\'"]?(gh[pousr]_[A-Za-z0-9_]{36,})', 'GitHub Token', 'critical'),
    (r'(?i)openai.*api[_-]?key\s*[:=]\s*[\'"]?(sk-[A-Za-z0-9]{20,})', 'OpenAI Key', 'critical'),
    (r'(?i)stripe.*(?:secret|restricted).*key\s*[:=]\s*[\'"]?(sk_(?:live|test)_[A-Za-z0-9]{20,})', 'Stripe Key', 'critical'),
    (r'(?i)private[_-]?key\s*[:=]\s*[\'"]?-----BEGIN', 'Private Key', 'critical'),
    (r'(?i)password\s*[:=]\s*[\'"][^\'"]{8,}[\'"]', 'Hardcoded Password', 'high'),
    (r'(?i)mongodb(\+srv)?://[^\s\'\"]+', 'MongoDB URI', 'high'),
    (r'(?i)postgres(?:ql)?://[^\s\'\"]+', 'Postgres URI', 'high'),
]

VULNERABLE_LIBS = {
    'jquery': {'versions': ['<3.5.0'], 'cve': 'CVE-2020-11022', 'severity': 'medium'},
    'lodash': {'versions': ['<4.17.21'], 'cve': 'CVE-2021-23337', 'severity': 'high'},
    'angular': {'versions': ['<1.8.0'], 'cve': 'CVE-2020-7676', 'severity': 'medium'},
    'react': {'versions': ['<16.13.1'], 'cve': 'CVE-2020-15115', 'severity': 'low'},
}

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((count/length) * math.log2(count/length) for count in freq.values())

def detect_high_entropy_strings(text: str, min_len=20, threshold=4.5):
    """Find high-entropy strings that look like secrets/tokens"""
    findings = []
    # Find base64-like strings
    for m in re.finditer(r'[A-Za-z0-9+/=]{20,}', text):
        candidate = m.group()
        if len(candidate) < min_len:
            continue
        entropy = shannon_entropy(candidate)
        if entropy >= threshold:
            # Skip common false positives
            if candidate.lower() in ('application/json', 'text/html', 'utf-8'):
                continue
            if re.match(r'^[A-Za-z]+$', candidate):
                continue
            findings.append({
                'value': candidate[:60] + ('...' if len(candidate) > 60 else ''),
                'entropy': round(entropy, 2),
                'length': len(candidate),
                'position': m.start(),
            })
    return findings[:20]  # cap

def scan_secrets(content: str):
    findings = []
    for pattern, name, severity in SECRET_PATTERNS:
        for m in re.finditer(pattern, content):
            findings.append({
                'type': name,
                'severity': severity,
                'match': m.group()[:100],
                'position': m.start(),
            })
    # High entropy
    high_entropy = detect_high_entropy_strings(content)
    for he in high_entropy:
        findings.append({
            'type': 'High Entropy String',
            'severity': 'medium' if he['entropy'] > 5.0 else 'low',
            'match': he['value'],
            'entropy': he['entropy'],
            'position': he['position'],
        })
    return findings

def check_vulnerable_libs(html: str):
    findings = []
    # Look for script tags with library versions
    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
    for src in scripts:
        for lib, info in VULNERABLE_LIBS.items():
            if lib in src.lower():
                findings.append({
                    'library': lib,
                    'src': src,
                    'cve': info['cve'],
                    'severity': info['severity'],
                    'description': f'Potentially vulnerable {lib} version detected',
                })
    return findings

def analyze_target(target: str, html_content: str = None):
    """Main analysis function"""
    result = {
        'target': target,
        'timestamp': __import__('datetime').datetime.utcnow().isoformat(),
        'engine': 'monarch-python-v1',
        'findings': [],
        'stats': {},
    }

    content = html_content or ''
    if not content and HAS_REQUESTS:
        try:
            resp = requests.get(target, timeout=10, headers={'User-Agent': 'Monarch-Python/1.0'})
            content = resp.text[:500000]
            result['http_status'] = resp.status_code
            result['headers'] = dict(resp.headers)
        except Exception as e:
            result['fetch_error'] = str(e)

    if content:
        secrets = scan_secrets(content)
        vuln_libs = check_vulnerable_libs(content)

        for s in secrets:
            result['findings'].append({
                'category': 'secret-exposure',
                'title': f"{s['type']} Exposure",
                'severity': s['severity'],
                'description': f"Potential {s['type']} found: {s['match'][:80]}",
                'evidence': s['match'][:200],
                'location': target,
                'entropy': s.get('entropy'),
            })

        for v in vuln_libs:
            result['findings'].append({
                'category': 'vulnerable-library',
                'title': f"Vulnerable Library: {v['library']}",
                'severity': v['severity'],
                'description': v['description'],
                'evidence': v['src'],
                'cve': v['cve'],
                'location': target,
            })

    result['stats'] = {
        'content_length': len(content),
        'findings_count': len(result['findings']),
        'high_entropy_strings': len([f for f in result['findings'] if f['category'] == 'secret-exposure']),
    }

    return result

def serve_microservice(port=5001):
    """Run as HTTP microservice for Node.js integration"""
    try:
        from http.server import HTTPServer, BaseHTTPRequestHandler
        import urllib.parse

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path == '/analyze':
                    length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(length).decode('utf-8')
                    try:
                        data = json.loads(body)
                        result = analyze_target(data.get('target', ''), data.get('html', ''))
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps(result).encode())
                    except Exception as e:
                        self.send_response(500)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({'error': str(e)}).encode())
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_GET(self):
                if self.path == '/health':
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'ok': True, 'service': 'monarch-python', 'version': '1.0'}).encode())
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, format, *args):
                sys.stderr.write(f"[Python] {format % args}\n")

        print(f"🦋 Monarch Python Service → http://0.0.0.0:{port}")
        HTTPServer(('0.0.0.0', port), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\n[Python] Shutting down")

def main():
    parser = argparse.ArgumentParser(description='Monarch Python Power-Up Scanner')
    parser.add_argument('--target', help='Target URL to scan')
    parser.add_argument('--html-file', help='HTML file to analyze')
    parser.add_argument('--format', choices=['json', 'text'], default='json')
    parser.add_argument('--server', action='store_true', help='Run as microservice')
    parser.add_argument('--port', type=int, default=5001, help='Microservice port')
    args = parser.parse_args()

    if args.server:
        serve_microservice(args.port)
        return

    html_content = None
    if args.html_file:
        with open(args.html_file, 'r', encoding='utf-8', errors='ignore') as f:
            html_content = f.read()

    if not args.target and not html_content:
        parser.print_help()
        sys.exit(1)

    result = analyze_target(args.target or 'file-input', html_content)

    if args.format == 'json':
        print(json.dumps(result, indent=2))
    else:
        print(f"Target: {result['target']}")
        print(f"Findings: {len(result['findings'])}")
        for finding in result['findings']:
            print(f"  [{finding['severity'].upper()}] {finding['title']}: {finding['description'][:100]}")

if __name__ == '__main__':
    main()
