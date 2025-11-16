#!/usr/bin/env python3
"""
EOL Framework Scanner - Pentesting Tool
Scans target URLs for frameworks/libraries and checks their EOL status
"""

import requests
import re
import json
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, List, Tuple
import argparse

class EOLScanner:
    def __init__(self, verify_ssl=True):
        self.eol_api = "https://endoflife.date/api"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'EOL-Scanner/1.0 (Pentesting Tool)'
        })
        self.verify_ssl = verify_ssl
        
        # Disable SSL warnings if verification is disabled
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
    def fetch_page(self, url: str) -> Tuple[str, dict]:
        """Fetch target page content and headers"""
        try:
            resp = self.session.get(url, timeout=10, verify=self.verify_ssl)
            resp.raise_for_status()
            return resp.text, dict(resp.headers)
        except Exception as e:
            print(f"[!] Error fetching {url}: {e}")
            return "", {}
    
    def detect_frameworks(self, html: str, headers: dict) -> Dict[str, str]:
        """Detect frameworks and their versions from HTML and headers"""
        findings = {}
        
        # Detection patterns for common frameworks/libraries
        patterns = {
            'angular': [
                r'angular[/@](\d+\.\d+\.\d+)',
                r'ng-version["\s:]+["\']?(\d+\.\d+\.\d+)',
            ],
            'react': [
                r'react[/@](\d+\.\d+\.\d+)',
                r'React\s+v?(\d+\.\d+\.\d+)',
            ],
            'vue': [
                r'vue[/@](\d+\.\d+\.\d+)',
                r'Vue\.version\s*=\s*["\'](\d+\.\d+\.\d+)',
            ],
            'jquery': [
                r'jquery[/-](\d+\.\d+\.\d+)',
                r'jQuery\s+v?(\d+\.\d+\.\d+)',
            ],
            'bootstrap': [
                r'bootstrap[/@](\d+\.\d+\.\d+)',
                r'Bootstrap\s+v?(\d+\.\d+\.\d+)',
            ],
            'django': [
                r'django[/@](\d+\.\d+)',
            ],
            'rails': [
                r'rails[/@](\d+\.\d+\.\d+)',
            ],
            'laravel': [
                r'laravel[/@](\d+\.\d+)',
            ],
            'wordpress': [
                r'wp-content/.*?ver=(\d+\.\d+\.?\d*)',
                r'WordPress\s+(\d+\.\d+\.?\d*)',
            ],
            'drupal': [
                r'Drupal\s+(\d+\.\d+)',
                r'drupal[/-](\d+\.\d+)',
            ],
        }
        
        # Check HTML content
        for framework, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.findall(pattern, html, re.IGNORECASE)
                if matches:
                    findings[framework] = matches[0]
                    break
        
        # Check headers for server info
        server = headers.get('Server', '').lower()
        if 'nginx' in server:
            match = re.search(r'nginx/(\d+\.\d+\.?\d*)', server)
            if match:
                findings['nginx'] = match.group(1)
        
        if 'apache' in server:
            match = re.search(r'apache/(\d+\.\d+\.?\d*)', server)
            if match:
                findings['apache'] = match.group(1)
        
        # Check for PHP version
        php_version = headers.get('X-Powered-By', '')
        if 'php' in php_version.lower():
            match = re.search(r'php/(\d+\.\d+\.?\d*)', php_version, re.IGNORECASE)
            if match:
                findings['php'] = match.group(1)
        
        return findings
    
    def check_eol_status(self, product: str, version: str) -> dict:
        """Query endoflife.date API for product version status"""
        try:
            # Get all cycles for the product
            resp = self.session.get(f"{self.eol_api}/{product}.json", timeout=5)
            if resp.status_code != 200:
                return {"error": f"Product '{product}' not found in EOL database"}
            
            cycles = resp.json()
            version_major = version.split('.')[0]
            
            # Find matching cycle
            for cycle in cycles:
                cycle_version = str(cycle.get('cycle', ''))
                if cycle_version == version_major or cycle_version == version:
                    eol_date = cycle.get('eol')
                    support_date = cycle.get('support')
                    
                    result = {
                        'product': product,
                        'version': version,
                        'cycle': cycle_version,
                        'eol_date': eol_date,
                        'support_date': support_date,
                        'is_eol': False,
                        'is_supported': True,
                    }
                    
                    # Check if EOL
                    if eol_date and eol_date != False:
                        try:
                            eol_datetime = datetime.strptime(str(eol_date), '%Y-%m-%d')
                            result['is_eol'] = eol_datetime < datetime.now()
                        except:
                            pass
                    
                    # Check if still supported
                    if support_date and support_date != False:
                        try:
                            support_datetime = datetime.strptime(str(support_date), '%Y-%m-%d')
                            result['is_supported'] = support_datetime >= datetime.now()
                        except:
                            pass
                    
                    return result
            
            return {"error": f"Version {version} not found in EOL database for {product}"}
        
        except Exception as e:
            return {"error": str(e)}
    
    def generate_report(self, url: str, findings: Dict[str, str], eol_results: List[dict]):
        """Generate a formatted security report"""
        print("\n" + "="*80)
        print(f"EOL SECURITY SCAN REPORT")
        print("="*80)
        print(f"Target URL: {url}")
        print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80)
        
        if not findings:
            print("\n[!] No frameworks or libraries detected.")
            return
        
        print(f"\n[+] Detected {len(findings)} frameworks/libraries:\n")
        
        critical_count = 0
        warning_count = 0
        
        for result in eol_results:
            if 'error' in result:
                print(f"[-] {result.get('product', 'Unknown')}: {result['error']}")
                continue
            
            status = "✓ SUPPORTED"
            severity = "INFO"
            
            if result['is_eol']:
                status = "✗ END OF LIFE"
                severity = "CRITICAL"
                critical_count += 1
            elif not result['is_supported']:
                status = "⚠ NO SECURITY SUPPORT"
                severity = "WARNING"
                warning_count += 1
            
            print(f"[{severity}] {result['product'].upper()} v{result['version']}")
            print(f"        Status: {status}")
            if result['eol_date']:
                print(f"        EOL Date: {result['eol_date']}")
            if result['support_date']:
                print(f"        Support Until: {result['support_date']}")
            print()
        
        print("="*80)
        print("SUMMARY:")
        print(f"  Critical Issues: {critical_count}")
        print(f"  Warnings: {warning_count}")
        print(f"  Total Detected: {len(findings)}")
        print("="*80)
        
        if critical_count > 0:
            print("\n[!] RECOMMENDATION: Upgrade end-of-life components immediately!")
        elif warning_count > 0:
            print("\n[!] RECOMMENDATION: Plan upgrades for unsupported components.")
        else:
            print("\n[✓] All detected components are currently supported.")
    
    def scan(self, url: str):
        """Main scanning function"""
        print(f"\n[*] Scanning {url}...")
        if not self.verify_ssl:
            print("[!] SSL verification disabled - use only for authorized pentesting!")
        
        # Fetch page
        html, headers = self.fetch_page(url)
        if not html:
            return
        
        # Detect frameworks
        print("[*] Detecting frameworks and libraries...")
        findings = self.detect_frameworks(html, headers)
        
        if not findings:
            print("[!] No frameworks detected. Try scanning more pages or use -v for verbose mode.")
            return
        
        # Check EOL status
        print("[*] Checking EOL status...")
        eol_results = []
        for product, version in findings.items():
            result = self.check_eol_status(product, version)
            result['product'] = product
            result['version'] = version
            eol_results.append(result)
        
        # Generate report
        self.generate_report(url, findings, eol_results)

def main():
    parser = argparse.ArgumentParser(
        description='EOL Framework Scanner - Check if detected frameworks are end-of-life',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python eol_scanner.py https://example.com
  python eol_scanner.py https://target.com/app
  python eol_scanner.py https://internal.corp --no-verify-ssl
        """
    )
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--no-verify-ssl', '-k', action='store_true',
                        help='Disable SSL certificate verification (for pentesting)')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url
    
    scanner = EOLScanner(verify_ssl=not args.no_verify_ssl)
    scanner.scan(args.url)

if __name__ == '__main__':
    main()
