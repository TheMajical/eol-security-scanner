#!/usr/bin/env python3
"""
EOL Quick Checker - Interactive version lookup tool
Quickly check if a specific framework/version is EOL
"""

import requests
import json
from datetime import datetime
import sys

class EOLChecker:
    def __init__(self):
        self.api_base = "https://endoflife.date/api"
        self.session = requests.Session()
        
    def get_available_products(self):
        """Get list of all available products from EOL API"""
        try:
            resp = self.session.get(f"{self.api_base}/all.json", timeout=5)
            if resp.status_code == 200:
                return resp.json()
            return []
        except:
            return []
    
    def search_product(self, query):
        """Search for products matching the query"""
        products = self.get_available_products()
        query_lower = query.lower()
        
        # Exact match first
        if query_lower in products:
            return [query_lower]
        
        # Partial matches
        matches = [p for p in products if query_lower in p.lower()]
        return matches
    
    def get_product_info(self, product):
        """Get all version cycles for a product"""
        try:
            resp = self.session.get(f"{self.api_base}/{product}.json", timeout=5)
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as e:
            print(f"[!] Error fetching data: {e}")
            return None
    
    def check_version(self, product, version):
        """Check EOL status for specific product version"""
        cycles = self.get_product_info(product)
        
        if not cycles:
            return None
        
        # Try to find matching cycle
        version_parts = version.split('.')
        major_version = version_parts[0]
        
        # Look for exact or major version match
        for cycle in cycles:
            cycle_version = str(cycle.get('cycle', ''))
            
            if cycle_version == version or cycle_version == major_version:
                return self.format_cycle_info(cycle, product, version)
        
        # If no match, show all available versions
        return {
            'found': False,
            'available_versions': [str(c.get('cycle', '')) for c in cycles[:10]]
        }
    
    def format_cycle_info(self, cycle, product, version):
        """Format cycle information into readable format"""
        eol_date = cycle.get('eol')
        support_date = cycle.get('support')
        lts = cycle.get('lts', False)
        latest = cycle.get('latest', 'Unknown')
        release_date = cycle.get('releaseDate', 'Unknown')
        
        info = {
            'found': True,
            'product': product,
            'version': version,
            'cycle': str(cycle.get('cycle', '')),
            'latest_in_cycle': latest,
            'release_date': release_date,
            'eol_date': eol_date,
            'support_date': support_date,
            'lts': lts,
            'is_eol': False,
            'is_supported': True,
            'days_until_eol': None,
            'days_until_support_end': None
        }
        
        today = datetime.now()
        
        # Check EOL status
        if eol_date and eol_date != False:
            try:
                eol_datetime = datetime.strptime(str(eol_date), '%Y-%m-%d')
                info['is_eol'] = eol_datetime < today
                if not info['is_eol']:
                    info['days_until_eol'] = (eol_datetime - today).days
                else:
                    info['days_until_eol'] = -(today - eol_datetime).days
            except:
                pass
        
        # Check support status
        if support_date and support_date != False:
            try:
                support_datetime = datetime.strptime(str(support_date), '%Y-%m-%d')
                info['is_supported'] = support_datetime >= today
                if info['is_supported']:
                    info['days_until_support_end'] = (support_datetime - today).days
            except:
                pass
        
        return info
    
    def display_result(self, result):
        """Display formatted result"""
        print("\n" + "="*70)
        
        if not result:
            print("[!] Product not found in endoflife.date database")
            print("="*70)
            return
        
        if not result.get('found'):
            print("[!] Version not found for this product")
            print("\nAvailable versions:")
            for v in result.get('available_versions', []):
                print(f"  - {v}")
            print("="*70)
            return
        
        # Header
        print(f"PRODUCT: {result['product'].upper()}")
        print(f"VERSION: {result['version']} (Cycle: {result['cycle']})")
        print("="*70)
        
        # Release info
        print(f"\n📦 Release Information:")
        print(f"   Release Date: {result['release_date']}")
        print(f"   Latest in Cycle: {result['latest_in_cycle']}")
        if result['lts']:
            print(f"   LTS: Yes (Long Term Support)")
        
        # Support status
        print(f"\n🛡️  Support Status:")
        if result['support_date']:
            if result['is_supported']:
                print(f"   ✓ Security Support: Active")
                if result['days_until_support_end']:
                    print(f"   Support Ends: {result['support_date']} ({result['days_until_support_end']} days)")
            else:
                print(f"   ✗ Security Support: ENDED on {result['support_date']}")
        else:
            print(f"   Support Info: Not specified")
        
        # EOL status
        print(f"\n⏰ End of Life Status:")
        if result['eol_date']:
            if result['is_eol']:
                days_ago = abs(result['days_until_eol'])
                print(f"   ✗ STATUS: END OF LIFE (ended {days_ago} days ago)")
                print(f"   EOL Date: {result['eol_date']}")
                print(f"\n   ⚠️  CRITICAL: This version is no longer maintained!")
            else:
                print(f"   ✓ STATUS: ACTIVE")
                print(f"   EOL Date: {result['eol_date']} ({result['days_until_eol']} days remaining)")
        else:
            print(f"   EOL Date: Not specified")
        
        # Security recommendation
        print(f"\n💡 Security Recommendation:")
        if result['is_eol']:
            print(f"   🔴 URGENT: Upgrade immediately to a supported version!")
        elif not result['is_supported']:
            print(f"   🟠 WARNING: No security support. Plan upgrade soon.")
        elif result['days_until_eol'] and result['days_until_eol'] < 180:
            print(f"   🟡 NOTICE: EOL approaching. Start planning migration.")
        else:
            print(f"   🟢 OK: Version is currently supported.")
        
        print("="*70)
    
    def interactive_mode(self):
        """Run in interactive mode"""
        print("\n" + "="*70)
        print("EOL QUICK CHECKER - Interactive Mode")
        print("="*70)
        print("Check if your framework/library version is end-of-life")
        print("Type 'exit' or 'quit' to leave\n")
        
        while True:
            try:
                # Get product
                product_input = input("Enter framework/product name (e.g., django, dotnet, php): ").strip()
                
                if product_input.lower() in ['exit', 'quit', 'q']:
                    print("\n[*] Goodbye!")
                    break
                
                if not product_input:
                    continue
                
                # Search for product
                matches = self.search_product(product_input)
                
                if not matches:
                    print(f"[!] No products found matching '{product_input}'")
                    print("[*] Try: django, dotnet, php, nodejs, python, java, etc.")
                    continue
                
                # If multiple matches, let user choose
                if len(matches) > 1:
                    print(f"\nFound {len(matches)} matches:")
                    for i, match in enumerate(matches[:10], 1):
                        print(f"  {i}. {match}")
                    
                    choice = input(f"\nSelect product (1-{min(len(matches), 10)}): ").strip()
                    try:
                        idx = int(choice) - 1
                        if 0 <= idx < len(matches):
                            product = matches[idx]
                        else:
                            print("[!] Invalid selection")
                            continue
                    except ValueError:
                        print("[!] Invalid input")
                        continue
                else:
                    product = matches[0]
                    print(f"[*] Found: {product}")
                
                # Get version
                version = input(f"Enter version for {product} (e.g., 3.2, 4.0): ").strip()
                
                if not version:
                    continue
                
                # Check version
                print(f"\n[*] Checking {product} version {version}...")
                result = self.check_version(product, version)
                self.display_result(result)
                
                print("\n" + "-"*70 + "\n")
                
            except KeyboardInterrupt:
                print("\n\n[*] Interrupted. Goodbye!")
                break
            except Exception as e:
                print(f"[!] Error: {e}")
                continue
    
    def quick_check(self, product, version):
        """Quick single check mode"""
        print(f"\n[*] Checking {product} version {version}...")
        
        # Search for product
        matches = self.search_product(product)
        
        if not matches:
            print(f"[!] Product '{product}' not found")
            return
        
        product = matches[0]
        result = self.check_version(product, version)
        self.display_result(result)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='EOL Quick Checker - Check if framework versions are end-of-life',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python eol_checker.py                    # Interactive mode
  python eol_checker.py django 3.2         # Quick check
  python eol_checker.py dotnet 6.0         # Quick check
  python eol_checker.py python 3.8         # Quick check
        """
    )
    
    parser.add_argument('product', nargs='?', help='Product/framework name')
    parser.add_argument('version', nargs='?', help='Version number')
    
    args = parser.parse_args()
    
    checker = EOLChecker()
    
    if args.product and args.version:
        # Quick check mode
        checker.quick_check(args.product, args.version)
    else:
        # Interactive mode
        checker.interactive_mode()

if __name__ == '__main__':
    main()
