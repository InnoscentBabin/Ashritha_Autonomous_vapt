#!/usr/bin/env python3
"""
Simple one-command execution for quick testing
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from integrated_main import IntegratedPentestingTool

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python simple_run.py <target_url>")
        print("Example: python simple_run.py http://testphp.vulnweb.com")
        sys.exit(1)
    
    target_url = sys.argv[1]
    
    print(f"\n[*] Starting pentest on: {target_url}")
    print("[*] This may take a few minutes...\n")
    
    # Initialize tool
    tool = IntegratedPentestingTool({
        'min_confidence': 'medium',
        'max_attempts': 5,
        'output_dir': 'pentest_results'
    })
    
    # Run full pipeline
    print("[Phase 1] Crawling website...")
    tool.crawl_website(target_url, max_urls=50, delay=1)
    
    print("\n[Phase 2] Converting to endpoints...")
    endpoints = tool.convert_to_endpoints()
    
    print("\n[Phase 3] Classifying vulnerabilities...")
    classifications = tool.classify_vulnerabilities(endpoints)
    
    print("\n[Phase 4] Testing vulnerabilities...")
    tool.test_vulnerabilities(classifications)
    
    print("\n[Phase 5] Saving results...")
    tool.save_results()
    
    print(f"\n[+] Complete! Found {len(tool.vulnerabilities)} vulnerabilities")
    print("[+] Results saved in pentest_results/ directory")