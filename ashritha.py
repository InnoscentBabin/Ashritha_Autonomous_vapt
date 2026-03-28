#!/usr/bin/env python3
"""
Ashritha - Autonomous Web Pentesting Tool
AI-Powered Vulnerability Scanner with Adaptive Payload Generation
"""

import sys
import os
import argparse
import logging
from datetime import datetime

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from integrated_main import IntegratedPentestingTool

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def generate_banner(tool_name, font='slant'):
    """Generate dynamic banner using pyfiglet"""
    try:
        import pyfiglet
        
        # Create figlet font
        figlet = pyfiglet.Figlet(font=font)
        
        # Generate banner
        banner = figlet.renderText(tool_name)
        
        # Add styling
        styled_banner = []
        styled_banner.append("╔" + "═" * 78 + "╗")
        for line in banner.split('\n'):
            if line.strip():
                # Center the text
                padding = (78 - len(line.rstrip())) // 2
                if padding < 0:
                    padding = 0
                styled_banner.append("║" + " " * padding + line.rstrip() + " " * (78 - padding - len(line.rstrip())) + "║")
        
        # Add description line
        styled_banner.append("║" + " " * 78 + "║")
        desc = "⚡ Autonomous Web Pentesting Tool ⚡"
        padding = (78 - len(desc)) // 2
        styled_banner.append("║" + " " * padding + desc + " " * (78 - padding - len(desc)) + "║")
        
        # Add AI and adaptive info
        ai_text = "🤖 AI-Powered | 🔄 Adaptive Payloads | 🎯 Intelligent Testing"
        padding = (78 - len(ai_text)) // 2
        styled_banner.append("║" + " " * padding + ai_text + " " * (78 - padding - len(ai_text)) + "║")
        
        # Bottom border
        styled_banner.append("╚" + "═" * 78 + "╝")
        
        return "\n".join(styled_banner)
        
    except ImportError:
        # Fallback if pyfiglet is not installed
        return generate_simple_banner(tool_name)
    except Exception as e:
        logger.debug(f"Banner generation error: {e}")
        return generate_simple_banner(tool_name)

def generate_simple_banner(tool_name):
    """Generate simple banner if pyfiglet is not available"""
    banner = []
    banner.append("╔" + "═" * 60 + "╗")
    banner.append("║" + " " * 60 + "║")
    
    # Center the tool name
    name_padding = (60 - len(tool_name)) // 2
    banner.append("║" + " " * name_padding + tool_name.upper() + " " * (60 - name_padding - len(tool_name)) + "║")
    
    banner.append("║" + " " * 60 + "║")
    desc = "Autonomous Web Pentesting Tool"
    desc_padding = (60 - len(desc)) // 2
    banner.append("║" + " " * desc_padding + desc + " " * (60 - desc_padding - len(desc)) + "║")
    
    banner.append("║" + " " * 60 + "║")
    ai_text = "AI-Powered | Adaptive Payloads"
    ai_padding = (60 - len(ai_text)) // 2
    banner.append("║" + " " * ai_padding + ai_text + " " * (60 - ai_padding - len(ai_text)) + "║")
    
    banner.append("╚" + "═" * 60 + "╝")
    
    return "\n".join(banner)

def main():
    # Tool name (can be changed by importing)
    tool_name = "ASHRITHA"
    
    parser = argparse.ArgumentParser(
        description=f'{tool_name} - Autonomous Web Pentesting Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full pentest on a website
  python main.py --mode full --url http://testphp.vulnweb.com
  
  # Quick scan with limited pages
  python main.py --mode full --url http://testphp.vulnweb.com --max-urls 30 --quick
  
  # Use specific AI model with adaptive depth
  python main.py --mode full --url http://testphp.vulnweb.com --model gemma3:1b --adaptive-depth 5

  
  # Available fonts: slant, standard, small, big, block, bubble, digital, etc.
        """
    )
    
    parser.add_argument('--mode', choices=['crawl', 'test', 'full'], default='full',
                       help='Operation mode: crawl, test, or full (default: full)')
    parser.add_argument('--url', help='Target URL for crawling (required for crawl/full mode)')
    parser.add_argument('--input-file', help='Input file with crawl data (for test mode)')
    parser.add_argument('--max-urls', type=int, default=50,
                       help='Maximum URLs to crawl (default: 50)')
    parser.add_argument('--delay', type=float, default=0.5,
                       help='Delay between requests in seconds (default: 0.5)')
    parser.add_argument('--min-confidence', choices=['high', 'medium', 'low'], default='medium',
                       help='Minimum confidence level for testing (default: medium)')
    parser.add_argument('--max-attempts', type=int, default=5,
                       help='Maximum attempts per test (default: 5)')
    parser.add_argument('--output-dir', default='pentest_results',
                       help='Output directory for results (default: pentest_results)')
    parser.add_argument('--quick', action='store_true',
                       help='Quick mode - reduces AI calls for faster testing')
    parser.add_argument('--model', default='gemma3:1b',
                       help='AI model to use (default: gemma3:1b)')
    parser.add_argument('--adaptive-depth', type=int, default=3,
                       help='Adaptive testing depth (default: 3)')
    parser.add_argument('--no-banner', action='store_true',
                       help='Disable banner display')
    parser.add_argument('--banner-font', default='slant',
                       help='Banner font for pyfiglet (default: slant)')
    parser.add_argument('--tool-name', default='ASHRITHA',
                       help='Tool name for banner (default: ASHRITHA)')
    
    args = parser.parse_args()
    
    # Update tool name if provided
    if args.tool_name:
        tool_name = args.tool_name.upper()
    
    # Print banner
    if not args.no_banner:
        try:
            banner = generate_banner(tool_name, args.banner_font)
            print("\n" + banner + "\n")
        except Exception as e:
            logger.debug(f"Banner error: {e}")
            print(generate_simple_banner(tool_name))
    
    # Validate arguments
    if args.mode in ['crawl', 'full'] and not args.url:
        print("Error: --url is required for crawl and full modes")
        sys.exit(1)
    
    if args.mode == 'test' and not args.input_file:
        print("Error: --input-file is required for test mode")
        sys.exit(1)
    
    # Configuration
    config = {
        'min_confidence': args.min_confidence,
        'max_attempts': args.max_attempts,
        'output_dir': args.output_dir,
        'quick_mode': args.quick,
        'ai_model': args.model,
        'adaptive_depth': args.adaptive_depth,
        'tool_name': tool_name
    }
    
    # Print configuration summary
    print("\n" + "="*70)
    print(f"   {tool_name} - Configuration Summary")
    print("="*70)
    print(f"Mode: {args.mode.upper()}")
    if args.url:
        print(f"Target: {args.url}")
    print(f"AI Model: {args.model}")
    print(f"Max URLs: {args.max_urls}")
    print(f"Min Confidence: {args.min_confidence}")
    print(f"Adaptive Depth: {args.adaptive_depth}")
    print(f"Max Attempts: {args.max_attempts}")
    print(f"Quick Mode: {'ON' if args.quick else 'OFF'}")
    print(f"Banner Font: {args.banner_font}")
    print("="*70 + "\n")
    
    # Initialize tool
    tool = IntegratedPentestingTool(config)
    
    try:
        if args.mode == 'crawl':
            print(f"[*] Starting {tool_name} crawl mode...")
            tool.crawl_website(args.url, args.max_urls, args.delay)
            tool.save_results()
            print(f"\n[+] Crawl completed! Results saved to: {args.output_dir}")
            
        elif args.mode == 'test':
            print(f"[*] Loading crawl data...")
            if tool.load_crawl_results(args.input_file):
                endpoints = tool.convert_to_endpoints()
                classifications = tool.classify_vulnerabilities(endpoints)
                tool.test_vulnerabilities(classifications)
                tool.save_results()
                print(f"\n[+] Testing completed!")
            
        else:  # full mode
            print(f"[*] Starting {tool_name} full pentesting pipeline...")
            print("\n[Phase 1] Crawling website...")
            tool.crawl_website(args.url, args.max_urls, args.delay)
            
            print("\n[Phase 2] Converting to endpoints...")
            endpoints = tool.convert_to_endpoints()
            
            print("\n[Phase 3] AI Vulnerability Classification...")
            classifications = tool.classify_vulnerabilities(endpoints)
            
            if classifications:
                print(f"\n[+] Found {len(classifications)} potential vulnerabilities to test")
                print("\n[Phase 4] Adaptive Vulnerability Testing...")
                tool.test_vulnerabilities(classifications)
            else:
                print("\n[!] No vulnerabilities detected by AI")
                print("[*] Attempting fallback pattern matching...")
                from ai_engine import AIEngine
                ai = AIEngine(model=args.model)
                for endpoint in endpoints[:5]:
                    vulns = ai._fallback_analysis(endpoint)
                    if vulns:
                        print(f"  Found potential vulnerabilities in {endpoint['url']}")
                        tool.test_vulnerabilities(vulns)
            
            print("\n[Phase 5] Saving results...")
            tool.save_results()
            
            print("\n" + "="*70)
            print(f"[+] {tool_name} PENTEST COMPLETE!")
            print(f"[+] Found {len(tool.vulnerabilities)} vulnerabilities")
            print(f"[+] Results saved in: {args.output_dir}/")
            print("="*70 + "\n")
        
    except KeyboardInterrupt:
        print(f"\n\n[!] {tool_name} interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()