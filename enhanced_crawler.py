"""
Enhanced crawler with pentesting format output
"""

import json
import os
from datetime import datetime

def save_enhanced_crawl_results(crawler, output_dir='crawl_output'):
    """Save crawl results in format ready for pentesting"""
    
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Extract endpoints for testing
    endpoints = []
    for url, page_data in crawler.input_detector.input_fields_data.items():
        # Process forms
        for form in page_data.get('forms', []):
            endpoint = {
                'url': url,
                'method': form.get('method', 'POST').upper(),
                'parameters': {}
            }
            
            for input_field in form.get('inputs', []):
                param_name = input_field.get('name')
                if param_name:
                    endpoint['parameters'][param_name] = input_field.get('placeholder', 'test')
            
            if endpoint['parameters']:
                endpoints.append(endpoint)
        
        # Process standalone inputs
        if not page_data.get('forms') and page_data.get('inputs'):
            endpoint = {
                'url': url,
                'method': 'GET',
                'parameters': {}
            }
            
            for input_field in page_data.get('inputs', []):
                param_name = input_field.get('name')
                if param_name:
                    endpoint['parameters'][param_name] = input_field.get('placeholder', 'test')
            
            if endpoint['parameters']:
                endpoints.append(endpoint)
    
    # Save endpoints file
    endpoints_file = os.path.join(output_dir, f'endpoints_{timestamp}.json')
    with open(endpoints_file, 'w', encoding='utf-8') as f:
        json.dump(endpoints, f, indent=2, ensure_ascii=False)
    
    # Save full data file
    full_data = {
        'domain': crawler.domain,
        'start_url': crawler.start_url,
        'timestamp': timestamp,
        'statistics': {
            'crawled_urls': len(crawler.visited_urls),
            'discovered_urls': len(crawler.discovered_urls),
            'pages_with_inputs': len(crawler.input_detector.input_fields_data),
            'auth_pages': len(crawler.input_detector.auth_pages_data)
        },
        'endpoints': endpoints,
        'input_fields_data': crawler.input_detector.input_fields_data,
        'auth_pages': crawler.input_detector.auth_pages_data
    }
    
    full_file = os.path.join(output_dir, f'full_data_{timestamp}.json')
    with open(full_file, 'w', encoding='utf-8') as f:
        json.dump(full_data, f, indent=2, ensure_ascii=False)
    
    print(f"\nCrawl results saved:")
    print(f"  - Endpoints: {endpoints_file}")
    print(f"  - Full data: {full_file}")
    
    return endpoints_file, full_file