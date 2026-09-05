#!/usr/bin/env python3
"""
👻 Ghost Layer: Parameter Ghost Mining Module
Discovers parameters that existed in old versions but were removed
These parameters often still work in the backend!

Techniques:
1. Extract parameters from historical URLs (Wayback/CommonCrawl)
2. Compare with current URLs to find "ghost" parameters
3. Test ghost parameters for active functionality
"""
import subprocess
import json
import os
import sys
from pathlib import Path
import requests
from urllib.parse import urlparse, parse_qs

def extract_parameters(urls):
    """Extract all parameters from a list of URLs"""
    params = {}
    
    for url in urls:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        endpoint = parsed.path
        
        if endpoint not in params:
            params[endpoint] = set()
        
        for param_name in query_params.keys():
            params[endpoint].add(param_name)
    
    return params

def compare_with_current(target, historical_params, output_dir):
    """
    Compare historical parameters with current site
    Find parameters that existed before but are not in current frontend
    """
    print(f"[+] Crawling current site to compare parameters...")
    
    # Use katana to crawl current site
    current_params_file = f"{output_dir}/current_params.json"
    
    cmd = [
        "katana",
        "-u", f"https://{target}",
        "-silent",
        "-json",
        "-o", current_params_file
    ]
    
    current_params = {}
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if os.path.exists(current_params_file):
            with open(current_params_file) as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        url = data.get("url", "")
                        parsed = urlparse(url)
                        endpoint = parsed.path
                        query_params = parse_qs(parsed.query)
                        
                        if endpoint not in current_params:
                            current_params[endpoint] = set()
                        
                        for param_name in query_params.keys():
                            current_params[endpoint].add(param_name)
                    except:
                        pass
    except Exception as e:
        print(f"[!] Katana error: {e}")
    
    # Find ghost parameters
    ghost_params = {}
    
    for endpoint, hist_params in historical_params.items():
        curr_params = current_params.get(endpoint, set())
        
        # Ghost = historical but not in current
        ghosts = hist_params - curr_params
        
        if ghosts:
            ghost_params[endpoint] = ghosts
    
    # Save results
    output_file = f"{output_dir}/ghost_parameters.txt"
    with open(output_file, "w") as f:
        f.write("# Ghost Parameters - Existed in old versions, removed from frontend\n")
        f.write("# These may still work in the backend!\n\n")
        
        for endpoint, params in ghost_params.items():
            f.write(f"Endpoint: {endpoint}\n")
            for param in sorted(params):
                f.write(f"  - {param}\n")
            f.write("\n")
    
    total_ghosts = sum(len(p) for p in ghost_params.values())
    print(f"[✓] Found {total_ghosts} ghost parameters across {len(ghost_params)} endpoints")
    
    return ghost_params

def generate_test_payloads(ghost_params, output_dir):
    """Generate test payloads for ghost parameters"""
    print("[+] Generating test payloads for ghost parameters...")
    
    payloads_file = f"{output_dir}/ghost_payloads.txt"
    
    test_values = [
        "test", "admin", "1", "true", "debug", "dev",
        "{{7*7}}", "' OR '1'='1", "<script>alert(1)</script>",
        "../../../../etc/passwd", "php://filter/read=convert.base64-encode/resource=index.php"
    ]
    
    with open(payloads_file, "w") as f:
        for endpoint, params in ghost_params.items():
            f.write(f"# Endpoint: {endpoint}\n")
            for param in params:
                for value in test_values:
                    f.write(f"{endpoint}?{param}={value}\n")
            f.write("\n")
    
    print(f"[✓] Generated test payloads in {payloads_file}")
    return payloads_file

def main(historical_urls_file, target, output_dir="results/ghost"):
    """Main parameter ghost mining function"""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    print(f"\n{'='*60}")
    print(f"👻 GHOST LAYER: PARAMETER MINING")
    print(f"{'='*60}\n")
    print("Finding parameters that existed in old versions but were removed")
    print("from the frontend - often still functional in backend!\n")
    
    # Load historical URLs
    historical_urls = []
    if os.path.exists(historical_urls_file):
        with open(historical_urls_file) as f:
            historical_urls = [line.strip() for line in f if line.strip()]
    
    print(f"[+] Loaded {len(historical_urls)} historical URLs")
    
    # Extract parameters from historical data
    historical_params = extract_parameters(historical_urls)
    print(f"[+] Extracted parameters from {len(historical_params)} endpoints")
    
    # Compare with current site
    ghost_params = compare_with_current(target, historical_params, output_dir)
    
    # Generate test payloads
    if ghost_params:
        generate_test_payloads(ghost_params, output_dir)
    
    return ghost_params

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <historical_urls_file> <target> [output_dir]")
        sys.exit(1)
    
    historical_file = sys.argv[1]
    target = sys.argv[2]
    output_dir = sys.argv[3] if len(sys.argv) > 3 else "results/ghost"
    main(historical_file, target, output_dir)
