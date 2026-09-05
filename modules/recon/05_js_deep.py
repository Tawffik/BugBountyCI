#!/usr/bin/env python3
"""
👻 Ghost Layer: JavaScript Deep Mining Module
Goes beyond simple URL extraction from JS files:
- Extract API patterns and endpoints
- Find authentication flows
- Discover internal endpoints
- Detect hardcoded secrets
- Identify API keys and tokens
"""
import subprocess
import json
import os
import sys
from pathlib import Path
import re
import requests

def download_js_files(url_file, output_dir):
    """Download JS files for analysis"""
    print(f"[+] Downloading JS files from {url_file}...")
    
    js_dir = f"{output_dir}/js_files"
    Path(js_dir).mkdir(parents=True, exist_ok=True)
    
    js_urls = []
    with open(url_file) as f:
        js_urls = [line.strip() for line in f if line.strip() and line.endswith(".js")]
    
    print(f"[+] Found {len(js_urls)} JS files")
    
    for i, url in enumerate(js_urls[:50]):  # Limit to 50 for now
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                filename = f"{js_dir}/js_{i}.js"
                with open(filename, "w") as f:
                    f.write(response.text)
        except:
            pass
    
    return js_dir

def extract_endpoints(js_dir, output_dir):
    """Extract API endpoints from JS files"""
    print("[+] Extracting API endpoints...")
    
    endpoint_patterns = [
        r'["'](/api/[^"']+)["']',
        r'["']([^"']+/api/[^"']+)["']',
        r'fetch\(["']([^"']+)["']',
        r'axios\.[a-z]+\(["']([^"']+)["']',
        r'XMLHttpRequest.*["']([^"']+)["']',
        r'url["']\s*[:=]\s*["']([^"']+)["']',
        r'endpoint["']\s*[:=]\s*["']([^"']+)["']',
    ]
    
    endpoints = set()
    
    for js_file in Path(js_dir).glob("*.js"):
        content = js_file.read_text()
        
        for pattern in endpoint_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            endpoints.update(matches)
    
    output_file = f"{output_dir}/api_endpoints.txt"
    with open(output_file, "w") as f:
        f.write("\n".join(sorted(endpoints)))
    
    print(f"[✓] Found {len(endpoints)} API endpoints")
    return endpoints

def find_secrets(js_dir, output_dir):
    """Find hardcoded secrets in JS files"""
    print("[+] Searching for hardcoded secrets...")
    
    secret_patterns = {
        "API Keys": [
            r'["']?api[_-]?key["']?\s*[:=]\s*["']([^"']{10,})["']',
            r'["']?apikey["']?\s*[:=]\s*["']([^"']{10,})["']',
        ],
        "AWS Keys": [
            r'AKIA[0-9A-Z]{16}',
            r'["']?aws[_-]?secret["']?\s*[:=]\s*["']([^"']+)["']',
        ],
        "Tokens": [
            r'["']?token["']?\s*[:=]\s*["']([^"']{20,})["']',
            r'["']?auth[_-]?token["']?\s*[:=]\s*["']([^"']{20,})["']',
            r'["']?access[_-]?token["']?\s*[:=]\s*["']([^"']{20,})["']',
        ],
        "Passwords": [
            r'["']?password["']?\s*[:=]\s*["']([^"']+)["']',
            r'["']?secret["']?\s*[:=]\s*["']([^"']+)["']',
        ],
    }
    
    secrets = {}
    
    for js_file in Path(js_dir).glob("*.js"):
        content = js_file.read_text()
        
        for category, patterns in secret_patterns.items():
            if category not in secrets:
                secrets[category] = set()
            
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                secrets[category].update(matches)
    
    # Save results
    output_file = f"{output_dir}/secrets.txt"
    with open(output_file, "w") as f:
        for category, found_secrets in secrets.items():
            if found_secrets:
                f.write(f"\n=== {category} ===\n")
                for secret in sorted(found_secrets):
                    f.write(f"{secret}\n")
    
    total_secrets = sum(len(s) for s in secrets.values())
    print(f"[✓] Found {total_secrets} potential secrets")
    return secrets

def detect_auth_flows(js_dir, output_dir):
    """Detect authentication flows in JS"""
    print("[+] Detecting authentication flows...")
    
    auth_patterns = {
        "Login Endpoints": [
            r'["']([^"']*login[^"']*)["']',
            r'["']([^"']*signin[^"']*)["']',
            r'["']([^"']*auth[^"']*)["']',
        ],
        "OAuth": [
            r'["']([^"']*oauth[^"']*)["']',
            r'["']([^"']*callback[^"']*)["']',
        ],
        "JWT": [
            r'["']?jwt["']?\s*[:=]',
            r'["']?bearer["']?\s*[:=]',
        ],
    }
    
    auth_endpoints = {}
    
    for js_file in Path(js_dir).glob("*.js"):
        content = js_file.read_text()
        
        for category, patterns in auth_patterns.items():
            if category not in auth_endpoints:
                auth_endpoints[category] = set()
            
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                auth_endpoints[category].update(matches)
    
    # Save results
    output_file = f"{output_dir}/auth_flows.txt"
    with open(output_file, "w") as f:
        for category, endpoints in auth_endpoints.items():
            if endpoints:
                f.write(f"\n=== {category} ===\n")
                for endpoint in sorted(endpoints):
                    f.write(f"{endpoint}\n")
    
    print(f"[✓] Detected authentication flows")
    return auth_endpoints

def run_linkfinder(js_dir, output_dir):
    """Run LinkFinder for additional endpoint discovery"""
    print("[+] Running LinkFinder...")
    
    output_file = f"{output_dir}/linkfinder.txt"
    
    for js_file in Path(js_dir).glob("*.js"):
        cmd = [
            "python3", "/opt/LinkFinder/linkfinder.py",
            "-i", str(js_file),
            "-o", "cli"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.stdout:
                with open(output_file, "a") as f:
                    f.write(result.stdout)
        except:
            pass
    
    print(f"[✓] LinkFinder completed")

def main(url_file, output_dir="results/js"):
    """Main JS deep mining function"""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    print(f"\n{'='*60}")
    print(f"👻 GHOST LAYER: JS DEEP MINING")
    print(f"{'='*60}\n")
    print("Extracting API patterns, secrets, and internal endpoints from JS!\n")
    
    # Download JS files
    js_dir = download_js_files(url_file, output_dir)
    
    # Extract various data
    endpoints = extract_endpoints(js_dir, output_dir)
    secrets = find_secrets(js_dir, output_dir)
    auth_flows = detect_auth_flows(js_dir, output_dir)
    
    # Run LinkFinder
    run_linkfinder(js_dir, output_dir)
    
    return {
        "endpoints": endpoints,
        "secrets": secrets,
        "auth_flows": auth_flows
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <url_file> [output_dir]")
        sys.exit(1)
    
    url_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "results/js"
    main(url_file, output_dir)
