#!/usr/bin/env python3
"""
👻 Ghost Layer: Temporal Recon Module
Discovers endpoints that existed in the past but were removed from frontend
Still accessible in backend - the "forgotten" attack surface!

Sources: Wayback Machine, CommonCrawl, URLScan.io
"""
import subprocess
import json
import os
import sys
from pathlib import Path
import requests
from urllib.parse import urlparse

def query_wayback(target, output_dir):
    """Query Wayback Machine for historical URLs"""
    print(f"[+] Querying Wayback Machine for {target}...")
    output_file = f"{output_dir}/wayback.txt"
    
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=text&fl=original&collapse=urlkey"
    
    try:
        response = requests.get(url, timeout=120)
        if response.status_code == 200:
            urls = [line.strip() for line in response.text.splitlines() if line.strip()]
            
            with open(output_file, "w") as f:
                f.write("\n".join(urls))
            
            print(f"[✓] Wayback found {len(urls)} historical URLs")
            return urls
    except Exception as e:
        print(f"[!] Wayback error: {e}")
    return []

def query_commoncrawl(target, output_dir):
    """Query CommonCrawl for historical URLs"""
    print(f"[+] Querying CommonCrawl for {target}...")
    output_file = f"{output_dir}/commoncrawl.txt"
    
    url = f"http://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.{target}/*&output=json"
    
    urls = []
    try:
        response = requests.get(url, timeout=120)
        if response.status_code == 200:
            for line in response.text.splitlines():
                try:
                    data = json.loads(line)
                    urls.append(data.get("url", ""))
                except:
                    pass
            
            with open(output_file, "w") as f:
                f.write("\n".join(urls))
            
            print(f"[✓] CommonCrawl found {len(urls)} URLs")
    except Exception as e:
        print(f"[!] CommonCrawl error: {e}")
    
    return urls

def query_urlscan(target, output_dir):
    """Query URLScan.io for recent scans"""
    print(f"[+] Querying URLScan.io for {target}...")
    output_file = f"{output_dir}/urlscan.txt"
    
    url = f"https://urlscan.io/api/v1/search/?q=domain:{target}"
    
    urls = []
    try:
        response = requests.get(url, timeout=60)
        if response.status_code == 200:
            data = response.json()
            for result in data.get("results", []):
                if "page" in result and "url" in result["page"]:
                    urls.append(result["page"]["url"])
            
            with open(output_file, "w") as f:
                f.write("\n".join(urls))
            
            print(f"[✓] URLScan found {len(urls)} URLs")
    except Exception as e:
        print(f"[!] URLScan error: {e}")
    
    return urls

def extract_ghost_endpoints(all_urls, target, output_dir):
    """
    Extract endpoints that existed in the past but may be removed from current frontend
    Focus on: API endpoints, admin panels, old versions, debug endpoints
    """
    print("[+] Extracting ghost endpoints from historical data...")
    
    ghost_patterns = [
        r"/api/v[0-9]",           # Old API versions
        r"/admin",                # Admin panels
        r"/debug",                # Debug endpoints
        r"/test",                 # Test endpoints
        r"/internal",             # Internal APIs
        r"/backup",               # Backup files
        r"\.bak$",                # Backup extensions
        r"\.old$",                # Old file extensions
        r"/v1/",                  # Old API versions
        r"/v2/",                  # Old API versions
    ]
    
    ghost_endpoints = set()
    current_domain = f".{target}"
    
    for url in all_urls:
        if current_domain not in url:
            continue
        
        parsed = urlparse(url)
        path = parsed.path
        
        # Check if it matches ghost patterns
        import re
        for pattern in ghost_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                ghost_endpoints.add(url)
                break
    
    output_file = f"{output_dir}/ghost_endpoints.txt"
    with open(output_file, "w") as f:
        f.write("\n".join(sorted(ghost_endpoints)))
    
    print(f"[✓] Found {len(ghost_endpoints)} ghost endpoints (historical but potentially active)")
    return ghost_endpoints

def main(target, output_dir="results/ghost"):
    """Main temporal recon function"""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    print(f"\n{'='*60}")
    print(f"👻 GHOST LAYER: TEMPORAL RECON")
    print(f"{'='*60}\n")
    print("Discovering endpoints that existed in the past but were removed")
    print("from the frontend - the forgotten attack surface!\n")
    
    all_urls = []
    
    # Query all sources
    all_urls.extend(query_wayback(target, output_dir))
    all_urls.extend(query_commoncrawl(target, output_dir))
    all_urls.extend(query_urlscan(target, output_dir))
    
    # Remove duplicates
    all_urls = list(set(all_urls))
    
    # Save all URLs
    all_file = f"{output_dir}/all_temporal_urls.txt"
    with open(all_file, "w") as f:
        f.write("\n".join(all_urls))
    
    print(f"\n[✓] Total temporal URLs collected: {len(all_urls)}")
    
    # Extract ghost endpoints
    ghost_endpoints = extract_ghost_endpoints(all_urls, target, output_dir)
    
    return ghost_endpoints

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target> [output_dir]")
        sys.exit(1)
    
    target = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "results/ghost"
    main(target, output_dir)
