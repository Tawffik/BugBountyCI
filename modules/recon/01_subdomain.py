#!/usr/bin/env python3
"""
🌐 Subdomain Enumeration Module
Uses: subfinder, amass, crt.sh, assetfinder, CT logs
"""
import subprocess
import json
import os
import sys
from pathlib import Path
import requests

def run_subfinder(target, output_dir):
    """Run subfinder for passive subdomain enumeration"""
    print(f"[+] Running subfinder for {target}...")
    output_file = f"{output_dir}/subfinder.txt"
    
    cmd = ["subfinder", "-d", target, "-silent", "-o", output_file]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            with open(output_file) as f:
                count = len([l for l in f if l.strip()])
            print(f"[✓] subfinder found {count} subdomains")
            return output_file
    except Exception as e:
        print(f"[!] subfinder error: {e}")
    return None

def run_amass(target, output_dir):
    """Run amass for deep DNS enumeration"""
    print(f"[+] Running amass for {target}...")
    output_file = f"{output_dir}/amass.txt"
    
    cmd = ["amass", "enum", "-passive", "-d", target, "-o", output_file]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode == 0:
            with open(output_file) as f:
                count = len([l for l in f if l.strip()])
            print(f"[✓] amass found {count} subdomains")
            return output_file
    except Exception as e:
        print(f"[!] amass error: {e}")
    return None

def run_crtsh(target, output_dir):
    """Query crt.sh for Certificate Transparency logs"""
    print(f"[+] Querying crt.sh for {target}...")
    output_file = f"{output_dir}/crtsh.txt"
    
    url = f"https://crt.sh/?q=%.{target}&output=json"
    
    try:
        response = requests.get(url, timeout=60)
        if response.status_code == 200:
            certs = response.json()
            subdomains = set()
            for cert in certs:
                name = cert.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip()
                    if line.endswith(f".{target}"):
                        subdomains.add(line)
            
            with open(output_file, "w") as f:
                f.write("\n".join(sorted(subdomains)))
            
            print(f"[✓] crt.sh found {len(subdomains)} subdomains")
            return output_file
    except Exception as e:
        print(f"[!] crt.sh error: {e}")
    return None

def merge_subdomains(output_dir):
    """Merge and deduplicate all subdomain sources"""
    print("[+] Merging and deduplicating subdomains...")
    
    all_subs = set()
    for filename in ["subfinder.txt", "amass.txt", "crtsh.txt", "assetfinder.txt"]:
        filepath = f"{output_dir}/{filename}"
        if os.path.exists(filepath):
            with open(filepath) as f:
                for line in f:
                    line = line.strip().lower()
                    if line:
                        all_subs.add(line)
    
    merged_file = f"{output_dir}/all_subs.txt"
    with open(merged_file, "w") as f:
        f.write("\n".join(sorted(all_subs)))
    
    print(f"[✓] Total unique subdomains: {len(all_subs)}")
    return merged_file

def main(target, output_dir="results/recon"):
    """Main subdomain enumeration function"""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    print(f"\n{'='*60}")
    print(f"🌐 SUBDOMAIN ENUMERATION: {target}")
    print(f"{'='*60}\n")
    
    run_subfinder(target, output_dir)
    run_amass(target, output_dir)
    run_crtsh(target, output_dir)
    
    return merge_subdomains(output_dir)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target> [output_dir]")
        sys.exit(1)
    
    target = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "results/recon"
    main(target, output_dir)
