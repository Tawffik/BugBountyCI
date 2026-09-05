#!/usr/bin/env python3
"""
🌍 Live Host Probing & Fingerprinting Module
Uses: httpx for live probing, tech detection, WAF detection
"""
import subprocess
import json
import os
import sys
from pathlib import Path

def run_httpx(input_file, output_dir):
    """Run httpx for live probing with tech detection"""
    print(f"[+] Running httpx on {input_file}...")
    
    live_file = f"{output_dir}/live.txt"
    
    cmd = [
        "httpx",
        "-l", input_file,
        "-silent",
        "-follow-redirects",
        "-status-code",
        "-tech-detect",
        "-title",
        "-content-length",
        "-o", live_file
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if os.path.exists(live_file):
            with open(live_file) as f:
                count = len([l for l in f if l.strip()])
            print(f"[✓] httpx found {count} live hosts")
            return live_file
    except Exception as e:
        print(f"[!] httpx error: {e}")
    return None

def detect_waf(input_file, output_dir):
    """Detect WAFs using wafw00f"""
    print(f"[+] Detecting WAFs...")
    waf_file = f"{output_dir}/waf.txt"
    
    cmd = ["wafw00f", "-i", input_file, "-o", waf_file]
    
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        print(f"[✓] WAF detection completed")
        return waf_file
    except Exception as e:
        print(f"[!] WAF detection error: {e}")
    return None

def main(input_file, output_dir="results/recon"):
    """Main live probing function"""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    print(f"\n{'='*60}")
    print(f"🌍 LIVE PROBING & FINGERPRINTING")
    print(f"{'='*60}\n")
    
    live_file = run_httpx(input_file, output_dir)
    if live_file:
        detect_waf(live_file, output_dir)
    
    return live_file

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input_file> [output_dir]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "results/recon"
    main(input_file, output_dir)
