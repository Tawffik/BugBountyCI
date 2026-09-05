#!/usr/bin/env python3
"""
🎯 Nuclei Vulnerability Scanner Module
Uses nuclei with custom and community templates
"""
import subprocess
import json
import os
import sys
from pathlib import Path

def run_nuclei(target_file, output_dir, templates=None):
    """Run nuclei scan with specified templates"""
    print(f"[+] Running nuclei scan...")
    
    output_file = f"{output_dir}/nuclei_results.json"
    sarif_file = f"{output_dir}/nuclei_results.sarif"
    
    cmd = [
        "nuclei",
        "-l", target_file,
        "-severity", "low,medium,high,critical",
        "-json",
        "-o", output_file,
        "-se", sarif_file,
        "-silent"
    ]
    
    if templates:
        cmd.extend(["-t", templates])
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        
        if os.path.exists(output_file):
            findings = []
            with open(output_file) as f:
                for line in f:
                    try:
                        findings.append(json.loads(line))
                    except:
                        pass
            
            print(f"[✓] Nuclei found {len(findings)} vulnerabilities")
            
            # Save summary
            summary_file = f"{output_dir}/nuclei_summary.txt"
            with open(summary_file, "w") as f:
                f.write(f"Total Findings: {len(findings)}\n\n")
                for finding in findings:
                    f.write(f"Template: {finding.get('template-id', 'N/A')}\n")
                    f.write(f"URL: {finding.get('matched-at', 'N/A')}\n")
                    f.write(f"Severity: {finding.get('info', {}).get('severity', 'N/A')}\n")
                    f.write(f"Description: {finding.get('info', {}).get('description', 'N/A')}\n")
                    f.write("-" * 80 + "\n")
            
            return findings
    except Exception as e:
        print(f"[!] Nuclei error: {e}")
    
    return []

def update_templates():
    """Update nuclei templates"""
    print("[+] Updating nuclei templates...")
    try:
        subprocess.run(["nuclei", "-update-templates"], capture_output=True, timeout=120)
        print("[✓] Templates updated")
    except:
        print("[!] Template update failed")

def main(target_file, output_dir="results/scan", templates=None):
    """Main nuclei scanning function"""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    print(f"\n{'='*60}")
    print(f"🎯 NUCLEI VULNERABILITY SCAN")
    print(f"{'='*60}\n")
    
    update_templates()
    findings = run_nuclei(target_file, output_dir, templates)
    
    return findings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_file> [output_dir] [templates_dir]")
        sys.exit(1)
    
    target_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "results/scan"
    templates = sys.argv[3] if len(sys.argv) > 3 else None
    main(target_file, output_dir, templates)
