#!/usr/bin/env python3
"""
🔗 Chain Correlation Module (AI-Powered)
Links findings across different scan phases to identify attack chains

Example chain:
1. Subdomain takeover found
2. Admin panel on that subdomain
3. Default credentials work
4. RCE vulnerability exists
= Full takeover chain!
"""
import json
import os
import sys
from pathlib import Path
import requests
from collections import defaultdict

class ChainCorrelator:
    def __init__(self, output_dir="results/chain"):
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Define attack patterns
        self.attack_chains = {
            "subdomain_takeover_chain": {
                "indicators": ["subdomain_takeover", "cname_record", "dangling_dns"],
                "severity": "critical",
                "description": "Subdomain takeover + additional access = full compromise"
            },
            "auth_bypass_chain": {
                "indicators": ["weak_password", "admin_panel", "id_vuln"],
                "severity": "high",
                "description": "Weak credentials + admin access + IDOR = privilege escalation"
            },
            "info_disclosure_chain": {
                "indicators": ["git_exposure", "backup_files", "config_files"],
                "severity": "high",
                "description": "Source code exposure + configuration files = full codebase access"
            },
            "rce_chain": {
                "indicators": ["file_upload", "ssrf", "command_injection"],
                "severity": "critical",
                "description": "File upload + SSRF + command injection = RCE"
            }
        }
    
    def load_findings(self, results_dir):
        """Load all findings from different scan phases"""
        findings = defaultdict(list)
        
        # Load nuclei findings
        nuclei_file = f"{results_dir}/scan/nuclei_results.json"
        if os.path.exists(nuclei_file):
            with open(nuclei_file) as f:
                for line in f:
                    try:
                        findings["nuclei"].append(json.loads(line))
                    except:
                        pass
        
        # Load ghost layer findings
        ghost_file = f"{results_dir}/ghost/ghost_endpoints.txt"
        if os.path.exists(ghost_file):
            with open(ghost_file) as f:
                findings["ghost_endpoints"] = [line.strip() for line in f if line.strip()]
        
        # Load secrets
        secrets_file = f"{results_dir}/js/secrets.txt"
        if os.path.exists(secrets_file):
            with open(secrets_file) as f:
                findings["secrets"] = f.read()
        
        return findings
    
    def identify_chains(self, findings):
        """Identify attack chains by correlating findings"""
        chains = []
        
        # Check for subdomain takeover chain
        if "subdomain_takeover" in str(findings["nuclei"]):
            if findings.get("ghost_endpoints"):
                chains.append({
                    "chain_name": "subdomain_takeover_chain",
                    "severity": "critical",
                    "indicators": ["subdomain_takeover", "ghost_endpoints"],
                    "description": "Subdomain takeover + historical endpoints = expanded attack surface"
                })
        
        # Check for auth bypass chain
        has_admin = any("admin" in str(f).lower() for f in findings["nuclei"])
        has_secrets = "password" in findings.get("secrets", "").lower()
        
        if has_admin and has_secrets:
            chains.append({
                "chain_name": "auth_bypass_chain",
                "severity": "high",
                "indicators": ["admin_panel", "hardcoded_secrets"],
                "description": "Admin panel found + hardcoded secrets = potential unauthorized access"
            })
        
        # Check for info disclosure chain
        has_git = any("git" in str(f).lower() for f in findings["nuclei"])
        has_backups = any("backup" in str(f).lower() for f in findings["nuclei"])
        
        if has_git and has_backups:
            chains.append({
                "chain_name": "info_disclosure_chain",
                "severity": "high",
                "indicators": ["git_exposure", "backup_files"],
                "description": "Git repository + backup files = full source code disclosure"
            })
        
        return chains
    
    def use_ai_for_chain_analysis(self, findings):
        """Use AI to identify complex attack chains"""
        print("[+] Using AI to analyze attack chains...")
        
        # Prepare findings summary for AI
        summary = {
            "total_findings": len(findings["nuclei"]),
            "ghost_endpoints": len(findings.get("ghost_endpoints", [])),
            "has_secrets": bool(findings.get("secrets")),
            "findings_types": list(set(f.get("template-id", "unknown") for f in findings["nuclei"]))
        }
        
        prompt = f"""
        Analyze these security findings and identify potential attack chains:
        
        Summary:
        - Total vulnerabilities: {summary['total_findings']}
        - Ghost endpoints found: {summary['ghost_endpoints']}
        - Secrets discovered: {summary['has_secrets']}
        - Vulnerability types: {', '.join(summary['findings_types'][:10])}
        
        Identify attack chains where multiple findings combine to create a more severe impact.
        Return JSON with: chain_name, severity (critical/high/medium/low), indicators, description, remediation
        """
        
        # This would normally call an AI API
        # For now, return empty (placeholder)
        return []
    
    def correlate(self, results_dir):
        """Main correlation function"""
        print(f"[+] Loading findings from {results_dir}...")
        findings = self.load_findings(results_dir)
        
        print(f"[+] Identifying attack chains...")
        chains = self.identify_chains(findings)
        
        # Use AI for deeper analysis
        ai_chains = self.use_ai_for_chain_analysis(findings)
        chains.extend(ai_chains)
        
        # Save chains
        output_file = f"{self.output_dir}/attack_chains.json"
        with open(output_file, "w") as f:
            json.dump(chains, f, indent=2)
        
        # Save human-readable report
        report_file = f"{self.output_dir}/chains_report.txt"
        with open(report_file, "w") as f:
            f.write("=" * 80 + "\n")
            f.write("ATTACK CHAIN ANALYSIS REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            for i, chain in enumerate(chains, 1):
                f.write(f"\n{'─' * 80}\n")
                f.write(f"Chain #{i}: {chain['chain_name']}\n")
                f.write(f"{'─' * 80}\n")
                f.write(f"Severity: {chain['severity'].upper()}\n")
                f.write(f"Indicators: {', '.join(chain['indicators'])}\n")
                f.write(f"Description: {chain['description']}\n")
                if "remediation" in chain:
                    f.write(f"Remediation: {chain['remediation']}\n")
        
        print(f"[✓] Identified {len(chains)} attack chains")
        return chains

def main(results_dir, output_dir="results/chain"):
    """Main chain correlation function"""
    print(f"\n{'='*80}")
    print(f"🔗 CHAIN CORRELATION ANALYSIS")
    print(f"{'='*80}\n")
    
    correlator = ChainCorrelator(output_dir)
    chains = correlator.correlate(results_dir)
    
    return chains

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <results_dir> [output_dir]")
        sys.exit(1)
    
    results_dir = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "results/chain"
    main(results_dir, output_dir)
