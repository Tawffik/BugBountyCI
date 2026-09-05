#!/usr/bin/env python3
"""
📊 Professional Report Generator Module
Generates comprehensive bug bounty reports with:
- Executive summary
- Detailed findings
- Attack chains
- Remediation recommendations
- Export formats: JSON, HTML, PDF
"""
import json
import os
import sys
from pathlib import Path
from datetime import datetime

class ReportGenerator:
    def __init__(self, results_dir, output_dir="reports"):
        self.results_dir = results_dir
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    def collect_all_findings(self):
        """Collect all findings from different modules"""
        findings = {
            "metadata": {
                "scan_date": datetime.now().isoformat(),
                "results_dir": self.results_dir
            },
            "recon": {},
            "scan": {},
            "chains": [],
            "statistics": {}
        }
        
        # Load subdomain data
        subdomain_file = f"{self.results_dir}/recon/all_subs.txt"
        if os.path.exists(subdomain_file):
            with open(subdomain_file) as f:
                findings["recon"]["subdomains"] = [line.strip() for line in f if line.strip()]
        
        # Load live hosts
        live_file = f"{self.results_dir}/recon/live.txt"
        if os.path.exists(live_file):
            with open(live_file) as f:
                findings["recon"]["live_hosts"] = [line.strip() for line in f if line.strip()]
        
        # Load nuclei findings
        nuclei_file = f"{self.results_dir}/scan/nuclei_results.json"
        if os.path.exists(nuclei_file):
            findings["scan"]["nuclei"] = []
            with open(nuclei_file) as f:
                for line in f:
                    try:
                        findings["scan"]["nuclei"].append(json.loads(line))
                    except:
                        pass
        
        # Load ghost layer findings
        ghost_file = f"{self.results_dir}/ghost/ghost_endpoints.txt"
        if os.path.exists(ghost_file):
            with open(ghost_file) as f:
                findings["recon"]["ghost_endpoints"] = [line.strip() for line in f if line.strip()]
        
        # Load attack chains
        chains_file = f"{self.results_dir}/chain/attack_chains.json"
        if os.path.exists(chains_file):
            with open(chains_file) as f:
                findings["chains"] = json.load(f)
        
        # Calculate statistics
        findings["statistics"] = {
            "total_subdomains": len(findings["recon"].get("subdomains", [])),
            "live_hosts": len(findings["recon"].get("live_hosts", [])),
            "total_vulnerabilities": len(findings["scan"].get("nuclei", [])),
            "ghost_endpoints": len(findings["recon"].get("ghost_endpoints", [])),
            "attack_chains": len(findings["chains"])
        }
        
        return findings
    
    def generate_executive_summary(self, findings):
        """Generate executive summary"""
        stats = findings["statistics"]
        
        summary = f"""
EXECUTIVE SUMMARY
{'='*80}

Scan Date: {findings['metadata']['scan_date']}
Target: {findings['metadata'].get('target', 'N/A')}

Key Metrics:
- Total Subdomains Discovered: {stats['total_subdomains']}
- Live Hosts Identified: {stats['live_hosts']}
- Vulnerabilities Found: {stats['total_vulnerabilities']}
- Ghost Endpoints (Historical): {stats['ghost_endpoints']}
- Attack Chains Identified: {stats['attack_chains']}

Critical Findings:
"""
        
        # Count by severity
        severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in findings["scan"].get("nuclei", []):
            severity = finding.get("info", {}).get("severity", "unknown").lower()
            if severity in severity_count:
                severity_count[severity] += 1
        
        for severity, count in severity_count.items():
            if count > 0:
                summary += f"- {severity.upper()}: {count} findings\n"
        
        if findings["chains"]:
            summary += f"\nAttack Chains:\n"
            for chain in findings["chains"][:3]:  # Top 3
                summary += f"- {chain['severity'].upper()}: {chain['chain_name']} - {chain['description']}\n"
        
        return summary
    
    def generate_json_report(self, findings):
        """Generate JSON report"""
        output_file = f"{self.output_dir}/report.json"
        with open(output_file, "w") as f:
            json.dump(findings, f, indent=2)
        print(f"[✓] JSON report saved: {output_file}")
        return output_file
    
    def generate_text_report(self, findings):
        """Generate detailed text report"""
        output_file = f"{self.output_dir}/report.txt"
        
        with open(output_file, "w") as f:
            # Executive summary
            f.write(self.generate_executive_summary(findings))
            f.write("\n" + "="*80 + "\n\n")
            
            # Detailed findings
            f.write("DETAILED FINDINGS\n")
            f.write("="*80 + "\n\n")
            
            # Nuclei findings
            if findings["scan"].get("nuclei"):
                f.write("VULNERABILITY FINDINGS\n")
                f.write("-"*80 + "\n\n")
                for i, finding in enumerate(findings["scan"]["nuclei"], 1):
                    f.write(f"Finding #{i}\n")
                    f.write(f"Template: {finding.get('template-id', 'N/A')}\n")
                    f.write(f"URL: {finding.get('matched-at', 'N/A')}\n")
                    f.write(f"Severity: {finding.get('info', {}).get('severity', 'N/A')}\n")
                    f.write(f"Description: {finding.get('info', {}).get('description', 'N/A')}\n")
                    f.write("-"*80 + "\n\n")
            
            # Ghost endpoints
            if findings["recon"].get("ghost_endpoints"):
                f.write("\nGHOST ENDPOINTS (Historical URLs)\n")
                f.write("-"*80 + "\n\n")
                for endpoint in findings["recon"]["ghost_endpoints"]:
                    f.write(f"- {endpoint}\n")
            
            # Attack chains
            if findings["chains"]:
                f.write("\n\nATTACK CHAINS\n")
                f.write("-"*80 + "\n\n")
                for i, chain in enumerate(findings["chains"], 1):
                    f.write(f"Chain #{i}: {chain['chain_name']}\n")
                    f.write(f"Severity: {chain['severity'].upper()}\n")
                    f.write(f"Description: {chain['description']}\n")
                    if "remediation" in chain:
                        f.write(f"Remediation: {chain['remediation']}\n")
                    f.write("-"*80 + "\n\n")
        
        print(f"[✓] Text report saved: {output_file}")
        return output_file
    
    def generate(self):
        """Generate all report formats"""
        print(f"\n{'='*80}")
        print(f"📊 GENERATING PROFESSIONAL REPORT")
        print(f"{'='*80}\n")
        
        findings = self.collect_all_findings()
        
        json_report = self.generate_json_report(findings)
        text_report = self.generate_text_report(findings)
        
        return {
            "json": json_report,
            "text": text_report,
            "findings": findings
        }

def main(results_dir, output_dir="reports"):
    """Main report generation function"""
    generator = ReportGenerator(results_dir, output_dir)
    return generator.generate()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <results_dir> [output_dir]")
        sys.exit(1)
    
    results_dir = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "reports"
    main(results_dir, output_dir)
