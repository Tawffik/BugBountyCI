#!/usr/bin/env python3
"""
Chain Attack Builder - Phase B.2 (Innovation #3)

Automatically builds attack chains by correlating multiple findings:
- Links related vulnerabilities into exploitable chains
- Calculates cumulative impact
- Generates step-by-step attack scenarios
- Prioritizes chains by exploitability and impact

Example chains:
- IDOR + Race Condition = Account Takeover
- Subdomain Takeover + Admin Panel = Full Control
- Info Disclosure + Hardcoded Secrets = Source Code Access
- SSRF + Internal Service = RCE
"""
import sys, os, json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))
from base import Finding, ResultWriter

class ChainAttackBuilder:
    """Build attack chains from correlated findings"""
    
    # Predefined attack chain patterns
    CHAIN_PATTERNS = {
        "account_takeover": {
            "required_findings": ["idor", "race_condition", "auth_bypass"],
            "min_required": 2,
            "impact": "critical",
            "description": "Multiple vulnerabilities combine to enable account takeover",
            "attack_steps": [
                "1. Use IDOR to access target user's data",
                "2. Exploit race condition to bypass security checks",
                "3. Modify account credentials or email",
                "4. Take over target account"
            ]
        },
        "subdomain_takeover_chain": {
            "required_findings": ["subdomain_takeover", "admin_panel", "info_disclosure"],
            "min_required": 2,
            "impact": "critical",
            "description": "Subdomain takeover combined with admin access",
            "attack_steps": [
                "1. Take over vulnerable subdomain",
                "2. Deploy malicious content or redirect traffic",
                "3. Access admin panels if present",
                "4. Extract sensitive information"
            ]
        },
        "rce_chain": {
            "required_findings": ["ssrf", "file_upload", "command_injection"],
            "min_required": 2,
            "impact": "critical",
            "description": "Server-side vulnerabilities combine for RCE",
            "attack_steps": [
                "1. Use SSRF to access internal services",
                "2. Upload malicious file or payload",
                "3. Trigger command injection",
                "4. Achieve remote code execution"
            ]
        },
        "data_breach": {
            "required_findings": ["info_disclosure", "api_key_leak", "s3_bucket"],
            "min_required": 2,
            "impact": "high",
            "description": "Information disclosure leads to data breach",
            "attack_steps": [
                "1. Discover exposed information",
                "2. Extract API keys or credentials",
                "3. Access protected resources",
                "4. Exfiltrate sensitive data"
            ]
        },
        "privilege_escalation": {
            "required_findings": ["idor", "privilege_escalation", "auth_bypass"],
            "min_required": 2,
            "impact": "high",
            "description": "Escalate privileges through chained vulnerabilities",
            "attack_steps": [
                "1. Use IDOR to access higher-privileged resources",
                "2. Exploit privilege escalation vulnerability",
                "3. Bypass authentication checks",
                "4. Gain elevated access"
            ]
        }
    }
    
    def __init__(self, target, results_dir="results", output_dir="results/chains"):
        self.target = target
        self.results_dir = results_dir
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        self.writer = ResultWriter(output_dir, "chain_attacks")
        self.all_findings = []
        self.chains = []
    
    def load_findings(self):
        """Load all findings from previous modules"""
        print(f"[+] Loading findings from {self.results_dir}")
        
        finding_files = [
            f"{self.results_dir}/attack_surface/attack_surface.json",
            f"{self.results_dir}/source_recon/source_recon_results.json",
            f"{self.results_dir}/secret_hunter/secrets.json",
            f"{self.results_dir}/business_logic/business_logic_analysis.json"
        ]
        
        for file_path in finding_files:
            if os.path.exists(file_path):
                try:
                    with open(file_path) as f:
                        data = json.load(f)
                        findings = data.get("findings", [])
                        self.all_findings.extend(findings)
                        print(f"    Loaded {len(findings)} findings from {os.path.basename(file_path)}")
                except Exception as e:
                    print(f"    [!] Error loading {file_path}: {e}")
        
        print(f"    Total findings loaded: {len(self.all_findings)}")
    
    def categorize_findings(self) -> Dict[str, List]:
        """Categorize findings by type"""
        categories = defaultdict(list)
        
        for finding in self.all_findings:
            category = finding.get("category", "unknown")
            categories[category].append(finding)
            
            # Also categorize by keywords in title/description
            title = finding.get("title", "").lower()
            desc = finding.get("description", "").lower()
            combined = title + " " + desc
            
            if "idor" in combined:
                categories["idor"].append(finding)
            if "race" in combined or "concurrent" in combined:
                categories["race_condition"].append(finding)
            if "auth" in combined or "bypass" in combined:
                categories["auth_bypass"].append(finding)
            if "subdomain" in combined and "takeover" in combined:
                categories["subdomain_takeover"].append(finding)
            if "admin" in combined:
                categories["admin_panel"].append(finding)
            if "ssrf" in combined:
                categories["ssrf"].append(finding)
            if "upload" in combined:
                categories["file_upload"].append(finding)
            if "injection" in combined or "rce" in combined:
                categories["command_injection"].append(finding)
            if "disclosure" in combined or "exposure" in combined:
                categories["info_disclosure"].append(finding)
            if "api" in combined and ("key" in combined or "secret" in combined):
                categories["api_key_leak"].append(finding)
            if "s3" in combined or "bucket" in combined:
                categories["s3_bucket"].append(finding)
            if "privilege" in combined or "escalation" in combined:
                categories["privilege_escalation"].append(finding)
        
        return categories
    
    def build_chains(self, categories: Dict[str, List]) -> List[Dict]:
        """Build attack chains from categorized findings"""
        print(f"[+] Building attack chains from {len(categories)} categories")
        
        chains = []
        
        for chain_name, pattern in self.CHAIN_PATTERNS.items():
            required = pattern["required_findings"]
            min_required = pattern["min_required"]
            
            # Check if we have enough findings
            available_categories = [cat for cat in required if cat in categories and categories[cat]]
            
            if len(available_categories) >= min_required:
                # Build chain
                chain = {
                    "name": chain_name,
                    "impact": pattern["impact"],
                    "description": pattern["description"],
                    "attack_steps": pattern["attack_steps"],
                    "findings": [],
                    "exploitability": 0.0
                }
                
                # Collect findings for this chain
                for category in available_categories:
                    chain["findings"].extend(categories[category][:3])  # Limit to 3 per category
                
                # Calculate exploitability score
                chain["exploitability"] = self._calculate_exploitability(chain)
                
                chains.append(chain)
                
                # Create finding for this chain
                severity = "critical" if pattern["impact"] == "critical" else "high"
                
                finding = Finding(
                    title=f"Attack chain: {chain_name.replace('_', ' ').title()}",
                    severity=severity,
                    category="attack_chain",
                    target=self.target,
                    description=pattern["description"],
                    evidence=f"Chain involves {len(chain['findings'])} findings across {len(available_categories)} categories",
                    impact=pattern["description"],
                    remediation="Fix individual vulnerabilities in the chain. Implement defense-in-depth.",
                    confidence="high",
                    source="chain_builder",
                    metadata={
                        "chain_name": chain_name,
                        "exploitability": chain["exploitability"],
                        "finding_count": len(chain["findings"]),
                        "categories": available_categories
                    }
                )
                self.writer.add_finding(finding)
        
        return chains
    
    def _calculate_exploitability(self, chain: Dict) -> float:
        """Calculate exploitability score for a chain"""
        score = 0.0
        
        # Base score from number of findings
        score += min(len(chain["findings"]) * 0.1, 0.5)
        
        # Bonus for high-severity findings
        high_severity = sum(1 for f in chain["findings"] if f.get("severity") in ["critical", "high"])
        score += high_severity * 0.1
        
        # Bonus for common vulnerability types
        common_types = ["idor", "ssrf", "auth_bypass", "race_condition"]
        for finding in chain["findings"]:
            category = finding.get("category", "")
            if any(ct in category for ct in common_types):
                score += 0.05
        
        return min(score, 1.0)
    
    def generate_attack_scenarios(self, chains: List[Dict]):
        """Generate detailed attack scenarios for each chain"""
        print(f"[+] Generating attack scenarios for {len(chains)} chains")
        
        for i, chain in enumerate(chains, 1):
            print(f"    Chain {i}: {chain['name']}")
            print(f"      Impact: {chain['impact']}")
            print(f"      Exploitability: {chain['exploitability']:.2f}")
            print(f"      Findings: {len(chain['findings'])}")
            
            # Save detailed scenario
            scenario_file = f"{self.output_dir}/chain_{i}_{chain['name']}.json"
            
            scenario = {
                "chain_name": chain["name"],
                "impact": chain["impact"],
                "exploitability": chain["exploitability"],
                "description": chain["description"],
                "attack_steps": chain["attack_steps"],
                "findings": chain["findings"],
                "tools_required": self._identify_required_tools(chain),
                "estimated_time": self._estimate_attack_time(chain)
            }
            
            with open(scenario_file, "w") as f:
                json.dump(scenario, f, indent=2)
    
    def _identify_required_tools(self, chain: Dict) -> List[str]:
        """Identify tools needed to execute the chain"""
        tools = set()
        
        categories = [f.get("category", "") for f in chain["findings"]]
        
        if any("idor" in c for c in categories):
            tools.update(["burp_suite", "proxy", "http_client"])
        if any("ssrf" in c for c in categories):
            tools.update(["curl", "burp_suite", "collaborator"])
        if any("race" in c for c in categories):
            tools.update(["turbo_intruder", "parallel_requests"])
        if any("injection" in c for c in categories):
            tools.update(["sqlmap", "burp_suite"])
        if any("subdomain" in c for c in categories):
            tools.update(["subfinder", "dig", "whois"])
        
        return sorted(tools)
    
    def _estimate_attack_time(self, chain: Dict) -> str:
        """Estimate time to execute the chain"""
        finding_count = len(chain["findings"])
        exploitability = chain["exploitability"]
        
        if exploitability > 0.8:
            return "15-30 minutes"
        elif exploitability > 0.6:
            return "1-2 hours"
        elif exploitability > 0.4:
            return "2-4 hours"
        else:
            return "4+ hours"
    
    def save_results(self):
        """Save all chains"""
        output_file = f"{self.output_dir}/attack_chains.json"
        
        output = {
            "target": self.target,
            "analyzed_at": datetime.utcnow().isoformat(),
            "statistics": {
                "total_chains": len(self.chains),
                "critical_chains": sum(1 for c in self.chains if c["impact"] == "critical"),
                "high_chains": sum(1 for c in self.chains if c["impact"] == "high"),
                "total_findings": len(self.all_findings)
            },
            "chains": self.chains
        }
        
        with open(output_file, "w") as f:
            json.dump(output, f, indent=2)
        
        print(f"[+] Attack chains saved to {output_file}")
    
    def run(self):
        """Execute full chain building"""
        print(f"\n{'='*80}")
        print(f"CHAIN ATTACK BUILDER - Automated Attack Chain Generation")
        print(f"Target: {self.target}")
        print(f"{'='*80}\n")
        
        # Load findings
        self.load_findings()
        
        # Categorize
        categories = self.categorize_findings()
        
        # Build chains
        self.chains = self.build_chains(categories)
        
        # Generate scenarios
        self.generate_attack_scenarios(self.chains)
        
        # Save
        self.writer.save()
        self.save_results()
        
        print(f"\n{'='*80}")
        print(f"Chain Building Complete")
        print(f"   Total chains: {len(self.chains)}")
        print(f"   Critical: {sum(1 for c in self.chains if c['impact'] == 'critical')}")
        print(f"   High: {sum(1 for c in self.chains if c['impact'] == 'high')}")
        print(f"{'='*80}\n")
        
        return self.chains

def main(target, results_dir="results", output_dir="results/chains"):
    builder = ChainAttackBuilder(target, results_dir, output_dir)
    return builder.run()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target> [results_dir]")
        sys.exit(1)
    
    target = sys.argv[1]
    results_dir = sys.argv[2] if len(sys.argv) > 2 else "results"
    
    main(target, results_dir)
