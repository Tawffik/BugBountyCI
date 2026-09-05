#!/usr/bin/env python3
"""
Scope-Aware Prioritizer - Phase B.4

Prioritizes findings based on:
- Scope validation (in-scope vs out-of-scope)
- Impact assessment
- Exploitability scoring
- Business context
- Remediation effort

Outputs prioritized list ready for bug bounty submission.
"""
import sys, os, json
from pathlib import Path
from datetime import datetime
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).parent.parent))
from base import Finding, ResultWriter, load_config

class ScopeAwarePrioritizer:
    """Prioritize findings based on scope and impact"""
    
    SEVERITY_WEIGHTS = {
        "critical": 100,
        "high": 75,
        "medium": 50,
        "low": 25,
        "info": 10
    }
    
    def __init__(self, target, output_dir="results/prioritized"):
        self.target = target
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        self.writer = ResultWriter(output_dir, "prioritized")
        self.scope_config = load_config("scope") or {}
        self.prioritized = []
    
    def validate_scope(self, finding: Dict) -> bool:
        """Check if finding is in authorized scope"""
        target_url = finding.get("target", "")
        
        # Check against authorized targets
        authorized = self.scope_config.get("authorized_targets", [])
        exclusions = self.scope_config.get("exclusions", [])
        
        # Simple scope check (can be enhanced with regex)
        in_scope = any(auth in target_url for auth in authorized)
        excluded = any(exc in target_url for exc in exclusions)
        
        return in_scope and not excluded
    
    def calculate_priority_score(self, finding: Dict) -> float:
        """Calculate priority score for a finding"""
        score = 0.0
        
        # Severity weight
        severity = finding.get("severity", "info").lower()
        score += self.SEVERITY_WEIGHTS.get(severity, 10)
        
        # Confidence bonus
        confidence = finding.get("confidence", "low")
        if confidence == "high":
            score *= 1.5
        elif confidence == "medium":
            score *= 1.2
        
        # Impact multiplier
        impact = finding.get("impact", "")
        if "account takeover" in impact.lower() or "rce" in impact.lower():
            score *= 2.0
        elif "data breach" in impact.lower() or "unauthorized access" in impact.lower():
            score *= 1.5
        
        # Category bonus
        category = finding.get("category", "")
        if category in ["secret", "business_logic", "attack_chain"]:
            score *= 1.3
        
        return score
    
    def prioritize_findings(self, findings: List[Dict]) -> List[Dict]:
        """Prioritize all findings"""
        print(f"[+] Prioritizing {len(findings)} findings")
        
        prioritized = []
        
        for finding in findings:
            # Validate scope
            in_scope = self.validate_scope(finding)
            
            # Calculate priority
            priority_score = self.calculate_priority_score(finding)
            
            prioritized.append({
                "finding": finding,
                "in_scope": in_scope,
                "priority_score": priority_score,
                "severity": finding.get("severity", "info"),
                "category": finding.get("category", "unknown")
            })
        
        # Sort by priority score (descending)
        prioritized.sort(key=lambda x: x["priority_score"], reverse=True)
        
        return prioritized
    
    def load_findings(self) -> List[Dict]:
        """Load all findings"""
        findings = []
        
        finding_files = [
            "results/triage/triage_report.json",
            "results/chains/attack_chains.json",
            "results/business_logic/business_logic_analysis.json"
        ]
        
        for file_path in finding_files:
            if os.path.exists(file_path):
                try:
                    with open(file_path) as f:
                        data = json.load(f)
                        file_findings = data.get("findings", data.get("triaged_findings", []))
                        
                        # Extract actual findings from triaged data
                        for item in file_findings:
                            if "original" in item:
                                findings.append(item["original"])
                            else:
                                findings.append(item)
                except:
                    pass
        
        return findings
    
    def generate_submission_list(self):
        """Generate bug bounty submission list"""
        print(f"[+] Generating submission list")
        
        # Filter in-scope findings
        in_scope = [p for p in self.prioritized if p["in_scope"]]
        
        submission_list = {
            "target": self.target,
            "generated_at": datetime.utcnow().isoformat(),
            "statistics": {
                "total_findings": len(self.prioritized),
                "in_scope": len(in_scope),
                "out_of_scope": len(self.prioritized) - len(in_scope)
            },
            "priority_ranking": []
        }
        
        # Create ranked list
        for rank, item in enumerate(in_scope[:20], 1):  # Top 20
            finding = item["finding"]
            submission_list["priority_ranking"].append({
                "rank": rank,
                "title": finding.get("title", "Unknown"),
                "severity": item["severity"],
                "category": item["category"],
                "priority_score": item["priority_score"],
                "target": finding.get("target", "Unknown"),
                "description": finding.get("description", "")[:200],
                "remediation": finding.get("remediation", "N/A"),
                "estimated_bounty": self._estimate_bounty(item["severity"])
            })
        
        # Save
        output_file = f"{self.output_dir}/submission_list.json"
        with open(output_file, "w") as f:
            json.dump(submission_list, f, indent=2)
        
        print(f"[+] Submission list saved to {output_file}")
        
        # Print top 10
        print(f"\n{'='*60}")
        print(f"TOP 10 PRIORITIZED FINDINGS")
        print(f"{'='*60}")
        for item in submission_list["priority_ranking"][:10]:
            print(f"\n#{item['rank']}: {item['title']}")
            print(f"   Severity: {item['severity']} | Score: {item['priority_score']:.1f}")
            print(f"   Target: {item['target']}")
            print(f"   Est. Bounty: {item['estimated_bounty']}")
        print(f"{'='*60}\n")
    
    def _estimate_bounty(self, severity: str) -> str:
        """Estimate potential bounty"""
        ranges = {
            "critical": "$5,000 - $50,000",
            "high": "$1,000 - $10,000",
            "medium": "$500 - $5,000",
            "low": "$100 - $1,000",
            "info": "N/A"
        }
        return ranges.get(severity.lower(), "Unknown")
    
    def run(self):
        """Execute prioritization"""
        print(f"\n{'='*80}")
        print(f"SCOPE-AWARE PRIORITIZATION")
        print(f"Target: {self.target}")
        print(f"{'='*80}\n")
        
        # Load findings
        findings = self.load_findings()
        
        # Prioritize
        self.prioritized = self.prioritize_findings(findings)
        
        # Generate submission list
        self.generate_submission_list()
        
        print(f"\n{'='*80}")
        print(f"Prioritization Complete")
        print(f"   Total findings: {len(self.prioritized)}")
        print(f"   In scope: {sum(1 for p in self.prioritized if p['in_scope'])}")
        print(f"{'='*80}\n")
        
        return self.prioritized

def main(target, output_dir="results/prioritized"):
    prioritizer = ScopeAwarePrioritizer(target, output_dir)
    return prioritizer.run()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target>")
        sys.exit(1)
    main(sys.argv[1])
