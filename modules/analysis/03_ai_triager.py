#!/usr/bin/env python3
"""
AI Triager - Phase B.3 (Innovation #4)

Uses AI to intelligently triage findings:
- Distinguish true positives from false positives
- Re-rank findings by actual impact
- Suggest PoCs

Uses multi-provider AI with automatic fallback.
"""

import sys
import os
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).parent.parent))
from base import Finding, ResultWriter
from ai_provider import ai


class AITriager:
    """AI-powered finding triage and validation"""
    
    def __init__(self, target, output_dir="results/triage"):
        self.target = target
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        self.writer = ResultWriter(output_dir, "ai_triage")
        self.triaged_findings = []
    
    def triage_finding(self, finding: Dict) -> Dict:
        """Triage a single finding using AI"""
        prompt = f"""Analyze this security finding and determine:
1. Is this a TRUE POSITIVE or FALSE POSITIVE?
2. What is the ACTUAL severity (critical/high/medium/low/info)?
3. How CONFIDENT are you (high/medium/low)?
4. What is the ACTUAL impact?
5. Suggest a brief PoC if true positive.

Finding:
- Title: {finding.get("title", "N/A")}
- Category: {finding.get("category", "N/A")}
- Target: {finding.get("target", "N/A")}
- Description: {finding.get("description", "N/A")}
- Evidence: {finding.get("evidence", "N/A")}
- Original severity: {finding.get("severity", "N/A")}

Return JSON:
{{
  "is_true_positive": true/false,
  "actual_severity": "critical/high/medium/low/info",
  "confidence": "high/medium/low",
  "actual_impact": "description of impact",
  "poc_suggestion": "brief PoC if true positive",
  "reasoning": "why you made this decision",
  "false_positive_reason": "why it's FP if applicable"
}}
"""
        
        system_prompt = "You are an expert bug bounty hunter triaging security findings. Be precise and realistic. Return JSON only."
        
        triage = ai.call_json(prompt, system_prompt)
        
        if triage:
            return triage
        
        # Fallback: keep original assessment
        return {
            "is_true_positive": True,
            "actual_severity": finding.get("severity", "medium"),
            "confidence": "low",
            "actual_impact": finding.get("impact", "Unknown"),
            "reasoning": "AI triage unavailable, using original assessment"
        }
    
    def load_findings(self) -> List[Dict]:
        """Load all findings from previous modules"""
        findings = []
        
        finding_files = [
            "results/attack_surface/attack_surface.json",
            "results/source_recon/source_recon_results.json",
            "results/secret_hunter/secrets.json",
            "results/business_logic/business_logic_analysis.json",
            "results/chains/attack_chains.json",
            "results/scan/nuclei_results.json"
        ]
        
        for file_path in finding_files:
            if os.path.exists(file_path):
                try:
                    with open(file_path) as f:
                        content = f.read()
                        # Try JSON lines format first
                        for line in content.splitlines():
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                data = json.loads(line)
                                if isinstance(data, dict):
                                    findings.append(data)
                            except json.JSONDecodeError:
                                pass
                        
                        # Try regular JSON format
                        if not findings:
                            try:
                                data = json.loads(content)
                                if isinstance(data, dict):
                                    file_findings = data.get("findings", [])
                                    findings.extend(file_findings)
                            except json.JSONDecodeError:
                                pass
                        
                        print(f"    Loaded {len(findings)} findings from {os.path.basename(file_path)}")
                except Exception as e:
                    print(f"    [!] Error loading {file_path}: {e}")
        
        return findings
    
    def triage_all_findings(self, findings: List[Dict]):
        """Triage all findings"""
        print(f"[+] Triaging {len(findings)} findings with AI")
        print(f"[+] {ai.status_report()}")
        
        for i, finding in enumerate(findings[:50], 1):  # Limit to 50 for cost
            if i % 10 == 0:
                print(f"    Progress: {i}/{min(len(findings), 50)}")
            
            triage = self.triage_finding(finding)
            
            # Create triaged finding
            triaged = {
                "original": finding,
                "triage": triage,
                "final_severity": triage.get("actual_severity", finding.get("severity")),
                "is_true_positive": triage.get("is_true_positive", True),
                "confidence": triage.get("confidence", "low")
            }
            
            self.triaged_findings.append(triaged)
            
            # Create finding for report
            if triaged["is_true_positive"]:
                validated_finding = Finding(
                    title=f"[VALIDATED] {finding.get('title', 'Unknown')}",
                    severity=triaged["final_severity"],
                    category=finding.get("category", "unknown"),
                    target=finding.get("target", "unknown"),
                    description=triage.get("actual_impact", finding.get("description", "")),
                    evidence=triage.get("reasoning", ""),
                    remediation=triage.get("poc_suggestion", "See original finding"),
                    confidence=triaged["confidence"],
                    source="ai_triager",
                    metadata={
                        "original_finding": finding,
                        "ai_triage": triage,
                        "validated": True,
                        "ai_provider": ai.last_successful_provider
                    }
                )
                self.writer.add_finding(validated_finding)
    
    def generate_triage_report(self):
        """Generate triage summary report"""
        report = {
            "target": self.target,
            "triaged_at": datetime.utcnow().isoformat(),
            "statistics": {
                "total_findings": len(self.triaged_findings),
                "true_positives": sum(1 for t in self.triaged_findings if t["is_true_positive"]),
                "false_positives": sum(1 for t in self.triaged_findings if not t["is_true_positive"]),
                "by_severity": {},
                "by_confidence": {}
            },
            "ai_provider_used": ai.last_successful_provider,
            "triaged_findings": self.triaged_findings
        }
        
        # Count by severity
        for triaged in self.triaged_findings:
            severity = triaged["final_severity"]
            report["statistics"]["by_severity"][severity] = report["statistics"]["by_severity"].get(severity, 0) + 1
            
            confidence = triaged["confidence"]
            report["statistics"]["by_confidence"][confidence] = report["statistics"]["by_confidence"].get(confidence, 0) + 1
        
        # Save report
        report_file = f"{self.output_dir}/triage_report.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Triage report saved to {report_file}")
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"TRIAGE SUMMARY")
        print(f"{'='*60}")
        print(f"Total findings: {report['statistics']['total_findings']}")
        print(f"True positives: {report['statistics']['true_positives']}")
        print(f"False positives: {report['statistics']['false_positives']}")
        print(f"AI provider used: {ai.last_successful_provider or 'None'}")
        print(f"\nBy severity:")
        for severity, count in sorted(report["statistics"]["by_severity"].items()):
            print(f"  {severity}: {count}")
        print(f"{'='*60}\n")
    
    def run(self):
        """Execute full AI triage"""
        print(f"\n{'='*80}")
        print(f"AI TRIAGER - Intelligent Finding Triage")
        print(f"Target: {self.target}")
        print(f"{'='*80}\n")
        
        # Load findings
        findings = self.load_findings()
        
        # Triage
        self.triage_all_findings(findings)
        
        # Generate report
        self.generate_triage_report()
        
        # Save validated findings
        self.writer.save()
        
        print(f"\n{'='*80}")
        print(f"AI Triage Complete")
        print(f"   Findings triaged: {len(self.triaged_findings)}")
        print(f"   True positives: {sum(1 for t in self.triaged_findings if t['is_true_positive'])}")
        print(f"{'='*80}\n")
        
        return self.triaged_findings


def main(target, output_dir="results/triage"):
    triager = AITriager(target, output_dir)
    return triager.run()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target>")
        sys.exit(1)
    
    main(sys.argv[1])