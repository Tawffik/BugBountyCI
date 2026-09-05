#!/usr/bin/env python3
"""Business Logic Analysis - Phase B.1"""
import sys, os, json, re
from pathlib import Path
from datetime import datetime
sys.path.insert(0, str(Path(__file__).parent.parent))
from base import Finding, ResultWriter

class BusinessLogicAnalyzer:
    def __init__(self, target, output_dir="results/business_logic"):
        self.target = target
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        self.writer = ResultWriter(output_dir, "business_logic")
    
    def analyze_endpoint(self, url, params=None):
        vulns = []
        params = params or {}
        
        payment_keywords = ["price", "amount", "total", "cost", "fee"]
        auth_keywords = ["password", "token", "session", "auth"]
        
        for param in params.keys():
            param_lower = param.lower()
            if any(kw in param_lower for kw in payment_keywords):
                vulns.append({"type": "payment_manipulation", "param": param, "severity": "high"})
            if any(kw in param_lower for kw in auth_keywords):
                vulns.append({"type": "auth_bypass", "param": param, "severity": "critical"})
        
        return vulns
    
    def run(self, endpoints=None):
        print(f"Business Logic Analysis: {self.target}")
        
        if endpoints:
            for ep in endpoints[:50]:
                vulns = self.analyze_endpoint(ep.get("url"), ep.get("parameters", {}))
                for vuln in vulns:
                    finding = Finding(
                        title=f"Business logic flaw: {vuln['type']}",
                        severity=vuln["severity"],
                        category="business_logic",
                        target=ep.get("url"),
                        description=f"Parameter {vuln['param']} may be vulnerable",
                        confidence="medium",
                        source="business_logic"
                    )
                    self.writer.add_finding(finding)
        
        self.writer.save()
        return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target>")
        sys.exit(1)
    analyzer = BusinessLogicAnalyzer(sys.argv[1])
    analyzer.run()
