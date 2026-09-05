#!/usr/bin/env python3
"""Continuous Monitoring - Phase C.2"""
import sys, os, json
from pathlib import Path
from datetime import datetime
sys.path.insert(0, str(Path(__file__).parent.parent))
from base import Finding, ResultWriter

class ContinuousMonitor:
    def __init__(self, target, output_dir="results/monitor"):
        self.target = target
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        self.writer = ResultWriter(output_dir, "monitor")
        self.changes = []
    
    def detect_changes(self, old_data, new_data):
        old_subs = set(old_data.get("subdomains", []))
        new_subs = set(new_data.get("subdomains", []))
        added = new_subs - old_subs
        
        for sub in list(added)[:10]:
            finding = Finding(
                title=f"New subdomain: {sub}",
                severity="info",
                category="monitoring",
                target=sub,
                description="New subdomain discovered",
                confidence="high",
                source="monitor"
            )
            self.writer.add_finding(finding)
        
        return len(added)
    
    def run(self, old_data=None, new_data=None):
        print(f"Continuous Monitoring: {self.target}")
        if old_data and new_data:
            changes = self.detect_changes(old_data, new_data)
            print(f"Detected {changes} changes")
        self.writer.save()
        return self.changes

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    ContinuousMonitor(sys.argv[1]).run()
