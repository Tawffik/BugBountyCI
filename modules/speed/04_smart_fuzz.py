#!/usr/bin/env python3
"""Smart Fuzzing - Phase C.4"""
import sys, os, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from base import Finding, ResultWriter

class SmartFuzzer:
    def __init__(self, target, output_dir="results/fuzz"):
        self.target = target
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        self.writer = ResultWriter(output_dir, "smart_fuzz")
    
    def fuzz_graphql(self, url):
        try:
            import requests
            query = '{"query": "{ __schema { types { name } } }"}'
            r = requests.post(url, data=query, headers={"Content-Type": "application/json"}, timeout=10)
            if r.status_code == 200:
                finding = Finding(
                    title=f"GraphQL introspection: {url}",
                    severity="high",
                    category="graphql",
                    target=url,
                    description="GraphQL introspection enabled",
                    confidence="high",
                    source="smart_fuzz"
                )
                self.writer.add_finding(finding)
        except:
            pass
    
    def run(self, urls=None):
        print(f"Smart Fuzzing: {self.target}")
        if urls:
            for url in urls[:10]:
                self.fuzz_graphql(url)
        self.writer.save()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    SmartFuzzer(sys.argv[1]).run()
