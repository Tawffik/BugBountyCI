#!/usr/bin/env python3
"""
AI-Powered Endpoint Discovery - Phase A.5
Uses LLMs to discover non-traditional endpoints
"""
import sys
import os
import json
import re
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))
from base import Finding, ResultWriter

class AIEndpointDiscovery:
    def __init__(self, target, output_dir="results/ai_endpoints"):
        self.target = target
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        self.writer = ResultWriter(output_dir, "ai_endpoints")
        self.endpoints = []
    
    def call_llm(self, prompt):
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            return ""
        try:
            import requests
            headers = {
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            }
            data = {
                "model": "claude-3-5-sonnet-20241022",
                "max_tokens": 4096,
                "messages": [{"role": "user", "content": prompt}]
            }
            r = requests.post("https://api.anthropic.com/v1/messages", headers=headers, json=data, timeout=60)
            if r.status_code == 200:
                return r.json()["content"][0]["text"]
        except:
            pass
        return ""
    
    def analyze_js(self, js_content, url):
        prompt = f"Extract API endpoints, parameters, and secrets from this JavaScript: {js_content[:8000]}. Return JSON."
        response = self.call_llm(prompt)
        return {"url": url, "response": response}
    
    def discover_graphql(self, urls):
        graphql = []
        paths = ["/graphql", "/api/graphql", "/v1/graphql"]
        try:
            import requests
            for url in urls[:10]:
                parsed = url.split("/")
                base = f"{parsed[0]}//{parsed[2]}" if len(parsed) > 2 else url
                for path in paths:
                    try:
                        r = requests.post(base + path, json={"query": "{ __typename }"}, timeout=10)
                        if r.status_code in [200, 400]:
                            graphql.append({"url": base + path})
                    except:
                        pass
        except:
            pass
        return graphql
    
    def run(self, js_files=None, urls=None):
        print(f"AI Endpoint Discovery: {self.target}")
        
        if js_files:
            print(f"Analyzing {len(js_files)} JS files")
            for js_url in js_files[:20]:
                try:
                    import requests
                    r = requests.get(js_url, timeout=15)
                    if r.status_code == 200:
                        self.analyze_js(r.text, js_url)
                except:
                    pass
        
        if urls:
            print(f"Discovering GraphQL endpoints")
            self.endpoints.extend(self.discover_graphql(urls))
        
        self.writer.save()
        return self.endpoints

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target>")
        sys.exit(1)
    discovery = AIEndpointDiscovery(sys.argv[1])
    discovery.run()
