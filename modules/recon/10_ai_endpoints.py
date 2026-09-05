#!/usr/bin/env python3
"""
AI-Powered Endpoint Discovery - Phase A.5
Uses LLMs with multi-provider fallback (Groq, Gemini, OpenRouter, Anthropic)
"""
import sys
import os
import json
import re
from pathlib import Path
from typing import Dict, List, Set, Optional
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))
from base import Finding, ResultWriter
from ai_provider import ai


class AIEndpointDiscovery:
    """AI-powered endpoint discovery using LLMs"""
    
    def __init__(self, target: str, output_dir: str = "results/ai_endpoints"):
        self.target = target
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        self.writer = ResultWriter(output_dir, "ai_endpoints")
        self.discovered_endpoints = []
        self.js_analyses = {}
    
    def analyze_javascript(self, js_content: str, url: str) -> Dict:
        """Deep JavaScript analysis using LLM"""
        analysis = {
            "url": url,
            "endpoints": [],
            "parameters": [],
            "secrets": [],
            "patterns": [],
            "technologies": []
        }
        
        system_prompt = """You are an expert bug bounty hunter analyzing JavaScript code.
Extract ALL potentially interesting information:
1. API endpoints (absolute and relative URLs)
2. Parameters and their expected values
3. Hardcoded secrets (API keys, tokens, passwords)
4. Authentication flows and tokens
5. Internal URLs and admin panels
6. GraphQL queries and mutations
7. WebSocket endpoints
8. Interesting patterns (debug flags, feature flags)

Return JSON:
{
  "endpoints": ["endpoint1", "endpoint2"],
  "parameters": [{"name": "param1", "context": "where it appears"}],
  "secrets": [{"type": "api_key", "value": "...", "context": "where found"}],
  "patterns": ["pattern1", "pattern2"],
  "technologies": ["tech1", "tech2"]
}
Focus on finding HIDDEN and NON-OBVIOUS endpoints."""
        
        # Truncate if too large
        content = js_content[:15000] if len(js_content) > 15000 else js_content
        
        prompt = "Analyze this JavaScript code from " + url + ":

```javascript
" + content + "
```

Extract all endpoints, parameters, secrets, and interesting patterns.
Return JSON only."
        
        result = ai.call_json(prompt, system_prompt)
        
        if result:
            analysis["endpoints"] = result.get("endpoints", [])
            analysis["parameters"] = result.get("parameters", [])
            analysis["secrets"] = result.get("secrets", [])
            analysis["patterns"] = result.get("patterns", [])
            analysis["technologies"] = result.get("technologies", [])
        else:
            # Fallback: extract using regex
            analysis["endpoints"] = self._extract_endpoints_regex(js_content)
        
        return analysis
    
    def _extract_endpoints_regex(self, js_content: str) -> List[str]:
        """Fallback: Extract endpoints using regex"""
        patterns = [
            r'["']([^"']*(?:api|endpoint|fetch|ajax)[^"']*)["']',
            r'fetch\(["']([^"']+)["']',
            r'axios\.[a-z]+\(["']([^"']+)["']',
            r'url["']\s*[:=]\s*["']([^"']+)["']',
            r'endpoint["']\s*[:=]\s*["']([^"']+)["']'
        ]
        
        endpoints = []
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            endpoints.extend(matches)
        
        return list(set(endpoints))
    
    def discover_graphql_endpoints(self, urls: List[str]) -> List[Dict]:
        """Discover GraphQL endpoints"""
        graphql_endpoints = []
        paths = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"]
        
        for url in urls[:20]:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            for path in paths:
                full_url = f"{base_url}{path}"
                
                try:
                    import requests
                    response = requests.post(
                        full_url,
                        json={"query": "{ __typename }"},
                        headers={"Content-Type": "application/json"},
                        timeout=10
                    )
                    
                    if response.status_code in [200, 400]:
                        try:
                            data = response.json()
                            if "data" in data or "errors" in data:
                                graphql_endpoints.append({
                                    "url": full_url,
                                    "introspection": self._test_introspection(full_url)
                                })
                        except:
                            pass
                except:
                    pass
        
        return graphql_endpoints
    
    def _test_introspection(self, url: str) -> bool:
        """Test if GraphQL introspection is enabled"""
        try:
            import requests
            query = "{ __schema { types { name } } }"
            response = requests.post(
                url,
                json={"query": query},
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                return "data" in data and "__schema" in data.get("data", {})
        except:
            pass
        return False
    
    def generate_findings(self):
        """Generate findings from discovered endpoints"""
        high_value_patterns = ["admin", "internal", "debug", "test", "api/v1", "graphql"]
        
        for endpoint in self.discovered_endpoints:
            url = endpoint.get("url", "")
            endpoint_type = endpoint.get("type", "unknown")
            
            for pattern in high_value_patterns:
                if pattern in url.lower():
                    finding = Finding(
                        title=f"AI-discovered high-value endpoint: {url}",
                        severity="medium",
                        category="ai_endpoint",
                        target=url,
                        description=f"Endpoint discovered through AI analysis: {endpoint_type}",
                        confidence="high",
                        source="ai_endpoints",
                        metadata=endpoint
                    )
                    self.writer.add_finding(finding)
                    break
    
    def save_results(self):
        """Save all results"""
        output_file = f"{self.output_dir}/ai_discovery.json"
        
        output = {
            "target": self.target,
            "analyzed_at": datetime.utcnow().isoformat(),
            "statistics": {
                "total_endpoints": len(self.discovered_endpoints),
                "js_files_analyzed": len(self.js_analyses)
            },
            "endpoints": self.discovered_endpoints,
            "js_analyses": self.js_analyses
        }
        
        with open(output_file, "w") as f:
            json.dump(output, f, indent=2)
        
        print(f"[+] AI discovery results saved to {output_file}")
    
    def run(self, js_files: List[str] = None, urls: List[str] = None) -> Dict:
        """Execute AI endpoint discovery"""
        print(f"
{'='*80}")
        print(f"AI-POWERED ENDPOINT DISCOVERY")
        print(f"Target: {self.target}")
        print(f"{'='*80}
")
        
        print(f"[+] {ai.status_report()}")
        
        # Analyze JavaScript files
        if js_files:
            print(f"[+] Analyzing {len(js_files)} JavaScript files with LLM")
            for i, js_url in enumerate(js_files[:30], 1):
                print(f"    Progress: {i}/{min(len(js_files), 30)}")
                
                try:
                    import requests
                    response = requests.get(js_url, timeout=15)
                    if response.status_code == 200:
                        analysis = self.analyze_javascript(response.text, js_url)
                        self.js_analyses[js_url] = analysis
                        
                        # Add discovered endpoints
                        for endpoint in analysis.get("endpoints", []):
                            self.discovered_endpoints.append({
                                "url": endpoint,
                                "type": "js_discovered",
                                "source": js_url
                            })
                except:
                    pass
        
        # Discover GraphQL endpoints
        if urls:
            print(f"[+] Discovering GraphQL endpoints")
            graphql = self.discover_graphql_endpoints(urls)
            self.discovered_endpoints.extend(graphql)
        
        # Generate findings
        self.generate_findings()
        self.writer.save()
        self.save_results()
        
        print(f"
{'='*80}")
        print(f"AI Endpoint Discovery Complete")
        print(f"   Total endpoints discovered: {len(self.discovered_endpoints)}")
        print(f"{'='*80}
")
        
        return self.discovered_endpoints


def main(target: str, js_files: List[str] = None, urls: List[str] = None, output_dir: str = "results/ai_endpoints"):
    discovery = AIEndpointDiscovery(target, output_dir)
    return discovery.run(js_files, urls)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target> [js_files_list] [urls_list]")
        sys.exit(1)
    
    target = sys.argv[1]
    js_files = []
    urls = []
    
    if len(sys.argv) > 2:
        try:
            with open(sys.argv[2]) as f:
                js_files = [line.strip() for line in f if line.strip()]
        except:
            pass
    
    if len(sys.argv) > 3:
        try:
            with open(sys.argv[3]) as f:
                urls = [line.strip() for line in f if line.strip()]
        except:
            pass
    
    main(target, js_files, urls)
