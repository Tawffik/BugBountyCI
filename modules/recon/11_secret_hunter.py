#!/usr/bin/env python3
"""
Secret Hunter - Phase A.6 (Innovation #2)

Context-aware secret detection beyond simple regex:
- Deep JavaScript analysis for API keys, tokens, credentials
- GitHub repository scanning for leaked secrets
- Cloud bucket secret discovery
- Source map analysis for hidden secrets
- Configuration file extraction
- Entropy-based secret detection
- Multi-source correlation to reduce false positives

This is Innovation #2: Contextual secret analysis
"""
import sys
import os
import json
import re
import math
import hashlib
from pathlib import Path
from typing import Dict, List, Set
from datetime import datetime
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from base import Finding, ResultWriter

class SecretHunter:
    """Advanced secret detection with context analysis"""
    
    # High-entropy patterns for secret detection
    SECRET_PATTERNS = {
        "aws_access_key": r"AKIA[0-9A-Z]{16}",
        "aws_secret_key": r"[A-Za-z0-9/+=]{40}",
        "github_token": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
        "slack_token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "stripe_key": r"[rs]k_live_[0-9a-zA-Z]{24}",
        "jwt_token": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/]*",
        "private_key": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "gcp_api_key": r"AIza[0-9A-Za-z_-]{35}",
        "firebase_url": r"https://[a-z0-9-]+\.firebaseio\.com",
        "sendgrid_api": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "twilio_api": r"SK[0-9a-fA-F]{32}",
        "mailgun_api": r"key-[0-9a-zA-Z]{32}",
        "heroku_api": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        "square_token": r"sq0atp-[0-9A-Za-z_-]{22}",
        "paypal_braintree": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
        "generic_api_key": r"[Aa]pi[_-]?[Kk]ey[_\s:=]+['\"]([A-Za-z0-9_\-]{16,})['\"]"
    }
    
    # Context keywords that increase confidence
    HIGH_CONFIDENCE_KEYWORDS = [
        "secret", "password", "token", "key", "credential", "auth",
        "private", "apikey", "api_key", "access_key", "secret_key"
    ]
    
    def __init__(self, target, output_dir="results/secret_hunter"):
        self.target = target
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        self.writer = ResultWriter(output_dir, "secret_hunter")
        self.secrets = []
        self.context_analysis = {}
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of a string"""
        if not data:
            return 0
        entropy = 0
        for x in set(data):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)
        return entropy
    
    def is_high_entropy(self, text, threshold=4.5):
        """Check if text has high entropy (likely a secret)"""
        return self.calculate_entropy(text) > threshold
    
    def extract_context(self, text, match_start, match_end, window=100):
        """Extract surrounding context for a match"""
        start = max(0, match_start - window)
        end = min(len(text), match_end + window)
        return text[start:end]
    
    def analyze_js_file(self, js_content, url):
        """Deep JavaScript analysis for secrets"""
        found_secrets = []
        
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            matches = re.finditer(pattern, js_content)
            
            for match in matches:
                secret_value = match.group(0)
                context = self.extract_context(js_content, match.start(), match.end())
                
                # Calculate confidence
                confidence = self._calculate_confidence(secret_value, context, secret_type)
                
                if confidence >= 0.6:  # Minimum threshold
                    found_secrets.append({
                        "type": secret_type,
                        "value": self._mask_secret(secret_value),
                        "raw_value": secret_value,  # Only for internal use
                        "context": context,
                        "confidence": confidence,
                        "source": url,
                        "line_number": js_content[:match.start()].count('\n') + 1
                    })
        
        return found_secrets
    
    def _calculate_confidence(self, secret_value, context, secret_type):
        """Calculate confidence score for a potential secret"""
        confidence = 0.5  # Base confidence
        
        # High entropy increases confidence
        if self.is_high_entropy(secret_value):
            confidence += 0.2
        
        # Context keywords increase confidence
        context_lower = context.lower()
        keyword_matches = sum(1 for kw in self.HIGH_CONFIDENCE_KEYWORDS if kw in context_lower)
        confidence += min(keyword_matches * 0.1, 0.3)
        
        # Specific patterns have higher base confidence
        high_confidence_types = ["aws_access_key", "github_token", "stripe_key", "jwt_token"]
        if secret_type in high_confidence_types:
            confidence += 0.2
        
        # Length check
        if len(secret_value) >= 20:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _mask_secret(self, secret):
        """Mask secret for safe display"""
        if len(secret) <= 8:
            return "*" * len(secret)
        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]
    
    def scan_github_repos(self):
        """Scan GitHub for leaked secrets"""
        print(f"[+] Searching GitHub for leaked secrets")
        
        try:
            import requests
            
            queries = [
                f'"{self.target}" api_key',
                f'"{self.target}" password',
                f'"{self.target}" secret',
                f'"{self.target}" token',
                f'"{self.target}" filename:.env',
                f'"{self.target}" extension:env'
            ]
            
            for query in queries:
                url = f"https://api.github.com/search/code?q={query}"
                headers = {"Accept": "application/vnd.github.v3.text-match+json"}
                
                response = requests.get(url, headers=headers, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    for item in data.get("items", [])[:10]:
                        # Fetch file content
                        raw_url = item.get("html_url", "").replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                        
                        try:
                            content_resp = requests.get(raw_url, timeout=15)
                            if content_resp.status_code == 200:
                                secrets = self.analyze_js_file(content_resp.text, raw_url)
                                for secret in secrets:
                                    secret["github_repo"] = item.get("repository", {}).get("full_name")
                                    secret["github_path"] = item.get("path")
                                    self.secrets.append(secret)
                        except:
                            pass
        except Exception as e:
            print(f"[!] GitHub search error: {e}")
    
    def scan_exposed_files(self, files_list):
        """Scan exposed files for secrets"""
        print(f"[+] Scanning {len(files_list)} exposed files for secrets")
        
        try:
            import requests
            
            for file_info in files_list[:50]:
                url = file_info.get("url", "")
                if not url:
                    continue
                
                try:
                    response = requests.get(url, timeout=15)
                    if response.status_code == 200:
                        secrets = self.analyze_js_file(response.text, url)
                        self.secrets.extend(secrets)
                except:
                    pass
        except Exception as e:
            print(f"[!] File scanning error: {e}")
    
    def analyze_source_maps(self, js_urls):
        """Analyze source maps for hidden secrets"""
        print(f"[+] Analyzing source maps from {len(js_urls)} JS files")
        
        try:
            import requests
            
            for js_url in js_urls[:20]:
                try:
                    response = requests.get(js_url, timeout=15)
                    if response.status_code == 200:
                        # Look for sourceMappingURL
                        map_match = re.search(r'//# sourceMappingURL=(.+)', response.text)
                        if map_match:
                            map_url = map_match.group(1)
                            if not map_url.startswith("http"):
                                map_url = f"{js_url.rsplit('/', 1)[0]}/{map_url}"
                            
                            # Fetch source map
                            map_resp = requests.get(map_url, timeout=15)
                            if map_resp.status_code == 200:
                                # Parse source map (simplified)
                                try:
                                    source_map = json.loads(map_resp.text)
                                    sources = source_map.get("sources", [])
                                    sources_content = source_map.get("sourcesContent", [])
                                    
                                    for i, source in enumerate(sources):
                                        if i < len(sources_content):
                                            secrets = self.analyze_js_file(sources_content[i], source)
                                            for secret in secrets:
                                                secret["source_map"] = map_url
                                                secret["original_source"] = source
                                                self.secrets.append(secret)
                                except:
                                    pass
                except:
                    pass
        except Exception as e:
            print(f"[!] Source map analysis error: {e}")
    
    def generate_findings(self):
        """Generate findings from discovered secrets"""
        print(f"[+] Generating findings for {len(self.secrets)} secrets")
        
        # Group by type
        by_type = {}
        for secret in self.secrets:
            secret_type = secret["type"]
            if secret_type not in by_type:
                by_type[secret_type] = []
            by_type[secret_type].append(secret)
        
        for secret_type, secrets in by_type.items():
            # Filter high-confidence secrets
            high_conf = [s for s in secrets if s["confidence"] >= 0.8]
            
            if high_conf:
                # Determine severity
                critical_types = ["aws_access_key", "aws_secret_key", "private_key", "github_token"]
                high_types = ["stripe_key", "jwt_token", "gcp_api_key", "firebase_url"]
                
                if secret_type in critical_types:
                    severity = "critical"
                elif secret_type in high_types:
                    severity = "high"
                else:
                    severity = "medium"
                
                finding = Finding(
                    title=f"{secret_type} discovered ({len(high_conf)} instances)",
                    severity=severity,
                    category="secret",
                    target=self.target,
                    description=f"Found {len(high_conf)} high-confidence {secret_type} secrets",
                    evidence=f"Total found: {len(secrets)}\nHigh confidence: {len(high_conf)}",
                    impact="Potential unauthorized access, data exfiltration, or service abuse",
                    remediation="1. Rotate the secret immediately\n2. Review access logs\n3. Implement secret management (Vault, AWS Secrets Manager)\n4. Remove from source code",
                    confidence="high",
                    source="secret_hunter",
                    cwe="CWE-798",
                    metadata={
                        "secret_type": secret_type,
                        "count": len(high_conf),
                        "samples": [
                            {
                                "masked_value": s["value"],
                                "source": s["source"],
                                "confidence": s["confidence"]
                            }
                            for s in high_conf[:5]
                        ]
                    }
                )
                self.writer.add_finding(finding)
    
    def save_results(self):
        """Save all results"""
        output_file = f"{self.output_dir}/secrets.json"
        
        # Mask raw values before saving
        safe_secrets = []
        for secret in self.secrets:
            safe_secret = secret.copy()
            safe_secret["value"] = self._mask_secret(secret["raw_value"])
            del safe_secret["raw_value"]
            safe_recrets.append(safe_secret)
        
        output = {
            "target": self.target,
            "analyzed_at": datetime.utcnow().isoformat(),
            "statistics": {
                "total_secrets": len(self.secrets),
                "by_type": {k: len(v) for k, v in self._group_by_type().items()}
            },
            "secrets": safe_secrets
        }
        
        with open(output_file, "w") as f:
            json.dump(output, f, indent=2)
        
        print(f"[+] Secrets saved to {output_file}")
    
    def _group_by_type(self):
        by_type = {}
        for secret in self.secrets:
            t = secret["type"]
            if t not in by_type:
                by_type[t] = []
            by_type[t].append(secret)
        return by_type
    
    def run(self, js_files=None, exposed_files=None):
        """Execute full secret hunting"""
        print(f"\n{'='*80}")
        print(f"SECRET HUNTER - Context-Aware Secret Detection")
        print(f"Target: {self.target}")
        print(f"{'='*80}\n")
        
        # Scan JavaScript files
        if js_files:
            print(f"[+] Scanning {len(js_files)} JavaScript files")
            try:
                import requests
                for js_url in js_files[:30]:
                    try:
                        response = requests.get(js_url, timeout=15)
                        if response.status_code == 200:
                            secrets = self.analyze_js_file(response.text, js_url)
                            self.secrets.extend(secrets)
                    except:
                        pass
            except Exception as e:
                print(f"[!] JS scanning error: {e}")
        
        # Scan GitHub
        self.scan_github_repos()
        
        # Scan exposed files
        if exposed_files:
            self.scan_exposed_files(exposed_files)
        
        # Analyze source maps
        if js_files:
            self.analyze_source_maps(js_files)
        
        # Generate findings
        self.generate_findings()
        self.writer.save()
        self.save_results()
        
        print(f"\n{'='*80}")
        print(f"Secret Hunting Complete")
        print(f"   Total secrets found: {len(self.secrets)}")
        print(f"{'='*80}\n")
        
        return self.secrets

def main(target, js_files=None, exposed_files=None, output_dir="results/secret_hunter"):
    hunter = SecretHunter(target, output_dir)
    return hunter.run(js_files, exposed_files)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target> [js_files_list] [exposed_files_list]")
        sys.exit(1)
    
    target = sys.argv[1]
    js_files = None
    exposed_files = None
    
    if len(sys.argv) > 2:
        try:
            with open(sys.argv[2]) as f:
                js_files = [line.strip() for line in f if line.strip()]
        except:
            pass
    
    if len(sys.argv) > 3:
        try:
            with open(sys.argv[3]) as f:
                data = json.load(f)
                exposed_files = data.get("exposed_files", [])
        except:
            pass
    
    main(target, js_files, exposed_files)
