#!/usr/bin/env python3
"""
🏢 Asset Ownership Module - Phase A.2

Determines asset ownership to:
- Identify in-scope vs out-of-scope assets
- Detect third-party services
- Map organizational structure
- Avoid legal issues by identifying unauthorized targets

Techniques:
- WHOIS data analysis
- DNS records (NS, MX, SOA, TXT)
- ASN organization lookup
- SSL certificate analysis
- HTTP header fingerprinting
- Company name extraction from metadata
"""
import sys
import os
import json
import subprocess
import re
from pathlib import Path
from typing import Dict, List, Set, Optional
from datetime import datetime
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from base import Finding, ResultWriter

class AssetOwnershipAnalyzer:
    """Analyze ownership of discovered assets"""
    
    # Known third-party services
    THIRD_PARTY_SERVICES = {
        "github.io": "GitHub Pages",
        "herokuapp.com": "Heroku",
        "netlify.app": "Netlify",
        "vercel.app": "Vercel",
        "pantheonsite.io": "Pantheon",
        "squarespace.com": "Squarespace",
        "wix.com": "Wix",
        "wordpress.com": "WordPress.com",
        "shopify.com": "Shopify",
        "zendesk.com": "Zendesk",
        "freshdesk.com": "Freshdesk",
        "salesforce.com": "Salesforce",
        "atlassian.net": "Atlassian",
        "slack.com": "Slack",
        "discourse.org": "Discourse",
        "ghost.io": "Ghost",
        "tumblr.com": "Tumblr",
        "typeform.com": "Typeform",
        "surveygizmo.com": "SurveyGizmo",
        "surveymonkey.com": "SurveyMonkey",
        "mailchimp.com": "Mailchimp",
        "sendgrid.net": "SendGrid",
        "mailgun.org": "Mailgun",
        "cloudfront.net": "AWS CloudFront",
        "amazonaws.com": "AWS",
        "azurewebsites.net": "Azure",
        "cloudapp.net": "Azure",
        "appspot.com": "Google App Engine",
        "googleapis.com": "Google Cloud",
        "firebaseapp.com": "Firebase",
        "firebaseio.com": "Firebase",
        "bitbucket.io": "Bitbucket",
        "gitlab.io": "GitLab",
        "pages.dev": "Cloudflare Pages",
        "workers.dev": "Cloudflare Workers",
        "r2.dev": "Cloudflare R2",
        "streamtape.com": "Streamtape",
        "s3.amazonaws.com": "AWS S3",
        "blob.core.windows.net": "Azure Blob",
        "storage.googleapis.com": "GCP Storage"
    }
    
    def __init__(self, target: str, assets_file: str, output_dir: str = "results/ownership"):
        self.target = target
        self.assets_file = assets_file
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        self.writer = ResultWriter(output_dir, "asset_ownership")
        self.ownership_map = {}  # asset -> ownership_info
        self.assets = self._load_assets()
    
    def _load_assets(self) -> Dict:
        """Load assets from attack surface module output"""
        try:
            with open(self.assets_file) as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Failed to load assets: {e}")
            return {"assets": {"subdomains": [], "ips": []}}
    
    def _run_tool(self, cmd: List[str], timeout: int = 60) -> str:
        """Run external tool safely"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.stdout
        except:
            return ""
    
    def analyze_whois(self, domain: str) -> Dict:
        """Analyze WHOIS data for a domain"""
        output = self._run_tool(["whois", domain], timeout=30)
        
        info = {
            "registrar": None,
            "registrant_org": None,
            "registrant_name": None,
            "registrant_email": None,
            "creation_date": None,
            "expiration_date": None,
            "name_servers": []
        }
        
        patterns = {
            "registrar": r"Registrar:\s*(.+)",
            "registrant_org": r"Registrant Organization:\s*(.+)",
            "registrant_name": r"Registrant Name:\s*(.+)",
            "registrant_email": r"Registrant Email:\s*(.+)",
            "creation_date": r"Creation Date:\s*(.+)",
            "expiration_date": r"Registry Expiry Date:\s*(.+)"
        }
        
        for field, pattern in patterns.items():
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                info[field] = match.group(1).strip()
        
        # Extract name servers
        ns_matches = re.findall(r"Name Server:\s*(.+)", output, re.IGNORECASE)
        info["name_servers"] = [ns.strip().lower() for ns in ns_matches]
        
        return info
    
    def analyze_dns_records(self, domain: str) -> Dict:
        """Analyze DNS records for ownership hints"""
        info = {
            "ns_records": [],
            "mx_records": [],
            "txt_records": [],
            "soa_record": None
        }
        
        # Use dig for detailed DNS queries
        for record_type in ["NS", "MX", "TXT", "SOA"]:
            output = self._run_tool(["dig", "+short", record_type, domain], timeout=15)
            records = [line.strip() for line in output.splitlines() if line.strip()]
            
            if record_type == "NS":
                info["ns_records"] = [r.rstrip(".").lower() for r in records]
            elif record_type == "MX":
                info["mx_records"] = records
            elif record_type == "TXT":
                info["txt_records"] = records
            elif record_type == "SOA":
                info["soa_record"] = records[0] if records else None
        
        return info
    
    def analyze_ssl_certificate(self, host: str) -> Dict:
        """Analyze SSL certificate for ownership info"""
        info = {
            "issuer": None,
            "subject": None,
            "subject_org": None,
            "issuer_org": None,
            "sans": []
        }
        
        try:
            import ssl
            import socket
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    
                    info["issuer"] = cert.issuer.rfc4514_string()
                    info["subject"] = cert.subject.rfc4514_string()
                    
                    # Extract organization
                    for attr in cert.subject:
                        if attr.oid._name == "organizationName":
                            info["subject_org"] = attr.value
                    
                    for attr in cert.issuer:
                        if attr.oid._name == "organizationName":
                            info["issuer_org"] = attr.value
                    
                    # Extract SANs
                    try:
                        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        info["sans"] = ext.value.get_values_for_type(x509.DNSName)
                    except:
                        pass
        except Exception as e:
            pass
        
        return info
    
    def check_third_party(self, host: str) -> Optional[str]:
        """Check if host belongs to known third-party service"""
        host_lower = host.lower()
        
        for pattern, service in self.THIRD_PARTY_SERVICES.items():
            if pattern in host_lower:
                return service
        
        # Check CNAME to known services
        output = self._run_tool(["dig", "+short", "CNAME", host], timeout=10)
        if output:
            cname = output.strip().rstrip(".").lower()
            for pattern, service in self.THIRD_PARTY_SERVICES.items():
                if pattern in cname:
                    return service
        
        return None
    
    def analyze_http_headers(self, host: str) -> Dict:
        """Analyze HTTP headers for ownership hints"""
        info = {
            "server": None,
            "powered_by": None,
            "organization": None,
            "title": None
        }
        
        output = self._run_tool([
            "httpx", "-u", f"https://{host}", "-silent",
            "-json", "-title", "-server", "-status-code"
        ], timeout=30)
        
        try:
            for line in output.splitlines():
                if line.strip():
                    data = json.loads(line)
                    info["server"] = data.get("webserver")
                    info["title"] = data.get("title")
                    break
        except:
            pass
        
        return info
    
    def determine_ownership(self, asset: str, asset_type: str = "subdomain") -> Dict:
        """Determine ownership of an asset"""
        ownership = {
            "asset": asset,
            "type": asset_type,
            "is_target_owned": False,
            "is_third_party": False,
            "third_party_service": None,
            "owner_organization": None,
            "confidence": "low",
            "evidence": []
        }
        
        # Check for third-party first
        third_party = self.check_third_party(asset)
        if third_party:
            ownership["is_third_party"] = True
            ownership["third_party_service"] = third_party
            ownership["confidence"] = "high"
            ownership["evidence"].append(f"Matches known third-party: {third_party}")
            return ownership
        
        # Analyze WHOIS for domains
        if asset_type in ["subdomain", "domain"]:
            domain = asset if asset_type == "domain" else ".".join(asset.split(".")[-2:])
            whois_info = self.analyze_whois(domain)
            
            if whois_info["registrant_org"]:
                ownership["owner_organization"] = whois_info["registrant_org"]
                ownership["evidence"].append(f"WHOIS registrant: {whois_info['registrant_org']}")
                
                # Check if organization matches target
                if self.target.lower() in whois_info["registrant_org"].lower():
                    ownership["is_target_owned"] = True
                    ownership["confidence"] = "high"
            
            # Analyze DNS records
            dns_info = self.analyze_dns_records(asset)
            
            # Check for third-party DNS providers
            third_party_dns = ["cloudflare", "google", "aws", "route53", "azure"]
            for ns in dns_info["ns_records"]:
                for provider in third_party_dns:
                    if provider in ns:
                        ownership["evidence"].append(f"DNS hosted by: {ns}")
        
        # SSL certificate analysis for subdomains
        if asset_type == "subdomain":
            ssl_info = self.analyze_ssl_certificate(asset)
            
            if ssl_info["subject_org"]:
                ownership["evidence"].append(f"SSL subject org: {ssl_info['subject_org']}")
                
                if self.target.lower() in ssl_info["subject_org"].lower():
                    ownership["is_target_owned"] = True
                    ownership["confidence"] = "high"
        
        # If we have any evidence and it's not third-party, likely target-owned
        if ownership["evidence"] and not ownership["is_third_party"]:
            ownership["is_target_owned"] = True
            if ownership["confidence"] == "low":
                ownership["confidence"] = "medium"
        
        return ownership
    
    def analyze_all_assets(self) -> Dict[str, Dict]:
        """Analyze ownership for all discovered assets"""
        assets = self.assets.get("assets", {})
        
        # Analyze subdomains
        subdomains = assets.get("subdomains", [])
        print(f"[+] Analyzing ownership for {len(subdomains)} subdomains")
        
        for i, subdomain in enumerate(subdomains, 1):
            if i % 50 == 0:
                print(f"    Progress: {i}/{len(subdomains)}")
            
            ownership = self.determine_ownership(subdomain, "subdomain")
            self.ownership_map[subdomain] = ownership
        
        # Analyze IPs
        ips = assets.get("ips", [])
        print(f"[+] Analyzing ownership for {len(ips)} IPs")
        
        for ip in ips:
            ownership = self.determine_ownership(ip, "ip")
            self.ownership_map[ip] = ownership
        
        return self.ownership_map
    
    def generate_findings(self):
        """Generate findings based on ownership analysis"""
        print(f"[+] Generating ownership findings")
        
        third_party_assets = []
        target_owned_assets = []
        unknown_ownership_assets = []
        
        for asset, ownership in self.ownership_map.items():
            if ownership["is_third_party"]:
                third_party_assets.append((asset, ownership))
            elif ownership["is_target_owned"]:
                target_owned_assets.append((asset, ownership))
            else:
                unknown_ownership_assets.append((asset, ownership))
        
        # Finding: Third-party assets that might be out of scope
        if third_party_assets:
            # Group by service
            by_service = {}
            for asset, ownership in third_party_assets:
                service = ownership["third_party_service"]
                if service not in by_service:
                    by_service[service] = []
                by_service[service].append(asset)
            
            for service, assets in by_service.items():
                finding = Finding(
                    title=f"Third-party service detected: {service}",
                    severity="info",
                    category="ownership",
                    target=self.target,
                    description=f"Found {len(assets)} assets hosted on {service}. Verify if these are in scope.",
                    confidence="high",
                    source="asset_ownership",
                    metadata={
                        "service": service,
                        "count": len(assets),
                        "assets": assets[:10]  # First 10 for brevity
                    }
                )
                self.writer.add_finding(finding)
        
        # Finding: Unknown ownership (needs manual verification)
        if unknown_ownership_assets:
            finding = Finding(
                title=f"Assets with unknown ownership require verification",
                severity="info",
                category="ownership",
                target=self.target,
                description=f"Found {len(unknown_ownership_assets)} assets that need manual ownership verification",
                confidence="medium",
                source="asset_ownership",
                metadata={
                    "count": len(unknown_ownership_assets),
                    "assets": [a for a, _ in unknown_ownership_assets[:20]]
                }
            )
            self.writer.add_finding(finding)
    
    def save_results(self):
        """Save ownership analysis results"""
        output_file = f"{self.output_dir}/ownership_analysis.json"
        
        # Categorize assets
        categorized = {
            "target_owned": [],
            "third_party": {},
            "unknown": []
        }
        
        for asset, ownership in self.ownership_map.items():
            if ownership["is_third_party"]:
                service = ownership["third_party_service"]
                if service not in categorized["third_party"]:
                    categorized["third_party"][service] = []
                categorized["third_party"][service].append(asset)
            elif ownership["is_target_owned"]:
                categorized["target_owned"].append(asset)
            else:
                categorized["unknown"].append(asset)
        
        output = {
            "target": self.target,
            "analyzed_at": datetime.utcnow().isoformat(),
            "statistics": {
                "total_analyzed": len(self.ownership_map),
                "target_owned": len(categorized["target_owned"]),
                "third_party_total": sum(len(v) for v in categorized["third_party"].values()),
                "unknown": len(categorized["unknown"])
            },
            "categorized": categorized,
            "detailed": self.ownership_map
        }
        
        with open(output_file, "w") as f:
            json.dump(output, f, indent=2)
        
        print(f"[+] Ownership analysis saved to {output_file}")
        print(f"    Target-owned: {len(categorized['target_owned'])}")
        print(f"    Third-party: {sum(len(v) for v in categorized['third_party'].values())}")
        print(f"    Unknown: {len(categorized['unknown'])}")
    
    def run(self) -> Dict:
        """Execute full ownership analysis"""
        print(f"\n{'='*80}")
        print(f"🏢 ASSET OWNERSHIP ANALYSIS")
        print(f"Target: {self.target}")
        print(f"{'='*80}\n")
        
        # Analyze all assets
        self.analyze_all_assets()
        
        # Generate findings
        self.generate_findings()
        self.writer.save()
        
        # Save detailed results
        self.save_results()
        
        return self.ownership_map

def main(target: str, assets_file: str, output_dir: str = "results/ownership"):
    """Main entry point"""
    analyzer = AssetOwnershipAnalyzer(target, assets_file, output_dir)
    return analyzer.run()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <target> <assets_file> [output_dir]")
        print(f"Example: {sys.argv[0]} example.com results/attack_surface/assets.json")
        sys.exit(1)
    
    target = sys.argv[1]
    assets_file = sys.argv[2]
    output_dir = sys.argv[3] if len(sys.argv) > 3 else "results/ownership"
    
    main(target, assets_file, output_dir)
