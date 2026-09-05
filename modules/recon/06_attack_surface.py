#!/usr/bin/env python3
"""
🌐 Attack Surface Mapping - Phase A Core Module

Comprehensive attack surface discovery combining:
- Subdomain enumeration (passive + active)
- IP discovery (A/AAAA records, ASN mapping)
- Port scanning (top ports + full scan option)
- Service fingerprinting
- ASN enumeration
- Cloud infrastructure detection

Output: Standardized JSON with all discovered assets
"""
import sys
import os
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Set
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))
from base import Finding, ResultWriter, load_config

class AttackSurfaceMapper:
    """Comprehensive attack surface mapper"""
    
    def __init__(self, target: str, output_dir: str = "results/attack_surface"):
        self.target = target
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        self.writer = ResultWriter(output_dir, "attack_surface")
        self.assets = {
            "subdomains": set(),
            "ips": set(),
            "cidrs": set(),
            "asns": set(),
            "ports": {},  # ip -> {port: service}
            "cloud_providers": set(),
            "technologies": {}  # host -> [technologies]
        }
    
    def _run_tool(self, cmd: List[str], timeout: int = 600) -> str:
        """Run external tool safely"""
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout,
                env={**os.environ, "PATH": os.environ.get("PATH", "")}
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            print(f"[!] Timeout: {' '.join(cmd[:2])}")
            return ""
        except FileNotFoundError:
            print(f"[!] Tool not found: {cmd[0]}")
            return ""
    
    def enumerate_subdomains(self) -> Set[str]:
        """Multi-source subdomain enumeration"""
        print(f"[+] Phase 1: Subdomain enumeration for {self.target}")
        
        subs = set()
        
        # 1. Subfinder (passive)
        output = self._run_tool(["subfinder", "-d", self.target, "-silent", "-timeout", "300"])
        for line in output.splitlines():
            line = line.strip().lower()
            if line.endswith(f".{self.target}"):
                subs.add(line)
        
        print(f"    subfinder: {len([s for s in subs if s])} subdomains")
        
        # 2. Assetfinder (complementary passive)
        output = self._run_tool(["assetfinder", "--subs-only", self.target])
        for line in output.splitlines():
            line = line.strip().lower()
            if line.endswith(f".{self.target}"):
                subs.add(line)
        
        # 3. crt.sh (Certificate Transparency)
        try:
            import requests
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            resp = requests.get(url, timeout=60)
            if resp.status_code == 200:
                for cert in resp.json():
                    name = cert.get("name_value", "")
                    for line in name.split("\n"):
                        line = line.strip().lower()
                        if line.endswith(f".{self.target}") and "*" not in line:
                            subs.add(line)
        except Exception as e:
            print(f"    crt.sh error: {e}")
        
        # 4. Amass (passive)
        output = self._run_tool(["amass", "enum", "-passive", "-d", self.target])
        for line in output.splitlines():
            line = line.strip().lower()
            if line.endswith(f".{self.target}"):
                subs.add(line)
        
        # 5. Findomain
        output = self._run_tool(["findomain", "-t", self.target, "-q"])
        for line in output.splitlines():
            line = line.strip().lower()
            if line.endswith(f".{self.target}"):
                subs.add(line)
        
        subs = {s for s in subs if s}
        self.assets["subdomains"] = subs
        print(f"    Total unique subdomains: {len(subs)}")
        
        return subs
    
    def resolve_ips(self, subdomains: Set[str]) -> Dict[str, Set[str]]:
        """Resolve subdomains to IPs"""
        print(f"[+] Phase 2: DNS resolution for {len(subdomains)} subdomains")
        
        # Write subdomains to temp file
        subs_file = f"{self.output_dir}/subdomains.txt"
        with open(subs_file, "w") as f:
            f.write("\n".join(sorted(subdomains)))
        
        # Use dnsx for mass resolution
        output = self._run_tool([
            "dnsx", "-l", subs_file, "-a", "-aaaa", "-silent",
            "-json", "-o", f"{self.output_dir}/dns_resolution.json"
        ])
        
        resolved = {}
        try:
            with open(f"{self.output_dir}/dns_resolution.json") as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        host = data.get("host", "").lower()
                        a_records = data.get("a", [])
                        aaaa_records = data.get("aaaa", [])
                        ips = set(a_records + aaaa_records)
                        
                        if ips:
                            resolved[host] = ips
                            self.assets["ips"].update(ips)
                    except:
                        pass
        except FileNotFoundError:
            pass
        
        print(f"    Resolved: {len(resolved)} hosts, {len(self.assets['ips'])} unique IPs")
        return resolved
    
    def scan_ports(self, ips: Set[str], mode: str = "top") -> Dict[str, Dict]:
        """Port scanning with naabu/nmap"""
        print(f"[+] Phase 3: Port scanning ({mode} mode)")
        
        if not ips:
            return {}
        
        ips_file = f"{self.output_dir}/ips.txt"
        with open(ips_file, "w") as f:
            f.write("\n".join(sorted(ips)))
        
        ports = {}
        
        if mode == "top":
            # Fast top-1000 port scan
            output = self._run_tool([
                "naabu", "-list", ips_file,
                "-top-ports", "1000",
                "-silent", "-json",
                "-o", f"{self.output_dir}/naabu_results.json"
            ], timeout=1800)
            
            try:
                with open(f"{self.output_dir}/naabu_results.json") as f:
                    for line in f:
                        try:
                            data = json.loads(line)
                            host = data.get("host", data.get("ip", ""))
                            port = data.get("port")
                            
                            if host not in ports:
                                ports[host] = {}
                            ports[host][port] = "unknown"
                        except:
                            pass
            except FileNotFoundError:
                pass
        
        self.assets["ports"] = ports
        print(f"    Scanned: {len(ports)} hosts")
        return ports
    
    def detect_cloud_infrastructure(self) -> Dict[str, str]:
        """Detect cloud providers for discovered IPs"""
        print(f"[+] Phase 4: Cloud infrastructure detection")
        
        cloud_map = {}
        
        for ip in self.assets["ips"]:
            provider = self._identify_cloud(ip)
            if provider:
                cloud_map[ip] = provider
                self.assets["cloud_providers"].add(provider)
        
        print(f"    Cloud IPs: {len(cloud_map)} ({', '.join(self.assets['cloud_providers']) or 'none'})")
        return cloud_map
    
    def _identify_cloud(self, ip: str) -> str:
        """Identify cloud provider for an IP"""
        # Cloud CIDR ranges (simplified - real impl would use full databases)
        # This would integrate with ipinfo.io, whoisxmlapi, etc.
        
        # ASN-based detection via whois/dns
        try:
            result = subprocess.run(
                ["whois", ip],
                capture_output=True,
                text=True,
                timeout=30
            )
            output = result.stdout.lower()
            
            if "amazon" in output or "aws" in output:
                return "AWS"
            elif "google" in output or "gcp" in output:
                return "GCP"
            elif "microsoft" in output or "azure" in output:
                return "Azure"
            elif "oracle" in output:
                return "Oracle Cloud"
            elif "digitalocean" in output:
                return "DigitalOcean"
            elif "cloudflare" in output:
                return "Cloudflare"
            elif "akamai" in output:
                return "Akamai"
            elif "linode" in output:
                return "Linode"
            elif "vultr" in output:
                return "Vultr"
        except:
            pass
        
        return None
    
    def detect_asns(self) -> Set[str]:
        """Enumerate ASNs for the target"""
        print(f"[+] Phase 5: ASN enumeration")
        
        asns = set()
        
        # Use amass intel for ASN discovery
        output = self._run_tool([
            "amass", "intel", "-org", self.target, "-timeout", "120"
        ])
        
        for line in output.splitlines():
            # Parse AS numbers
            import re
            as_match = re.search(r"AS(\d+)", line)
            if as_match:
                asns.add(as_match.group(1))
        
        # Use asnmap if available
        output = self._run_tool(["asnmap", "-d", self.target, "-silent"])
        for line in output.splitlines():
            import re
            as_match = re.search(r"AS(\d+)", line)
            if as_match:
                asns.add(as_match.group(1))
        
        self.assets["asns"] = asns
        print(f"    ASNs found: {len(asns)}")
        
        return asns
    
    def fingerprint_technologies(self, subdomains: Set[str]) -> Dict[str, List[str]]:
        """Fingerprint technologies on live hosts"""
        print(f"[+] Phase 6: Technology fingerprinting")
        
        tech_map = {}
        
        # First, probe live hosts
        live_file = f"{self.output_dir}/live_hosts.txt"
        
        # Use httpx to find live hosts
        subs_file = f"{self.output_dir}/subdomains.txt"
        output = self._run_tool([
            "httpx", "-l", subs_file, "-silent",
            "-tech-detect", "-title",
            "-json", "-o", f"{self.output_dir}/httpx_results.json"
        ], timeout=600)
        
        try:
            with open(f"{self.output_dir}/httpx_results.json") as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        host = data.get("input", "").lower()
                        techs = data.get("tech", [])
                        
                        if techs:
                            tech_map[host] = techs
                            self.assets["technologies"][host] = techs
                    except:
                        pass
        except FileNotFoundError:
            pass
        
        print(f"    Fingerprinted: {len(tech_map)} hosts")
        return tech_map
    
    def generate_findings(self):
        """Generate findings from discovered assets"""
        print(f"[+] Generating findings from attack surface")
        
        # High-value subdomains
        high_value_patterns = ["admin", "api", "dev", "staging", "test", "internal", "vpn", "mail"]
        
        for subdomain in self.assets["subdomains"]:
            for pattern in high_value_patterns:
                if pattern in subdomain:
                    finding = Finding(
                        title=f"High-value subdomain: {subdomain}",
                        severity="info",
                        category="subdomain",
                        target=subdomain,
                        description=f"Discovered subdomain containing '{pattern}' keyword, typically high-value target",
                        confidence="high",
                        source="attack_surface",
                        metadata={"subdomain": subdomain, "pattern": pattern}
                    )
                    self.writer.add_finding(finding)
                    break
        
        # Cloud IPs
        for ip, provider in self.detect_cloud_infrastructure().items():
            finding = Finding(
                title=f"{provider} infrastructure: {ip}",
                severity="info",
                category="cloud",
                target=ip,
                description=f"IP {ip} belongs to {provider} cloud infrastructure",
                confidence="high",
                source="attack_surface",
                metadata={"ip": ip, "provider": provider}
            )
            self.writer.add_finding(finding)
        
        # Interesting ports
        interesting_ports = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 
                           3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
                           27017: "MongoDB", 9200: "Elasticsearch"}
        
        for ip, ports in self.assets["ports"].items():
            for port in ports:
                if port in interesting_ports:
                    finding = Finding(
                        title=f"Interesting service: {interesting_ports[port]} on {ip}:{port}",
                        severity="low",
                        category="port",
                        target=f"{ip}:{port}",
                        description=f"Potentially interesting service detected",
                        confidence="high",
                        source="attack_surface",
                        metadata={"ip": ip, "port": port, "service": interesting_ports[port]}
                    )
                    self.writer.add_finding(finding)
        
        # Vulnerable technologies
        vuln_tech = ["jenkins", "tomcat", "struts", "weblogic", "jboss", "drupal"]
        
        for host, techs in self.assets["technologies"].items():
            for tech in techs:
                if any(v in tech.lower() for v in vuln_tech):
                    finding = Finding(
                        title=f"Potentially vulnerable technology: {tech} on {host}",
                        severity="medium",
                        category="technology",
                        target=host,
                        description=f"Technology '{tech}' detected - known for historical vulnerabilities",
                        confidence="medium",
                        source="attack_surface",
                        metadata={"host": host, "technology": tech}
                    )
                    self.writer.add_finding(finding)
    
    def save_assets(self):
        """Save all assets to JSON file"""
        assets_file = f"{self.output_dir}/assets.json"
        
        output = {
            "target": self.target,
            "generated_at": datetime.utcnow().isoformat(),
            "statistics": {
                "subdomains": len(self.assets["subdomains"]),
                "ips": len(self.assets["ips"]),
                "cidrs": len(self.assets["cidrs"]),
                "asns": len(self.assets["asns"]),
                "cloud_providers": len(self.assets["cloud_providers"])
            },
            "assets": {
                "subdomains": sorted(self.assets["subdomains"]),
                "ips": sorted(self.assets["ips"]),
                "cidrs": sorted(self.assets["cidrs"]),
                "asns": sorted(self.assets["asns"]),
                "ports": {k: v for k, v in self.assets["ports"].items()},
                "cloud_providers": sorted(self.assets["cloud_providers"]),
                "technologies": self.assets["technologies"]
            }
        }
        
        with open(assets_file, "w") as f:
            json.dump(output, f, indent=2)
        
        print(f"[+] Assets saved to {assets_file}")
    
    def run(self, mode: str = "full") -> Dict:
        """Execute full attack surface mapping"""
        print(f"\n{'='*80}")
        print(f"🌐 ATTACK SURFACE MAPPING")
        print(f"Target: {self.target}")
        print(f"Mode: {mode}")
        print(f"{'='*80}\n")
        
        # Execute phases
        subdomains = self.enumerate_subdomains()
        resolved = self.resolve_ips(subdomains)
        self.scan_ports(self.assets["ips"], mode="top" if mode != "full" else "full")
        self.detect_asns()
        self.fingerprint_technologies(subdomains)
        
        # Generate findings
        self.generate_findings()
        self.writer.save()
        
        # Save raw assets
        self.save_assets()
        
        print(f"\n{'='*80}")
        print(f"✅ Attack Surface Mapping Complete")
        print(f"   Subdomains: {len(self.assets['subdomains'])}")
        print(f"   IPs: {len(self.assets['ips'])}")
        print(f"   ASNs: {len(self.assets['asns'])}")
        print(f"   Cloud Providers: {len(self.assets['cloud_providers'])}")
        print(f"{'='*80}\n")
        
        return self.assets

def main(target: str, output_dir: str = "results/attack_surface", mode: str = "full"):
    """Main entry point"""
    mapper = AttackSurfaceMapper(target, output_dir)
    return mapper.run(mode)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target> [output_dir] [mode]")
        print(f"  mode: 'fast' or 'full' (default: full)")
        sys.exit(1)
    
    target = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "results/attack_surface"
    mode = sys.argv[3] if len(sys.argv) > 3 else "full"
    
    main(target, output_dir, mode)
