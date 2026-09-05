#!/usr/bin/env python3
"""
🔍 Source Code Recon & Leak Detection - Phase A.3

Discovers exposed source code and sensitive files:
- GitHub code search (organization, repositories, leaked secrets)
- npm/pypi package analysis
- Exposed .git/.svn repositories
- Leaked .env files
- Backup files (.bak, .old, .zip, .tar.gz)
- Configuration files (.config, .ini, .yaml)
- Source maps from JavaScript
- Exposed IDE files (.vscode, .idea)

Techniques:
- GitHub API search
- Direct file probing with httpx
- Git repository extraction
- Pattern-based discovery
"""
import sys
import os
import json
import subprocess
import re
import time
from pathlib import Path
from typing import Dict, List, Set, Optional
from datetime import datetime
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from base import Finding, ResultWriter

class SourceCodeRecon:
    """Source code and leak detection module"""
    
    # High-value sensitive files to probe
    SENSITIVE_FILES = [
        # Git repositories
        ".git/config",
        ".git/HEAD",
        ".git/index",
        ".git/refs/heads/master",
        ".git/refs/heads/main",
        ".gitignore",
        
        # SVN
        ".svn/entries",
        ".svn/wc.db",
        
        # Environment files
        ".env",
        ".env.local",
        ".env.development",
        ".env.production",
        ".env.staging",
        ".env.test",
        ".env.backup",
        "env",
        "environment",
        
        # Configuration files
        "config.php",
        "config.yml",
        "config.yaml",
        "config.json",
        "config.ini",
        "config.xml",
        "configuration.php",
        "settings.py",
        "settings.json",
        "settings.yml",
        "application.yml",
        "application.properties",
        "web.config",
        "app.config",
        
        # Backup files
        "backup.sql",
        "database.sql",
        "dump.sql",
        "backup.zip",
        "backup.tar.gz",
        "site.zip",
        "www.zip",
        "html.zip",
        "backup.bak",
        "index.php.bak",
        "config.php.bak",
        "web.config.bak",
        
        # IDE and development files
        ".vscode/settings.json",
        ".idea/workspace.xml",
        ".idea/dataSources.xml",
        ".DS_Store",
        "Thumbs.db",
        
        # CMS files
        "wp-config.php",
        "wp-config.php.bak",
        "wp-config.php.old",
        "wp-config.php.save",
        "wp-content/debug.log",
        "administrator/configuration.php",
        "configuration.php",
        
        # Debug and log files
        "debug.log",
        "error.log",
        "access.log",
        "php_errors.log",
        "laravel.log",
        "storage/logs/laravel.log",
        
        # API documentation
        "swagger.json",
        "swagger.yml",
        "openapi.json",
        "openapi.yml",
        "api-docs.json",
        
        # Sensitive endpoints
        "phpinfo.php",
        "info.php",
        "test.php",
        "server-status",
        "server-info",
        ".htaccess",
        ".htpasswd",
        "robots.txt",
        "sitemap.xml",
        "crossdomain.xml",
        "clientaccesspolicy.xml",
        
        # CI/CD files
        ".travis.yml",
        ".github/workflows/ci.yml",
        ".github/workflows/deploy.yml",
        "Jenkinsfile",
        ".circleci/config.yml",
        "azure-pipelines.yml",
        "bitbucket-pipelines.yml",
        "Dockerfile",
        "docker-compose.yml",
        
        # Package files
        "package.json",
        "package-lock.json",
        "composer.json",
        "composer.lock",
        "Gemfile",
        "Gemfile.lock",
        "requirements.txt",
        "Pipfile",
        "Pipfile.lock",
        "pom.xml",
        "build.gradle",
        
        # Cloud config
        ".aws/credentials",
        ".ssh/id_rsa",
        "id_rsa",
        "id_rsa.pub",
        "credentials.json",
        "service-account.json"
    ]
    
    # Backup file patterns
    BACKUP_EXTENSIONS = [".bak", ".old", ".orig", ".save", ".swp", ".dist", ".backup", ".copy"]
    COMPRESSED_EXTENSIONS = [".zip", ".tar.gz", ".tgz", ".tar.bz2", ".rar", ".7z"]
    
    def __init__(self, target: str, hosts_file: str, output_dir: str = "results/source_recon"):
        self.target = target
        self.hosts_file = hosts_file
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        self.writer = ResultWriter(output_dir, "source_recon")
        self.findings = []
        self.github_results = {}
        self.exposed_files = {}
        
        self.hosts = self._load_hosts()
    
    def _load_hosts(self) -> List[str]:
        """Load hosts to scan"""
        try:
            with open(self.hosts_file) as f:
                return [line.strip() for line in f if line.strip()]
        except:
            # If file contains JSON, extract live hosts
            try:
                with open(self.hosts_file) as f:
                    data = json.load(f)
                    if "assets" in data:
                        return data["assets"].get("subdomains", [])
            except:
                pass
        return []
    
    def _run_tool(self, cmd: List[str], timeout: int = 600) -> str:
        """Run external tool safely"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.stdout
        except:
            return ""
    
    def github_code_search(self, query: str) -> List[Dict]:
        """Search GitHub for leaked code"""
        results = []
        
        # Use GitHub search API
        search_queries = [
            f'"{self.target}" password',
            f'"{self.target}" api_key',
            f'"{self.target}" secret',
            f'"{self.target}" token',
            f'"{self.target}" credentials',
            f'"{self.target}" database_url',
            f'"{self.target}" aws_access_key',
            f'"{self.target}" stripe_key',
            f'"{self.target}" filename:.env',
            f'"{self.target}" extension:env',
            f'"{self.target}" extension:pem',
            f'"{self.target}" extension:sql'
        ]
        
        try:
            import requests
            
            for query in search_queries:
                url = f"https://api.github.com/search/code?q={query}"
                headers = {"Accept": "application/vnd.github.v3.text-match+json"}
                
                response = requests.get(url, headers=headers, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    for item in data.get("items", [])[:20]:  # Limit results
                        results.append({
                            "repository": item.get("repository", {}).get("full_name"),
                            "path": item.get("path"),
                            "html_url": item.get("html_url"),
                            "query": query
                        })
                
                # Rate limit handling
                time.sleep(2)
        except Exception as e:
            print(f"[!] GitHub search error: {e}")
        
        return results
    
    def search_github_org(self) -> List[Dict]:
        """Search for GitHub organization related to target"""
        results = []
        
        try:
            import requests
            
            # Search for organizations with target name
            url = f"https://api.github.com/search/repositories?q={self.target}"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get("items", [])[:50]:
                    results.append({
                        "repository": item.get("full_name"),
                        "description": item.get("description"),
                        "url": item.get("html_url"),
                        "language": item.get("language"),
                        "stars": item.get("stargazers_count")
                    })
        except Exception as e:
            print(f"[!] GitHub org search error: {e}")
        
        return results
    
    def probe_sensitive_files(self, host: str) -> List[Dict]:
        """Probe for sensitive files on a host"""
        found = []
        
        # Build URL list
        urls = []
        for file_path in self.SENSITIVE_FILES:
            urls.append(f"https://{host}/{file_path}")
            urls.append(f"http://{host}/{file_path}")
        
        # Use httpx for mass probing
        urls_file = f"{self.output_dir}/urls_to_probe.txt"
        with open(urls_file, "w") as f:
            f.write("\n".join(urls))
        
        output_file = f"{self.output_dir}/httpx_sensitive_{host}.json"
        
        output = self._run_tool([
            "httpx", "-l", urls_file, "-silent",
            "-status-code", "-content-length",
            "-match-code", "200,201,301,302,403",
            "-json", "-o", output_file
        ], timeout=300)
        
        # Parse results
        try:
            with open(output_file) as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        url = data.get("url", data.get("input", ""))
                        status = data.get("status-code")
                        length = data.get("content-length", 0)
                        
                        # Filter out 403 (forbidden) - usually not accessible
                        if status in [200, 201, 301, 302] and length > 0:
                            # Extract file path
                            parsed = urlparse(url)
                            file_path = parsed.path.lstrip("/")
                            
                            found.append({
                                "url": url,
                                "path": file_path,
                                "status": status,
                                "size": length,
                                "host": host
                            })
                    except:
                        pass
        except FileNotFoundError:
            pass
        
        # Cleanup
        try:
            os.remove(urls_file)
            os.remove(output_file)
        except:
            pass
        
        return found
    
    def extract_git_repository(self, host: str) -> Optional[Dict]:
        """Try to extract .git repository contents"""
        info = {"host": host, "exposed": False, "files": [], "commits": []}
        
        # Check if .git/config exists
        try:
            import requests
            url = f"https://{host}/.git/config"
            response = requests.get(url, timeout=15, allow_redirects=False)
            
            if response.status_code == 200 and "[core]" in response.text:
                info["exposed"] = True
                info["config"] = response.text[:500]  # First 500 chars
                
                # Try to get HEAD
                head_url = f"https://{host}/.git/HEAD"
                head_resp = requests.get(head_url, timeout=10)
                if head_resp.status_code == 200:
                    info["head"] = head_resp.text.strip()
                
                # Try to get refs
                refs_url = f"https://{host}/.git/refs/heads/"
                refs_resp = requests.get(refs_url, timeout=10)
                if refs_resp.status_code == 200:
                    info["branches"] = [
                        line.strip() for line in refs_resp.text.splitlines()
                        if line.strip()
                    ]
        except:
            pass
        
        return info if info["exposed"] else None
    
    def find_backup_files(self, host: str) -> List[Dict]:
        """Find backup files by pattern"""
        found = []
        
        # Common backup patterns
        base_files = ["index.php", "config.php", "wp-config.php", "web.config"]
        
        urls = []
        for base in base_files:
            for ext in self.BACKUP_EXTENSIONS:
                urls.append(f"https://{host}/{base}{ext}")
        
        # Use httpx
        urls_file = f"{self.output_dir}/backup_urls.txt"
        with open(urls_file, "w") as f:
            f.write("\n".join(urls))
        
        output_file = f"{self.output_dir}/httpx_backup_{host}.json"
        
        self._run_tool([
            "httpx", "-l", urls_file, "-silent",
            "-match-code", "200",
            "-json", "-o", output_file
        ], timeout=120)
        
        try:
            with open(output_file) as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        found.append({
                            "url": data.get("url", data.get("input", "")),
                            "status": data.get("status-code"),
                            "size": data.get("content-length", 0)
                        })
                    except:
                        pass
        except FileNotFoundError:
            pass
        
        return found
    
    def analyze_js_source_maps(self, host: str) -> List[Dict]:
        """Find and analyze JavaScript source maps"""
        found = []
        
        try:
            import requests
            
            # Get homepage
            url = f"https://{host}"
            response = requests.get(url, timeout=15)
            
            if response.status_code == 200:
                # Find all JS files
                js_pattern = r'src=["\']([^"\']*.js)["\']'
                js_files = re.findall(js_pattern, response.text)
                
                # Check each JS file for sourceMappingURL
                for js_file in js_files[:10]:  # Limit
                    if not js_file.startswith("http"):
                        js_file = f"{url}/{js_file}"
                    
                    try:
                        js_resp = requests.get(js_file, timeout=10)
                        if js_resp.status_code == 200:
                            # Look for sourceMappingURL
                            map_match = re.search(r'//# sourceMappingURL=(.+)', js_resp.text)
                            if map_match:
                                map_url = map_match.group(1)
                                found.append({
                                    "js_file": js_file,
                                    "source_map": map_url,
                                    "host": host
                                })
                    except:
                        pass
        except Exception as e:
            print(f"[!] Source map analysis error: {e}")
        
        return found
    
    def scan_all_hosts(self):
        """Scan all hosts for sensitive files"""
        print(f"[+] Scanning {len(self.hosts)} hosts for sensitive files")
        
        for i, host in enumerate(self.hosts, 1):
            if i % 20 == 0:
                print(f"    Progress: {i}/{len(self.hosts)}")
            
            # Remove protocol if present
            host = host.replace("https://", "").replace("http://", "").strip()
            
            # Probe sensitive files
            found_files = self.probe_sensitive_files(host)
            if found_files:
                self.exposed_files[host] = found_files
                
                # Create findings
                for file_info in found_files:
                    path = file_info["path"]
                    
                    # Determine severity based on file type
                    severity = "info"
                    if ".env" in path.lower() or "config.php" in path.lower():
                        severity = "high"
                    elif ".git/" in path or ".svn/" in path:
                        severity = "critical"
                    elif ".sql" in path or "backup" in path.lower():
                        severity = "high"
                    elif "debug" in path.lower() or "log" in path.lower():
                        severity = "medium"
                    
                    finding = Finding(
                        title=f"Exposed sensitive file: {path}",
                        severity=severity,
                        category="sensitive_file",
                        target=file_info["url"],
                        description=f"Sensitive file '{path}' is publicly accessible",
                        evidence=f"URL: {file_info['url']}\nStatus: {file_info['status']}\nSize: {file_info['size']} bytes",
                        confidence="high",
                        source="source_recon",
                        cwe="CWE-538" if ".git" in path else "CWE-200"
                    )
                    self.writer.add_finding(finding)
            
            # Try to extract git repos
            git_info = self.extract_git_repository(host)
            if git_info:
                finding = Finding(
                    title=f"Exposed Git repository on {host}",
                    severity="critical",
                    category="exposed_repository",
                    target=f"https://{host}",
                    description=f"Git repository is publicly accessible - full source code disclosure possible",
                    evidence=f"HEAD: {git_info.get('head', 'N/A')}\nBranches: {', '.join(git_info.get('branches', [])[:5])}",
                    impact="Complete source code disclosure, potentially including hardcoded secrets, internal logic, and vulnerabilities",
                    remediation="1. Disable directory listing on web server\n2. Move .git directory outside web root\n3. Use .htaccess to block access: `RedirectMatch 404 /\.git`",
                    confidence="high",
                    source="source_recon",
                    cwe="CWE-538",
                    cvss=9.1
                )
                self.writer.add_finding(finding)
    
    def generate_github_findings(self):
        """Generate findings from GitHub searches"""
        print(f"[+] Searching GitHub for leaked secrets")
        
        # Search for leaked code
        code_results = self.github_code_search(f'"{self.target}"')
        
        if code_results:
            for result in code_results:
                finding = Finding(
                    title=f"Potentially leaked code on GitHub: {result['repository']}",
                    severity="medium",
                    category="github_leak",
                    target=result["html_url"],
                    description=f"Found potential sensitive information in public GitHub repository",
                    evidence=f"Repository: {result['repository']}\nPath: {result['path']}\nSearch: {result['query']}",
                    confidence="medium",
                    source="source_recon",
                    metadata=result
                )
                self.writer.add_finding(finding)
        
        # Search for organization
        org_results = self.search_github_org()
        
        if org_results:
            for result in org_results:
                if result.get("description"):
                    desc_lower = result["description"].lower()
                    if "internal" in desc_lower or "private" in desc_lower or "secret" in desc_lower:
                        finding = Finding(
                            title=f"Suspicious GitHub repository: {result['repository']}",
                            severity="low",
                            category="github_repo",
                            target=result["url"],
                            description=f"Repository description suggests it might contain sensitive information",
                            evidence=f"Description: {result['description']}\nStars: {result.get('stars', 0)}",
                            confidence="low",
                            source="source_recon",
                            metadata=result
                        )
                        self.writer.add_finding(finding)
    
    def save_results(self):
        """Save all results to JSON"""
        output_file = f"{self.output_dir}/source_recon_results.json"
        
        output = {
            "target": self.target,
            "analyzed_at": datetime.utcnow().isoformat(),
            "statistics": {
                "hosts_scanned": len(self.hosts),
                "exposed_files": sum(len(f) for f in self.exposed_files.values()),
                "github_results": len(self.github_results)
            },
            "exposed_files": self.exposed_files,
            "github_results": self.github_results
        }
        
        with open(output_file, "w") as f:
            json.dump(output, f, indent=2)
        
        print(f"[+] Results saved to {output_file}")
    
    def run(self) -> Dict:
        """Execute full source code recon"""
        print(f"\n{'='*80}")
        print(f"🔍 SOURCE CODE RECON & LEAK DETECTION")
        print(f"Target: {self.target}")
        print(f"{'='*80}\n")
        
        # Scan all hosts
        self.scan_all_hosts()
        
        # GitHub searches
        self.generate_github_findings()
        
        # Save findings
        self.writer.save()
        self.save_results()
        
        return {
            "exposed_files": self.exposed_files,
            "github_results": self.github_results
        }

def main(target: str, hosts_file: str, output_dir: str = "results/source_recon"):
    """Main entry point"""
    recon = SourceCodeRecon(target, hosts_file, output_dir)
    return recon.run()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <target> <hosts_file> [output_dir]")
        print(f"Example: {sys.argv[0]} example.com results/attack_surface/live_hosts.txt")
        sys.exit(1)
    
    target = sys.argv[1]
    hosts_file = sys.argv[2]
    output_dir = sys.argv[3] if len(sys.argv) > 3 else "results/source_recon"
    
    main(target, hosts_file, output_dir)
