#!/usr/bin/env python3
"""
Massive Parallel Scanner - Phase C.1

Executes all modules in parallel for maximum speed:
- Concurrent subdomain enumeration
- Parallel port scanning
- Simultaneous vulnerability checks
- Distributed task scheduling
- Resource optimization

Reduces scan time from hours to minutes.
"""
import sys, os, json
import asyncio
import aiohttp
from pathlib import Path
from datetime import datetime
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import subprocess

sys.path.insert(0, str(Path(__file__).parent.parent))
from base import Finding, ResultWriter

class ParallelScanner:
    """Execute scanning modules in parallel"""
    
    def __init__(self, target, output_dir="results/parallel", max_workers=10):
        self.target = target
        self.output_dir = output_dir
        self.max_workers = max_workers
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        self.writer = ResultWriter(output_dir, "parallel_scan")
        self.results = {}
    
    def run_module_sync(self, module_path: str, args: List[str]) -> Dict:
        """Run a module synchronously (for process pool)"""
        try:
            cmd = ["python", module_path, self.target] + args
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,  # 1 hour timeout
                cwd=os.path.dirname(module_path)
            )
            
            return {
                "module": module_path,
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                "module": module_path,
                "success": False,
                "error": "Timeout"
            }
        except Exception as e:
            return {
                "module": module_path,
                "success": False,
                "error": str(e)
            }
    
    async def run_module_async(self, module_path: str, args: List[str]) -> Dict:
        """Run a module asynchronously"""
        loop = asyncio.get_event_loop()
        
        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            result = await loop.run_in_executor(
                executor,
                self.run_module_sync,
                module_path,
                args
            )
        
        return result
    
    def execute_parallel_phases(self):
        """Execute scanning phases in parallel"""
        print(f"[+] Executing parallel scanning phases")
        
        # Define phases that can run in parallel
        parallel_phases = [
            {
                "name": "subdomain_enum",
                "module": "modules/recon/01_subdomain.py",
                "args": [f"{self.output_dir}/subdomains"]
            },
            {
                "name": "attack_surface",
                "module": "modules/recon/06_attack_surface.py",
                "args": [f"{self.output_dir}/attack_surface"]
            },
            {
                "name": "cloud_recon",
                "module": "modules/recon/09_cloud_recon.py",
                "args": [f"{self.output_dir}/cloud"]
            }
        ]
        
        # Execute in parallel
        with ThreadPoolExecutor(max_workers=len(parallel_phases)) as executor:
            futures = []
            for phase in parallel_phases:
                print(f"    Starting: {phase['name']}")
                future = executor.submit(
                    self.run_module_sync,
                    phase["module"],
                    phase["args"]
                )
                futures.append((phase["name"], future))
            
            # Collect results
            for name, future in futures:
                result = future.result()
                self.results[name] = result
                
                if result["success"]:
                    print(f"    ✓ {name} completed successfully")
                else:
                    print(f"    ✗ {name} failed: {result.get('error', 'Unknown')}")
    
    async def execute_concurrent_checks(self, hosts: List[str]):
        """Execute concurrent HTTP checks on multiple hosts"""
        print(f"[+] Running concurrent checks on {len(hosts)} hosts")
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(limit=50)
        ) as session:
            
            async def check_host(host: str) -> Dict:
                """Check a single host"""
                try:
                    url = f"https://{host}"
                    async with session.get(url, allow_redirects=True) as response:
                        return {
                            "host": host,
                            "status": response.status,
                            "url": str(response.url),
                            "headers": dict(response.headers),
                            "success": True
                        }
                except Exception as e:
                    return {
                        "host": host,
                        "success": False,
                        "error": str(e)
                    }
            
            # Execute all checks concurrently
            tasks = [check_host(host) for host in hosts[:100]]  # Limit to 100
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            successful = sum(1 for r in results if isinstance(r, dict) and r.get("success"))
            print(f"    Checked {len(results)} hosts, {successful} successful")
            
            return results
    
    def parallel_port_scan(self, hosts: List[str], ports: str = "top-1000"):
        """Parallel port scanning using naabu"""
        print(f"[+] Parallel port scanning {len(hosts)} hosts")
        
        # Write hosts to file
        hosts_file = f"{self.output_dir}/hosts_to_scan.txt"
        with open(hosts_file, "w") as f:
            f.write("\n".join(hosts))
        
        output_file = f"{self.output_dir}/port_scan_results.json"
        
        # Run naabu with high concurrency
        cmd = [
            "naabu",
            "-list", hosts_file,
            "-top-ports", ports,
            "-c", "100",  # 100 concurrent threads
            "-rate", "1000",  # 1000 packets per second
            "-silent",
            "-json",
            "-o", output_file
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            
            if result.returncode == 0:
                # Parse results
                open_ports = {}
                try:
                    with open(output_file) as f:
                        for line in f:
                            data = json.loads(line)
                            host = data.get("host", data.get("ip", ""))
                            port = data.get("port")
                            
                            if host not in open_ports:
                                open_ports[host] = []
                            open_ports[host].append(port)
                    
                    total_ports = sum(len(ports) for ports in open_ports.values())
                    print(f"    Scanned {len(open_ports)} hosts, found {total_ports} open ports")
                except:
                    pass
                
                return open_ports
        except Exception as e:
            print(f"    [!] Port scan error: {e}")
        
        return {}
    
    def parallel_nuclei_scan(self, targets: List[str], templates: str = None):
        """Parallel nuclei scanning"""
        print(f"[+] Parallel nuclei scan on {len(targets)} targets")
        
        # Write targets to file
        targets_file = f"{self.output_dir}/targets_for_nuclei.txt"
        with open(targets_file, "w") as f:
            f.write("\n".join(targets))
        
        output_file = f"{self.output_dir}/nuclei_parallel_results.json"
        
        cmd = [
            "nuclei",
            "-l", targets_file,
            "-c", "50",  # 50 concurrent templates
            "-bs", "25",  # Batch size
            "-severity", "critical,high,medium",
            "-silent",
            "-json",
            "-o", output_file
        ]
        
        if templates:
            cmd.extend(["-t", templates])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            if result.returncode == 0:
                # Count findings
                findings = 0
                try:
                    with open(output_file) as f:
                        findings = sum(1 for line in f if line.strip())
                    print(f"    Found {findings} vulnerabilities")
                except:
                    pass
                
                return findings
        except Exception as e:
            print(f"    [!] Nuclei scan error: {e}")
        
        return 0
    
    def optimize_resource_usage(self):
        """Optimize resource usage based on system capabilities"""
        import multiprocessing
        
        cpu_count = multiprocessing.cpu_count()
        memory_gb = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') / (1024**3)
        
        print(f"[+] System resources: {cpu_count} CPUs, {memory_gb:.1f} GB RAM")
        
        # Adjust max workers based on resources
        if cpu_count >= 8 and memory_gb >= 16:
            self.max_workers = 20
        elif cpu_count >= 4 and memory_gb >= 8:
            self.max_workers = 10
        else:
            self.max_workers = 5
        
        print(f"    Max parallel workers: {self.max_workers}")
    
    def save_results(self):
        """Save parallel scan results"""
        output_file = f"{self.output_dir}/parallel_results.json"
        
        output = {
            "target": self.target,
            "scanned_at": datetime.utcnow().isoformat(),
            "configuration": {
                "max_workers": self.max_workers
            },
            "phase_results": self.results
        }
        
        with open(output_file, "w") as f:
            json.dump(output, f, indent=2)
        
        print(f"[+] Parallel results saved to {output_file}")
    
    def run(self, hosts: List[str] = None):
        """Execute full parallel scan"""
        print(f"\n{'='*80}")
        print(f"MASSIVE PARALLEL SCANNING")
        print(f"Target: {self.target}")
        print(f"{'='*80}\n")
        
        # Optimize resources
        self.optimize_resource_usage()
        
        # Execute parallel phases
        self.execute_parallel_phases()
        
        # If hosts provided, run concurrent checks
        if hosts:
            # Concurrent HTTP checks
            asyncio.run(self.execute_concurrent_checks(hosts))
            
            # Parallel port scanning
            self.parallel_port_scan(hosts)
            
            # Parallel nuclei scan
            self.parallel_nuclei_scan(hosts)
        
        # Save results
        self.save_results()
        
        print(f"\n{'='*80}")
        print(f"Parallel Scanning Complete")
        print(f"   Phases executed: {len(self.results)}")
        print(f"   Successful: {sum(1 for r in self.results.values() if r.get('success'))}")
        print(f"{'='*80}\n")
        
        return self.results

def main(target, hosts_file=None, output_dir="results/parallel"):
    scanner = ParallelScanner(target, output_dir)
    
    hosts = []
    if hosts_file and os.path.exists(hosts_file):
        with open(hosts_file) as f:
            hosts = [line.strip() for line in f if line.strip()]
    
    return scanner.run(hosts)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target> [hosts_file]")
        sys.exit(1)
    
    target = sys.argv[1]
    hosts_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    main(target, hosts_file)
