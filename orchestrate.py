#!/usr/bin/env python3
"""
BugBountyCI Orchestrator - Main Entry Point

Executes the complete bug bounty pipeline:
Phase A: Smart Recon
Phase B: Intelligence & Analysis
Phase C: Speed & Coverage
Phase D: Integration
"""
import sys
import os
import json
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List

class Orchestrator:
    def __init__(self, target, output_dir="results", mode="full"):
        self.target = target
        self.output_dir = output_dir
        self.mode = mode
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        self.results = {}
        self.start_time = datetime.utcnow()
    
    def run_module(self, module_path, args=None):
        """Run a single module"""
        args = args or []
        cmd = ["python", module_path, self.target] + args
        
        print(f"\n[+] Running: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,
                cwd=os.getcwd()
            )
            
            success = result.returncode == 0
            
            if success:
                print(f"    ✓ Module completed successfully")
            else:
                print(f"    ✗ Module failed: {result.stderr[:200]}")
            
            return {
                "success": success,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
        except subprocess.TimeoutExpired:
            print(f"    ✗ Module timeout")
            return {"success": False, "error": "Timeout"}
        except Exception as e:
            print(f"    ✗ Module error: {e}")
            return {"success": False, "error": str(e)}
    
    def phase_a_recon(self):
        """Phase A: Smart Recon"""
        print(f"\n{'='*80}")
        print(f"PHASE A: SMART RECON")
        print(f"{'='*80}")
        
        modules = [
            ("modules/recon/01_subdomain.py", [f"{self.output_dir}/recon"]),
            ("modules/recon/02_live_probe.py", [f"{self.output_dir}/recon/all_subs.txt"]),
            ("modules/recon/06_attack_surface.py", [f"{self.output_dir}/attack_surface"]),
            ("modules/recon/07_asset_ownership.py", [f"{self.output_dir}/attack_surface/assets.json"]),
            ("modules/recon/08_source_recon.py", [f"{self.output_dir}/recon/live.txt"]),
            ("modules/recon/09_cloud_recon.py", [f"{self.output_dir}/cloud"]),
            ("modules/recon/10_ai_endpoints.py", []),
            ("modules/recon/11_secret_hunter.py", [])
        ]
        
        for module_path, args in modules:
            if os.path.exists(module_path):
                self.results[module_path] = self.run_module(module_path, args)
    
    def phase_b_analysis(self):
        """Phase B: Intelligence & Analysis"""
        print(f"\n{'='*80}")
        print(f"PHASE B: INTELLIGENCE & ANALYSIS")
        print(f"{'='*80}")
        
        modules = [
            ("modules/analysis/01_business_logic.py", []),
            ("modules/analysis/02_chain_builder.py", [self.output_dir]),
            ("modules/analysis/03_ai_triager.py", []),
            ("modules/analysis/04_prioritizer.py", []),
            ("modules/analysis/05_report_generator.py", [f"{self.output_dir}/reports"])
        ]
        
        for module_path, args in modules:
            if os.path.exists(module_path):
                self.results[module_path] = self.run_module(module_path, args)
    
    def phase_c_speed(self):
        """Phase C: Speed & Coverage"""
        print(f"\n{'='*80}")
        print(f"PHASE C: SPEED & COVERAGE")
        print(f"{'='*80}")
        
        modules = [
            ("modules/speed/01_parallel_scanner.py", []),
            ("modules/speed/02_continuous_monitor.py", []),
            ("modules/speed/03_template_engine.py", []),
            ("modules/speed/04_smart_fuzz.py", [])
        ]
        
        for module_path, args in modules:
            if os.path.exists(module_path):
                self.results[module_path] = self.run_module(module_path, args)
    
    def phase_d_integration(self):
        """Phase D: Integration"""
        print(f"\n{'='*80}")
        print(f"PHASE D: INTEGRATION")
        print(f"{'='*80}")
        
        # Generate final summary
        summary = {
            "target": self.target,
            "started_at": self.start_time.isoformat(),
            "completed_at": datetime.utcnow().isoformat(),
            "duration": str(datetime.utcnow() - self.start_time),
            "modules_executed": len(self.results),
            "successful": sum(1 for r in self.results.values() if r.get("success")),
            "failed": sum(1 for r in self.results.values() if not r.get("success"))
        }
        
        summary_file = f"{self.output_dir}/orchestration_summary.json"
        with open(summary_file, "w") as f:
            json.dump(summary, f, indent=2)
        
        print(f"[+] Orchestration summary saved to {summary_file}")
    
    def run(self):
        """Execute full pipeline"""
        print(f"\n{'#'*80}")
        print(f"# BugBountyCI Orchestrator")
        print(f"# Target: {self.target}")
        print(f"# Mode: {self.mode}")
        print(f"# Started: {self.start_time.isoformat()}")
        print(f"{'#'*80}\n")
        
        # Execute phases
        self.phase_a_recon()
        self.phase_b_analysis()
        
        if self.mode == "full":
            self.phase_c_speed()
        
        self.phase_d_integration()
        
        # Final summary
        end_time = datetime.utcnow()
        duration = end_time - self.start_time
        
        print(f"\n{'#'*80}")
        print(f"# PIPELINE COMPLETE")
        print(f"# Target: {self.target}")
        print(f"# Duration: {duration}")
        print(f"# Modules: {len(self.results)}")
        print(f"# Successful: {sum(1 for r in self.results.values() if r.get('success'))}")
        print(f"# Failed: {sum(1 for r in self.results.values() if not r.get('success'))}")
        print(f"{'#'*80}\n")
        
        return self.results

def main():
    if len(sys.argv) < 2:
        print("Usage: python orchestrate.py <target> [mode]")
        print("  mode: 'full' (default) or 'quick'")
        sys.exit(1)
    
    target = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "full"
    
    orchestrator = Orchestrator(target, mode=mode)
    return orchestrator.run()

if __name__ == "__main__":
    main()
