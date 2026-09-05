#!/usr/bin/env python3
"""
BugBountyCI Local Orchestrator
Fallback for running pipeline locally (mirrors hunt.yml workflow)

Usage:
    python orchestrate.py example.com full    # Run all phases
    python orchestrate.py example.com quick   # Recon + scan only
"""
import sys
import os
import json
import subprocess
from pathlib import Path
from datetime import datetime

class Orchestrator:
    def __init__(self, target, mode='full'):
        self.target = target
        self.mode = mode
        self.output_dir = 'results'
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        Path('reports').mkdir(parents=True, exist_ok=True)
        self.start_time = datetime.utcnow()
        self.results = {}

    def run_module(self, module_path, args=None):
        args = args or []
        cmd = ['python3', module_path] + args
        print(f'\n[+] Running: {" ".join(cmd)}')

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            success = result.returncode == 0

            if success:
                print('    ✓ Success')
            else:
                print('    ✗ Failed')
                if result.stderr:
                    print(f'    Error: {result.stderr[:300]}')

            self.results[module_path] = {'success': success}
            return success
        except subprocess.TimeoutExpired:
            print('    ✗ Timeout')
            self.results[module_path] = {'success': False, 'error': 'timeout'}
            return False
        except FileNotFoundError:
            print(f'    ✗ Module not found: {module_path}')
            return False
        except Exception as e:
            print(f'    ✗ Error: {e}')
            self.results[module_path] = {'success': False, 'error': str(e)}
            return False

    def phase_a_recon(self):
        print(f'\n{"="*80}')
        print('PHASE A: SMART RECON')
        print('='*80)

        modules = [
            ('modules/recon/01_subdomain.py', [self.target, f'{self.output_dir}/recon']),
            ('modules/recon/02_live_probe.py', [f'{self.output_dir}/recon/all_subs.txt', f'{self.output_dir}/recon']),
            ('modules/recon/06_attack_surface.py', [self.target, f'{self.output_dir}/attack_surface', 'full']),
            ('modules/recon/07_asset_ownership.py', [self.target, f'{self.output_dir}/attack_surface/assets.json', f'{self.output_dir}/ownership']),
            ('modules/recon/03_temporal.py', [self.target, f'{self.output_dir}/ghost']),
            ('modules/recon/04_param_ghost.py', [f'{self.output_dir}/ghost/all_temporal_urls.txt', self.target, f'{self.output_dir}/ghost']),
            ('modules/recon/09_cloud_recon.py', [self.target, f'{self.output_dir}/cloud']),
            ('modules/recon/08_source_recon.py', [self.target, f'{self.output_dir}/recon/live.txt', f'{self.output_dir}/source_recon']),
            ('modules/recon/10_ai_endpoints.py', [self.target, f'{self.output_dir}/ai_endpoints']),
            ('modules/recon/11_secret_hunter.py', [self.target, f'{self.output_dir}/secret_hunter'])
        ]

        for module, args in modules:
            if os.path.exists(module):
                self.run_module(module, args)
            else:
                print(f'    ⚠ {module} not found, skipping')

    def phase_b_analysis(self):
        print(f'\n{"="*80}')
        print('PHASE B: INTELLIGENCE & ANALYSIS')
        print('='*80)

        modules = [
            ('modules/scan/01_nuclei.py', [f'{self.output_dir}/recon/live.txt', f'{self.output_dir}/scan']),
            ('modules/scan/02_race.py', [f'{self.output_dir}/recon/live.txt', f'{self.output_dir}/scan']),
            ('modules/analysis/01_business_logic.py', [self.target, f'{self.output_dir}/business_logic']),
            ('modules/analysis/02_chain_builder.py', [self.target, self.output_dir, f'{self.output_dir}/chains']),
            ('modules/analysis/03_ai_triager.py', [self.target, f'{self.output_dir}/triage']),
            ('modules/analysis/04_prioritizer.py', [self.target, f'{self.output_dir}/prioritized']),
            ('modules/analysis/05_report_generator.py', [self.target, 'reports'])
        ]

        for module, args in modules:
            if os.path.exists(module):
                self.run_module(module, args)
            else:
                print(f'    ⚠ {module} not found, skipping')

    def phase_c_speed(self):
        if self.mode != 'full':
            return

        print(f'\n{"="*80}')
        print('PHASE C: SPEED & COVERAGE')
        print('='*80)

        modules = [
            ('modules/speed/01_parallel_scanner.py', [self.target, f'{self.output_dir}/recon/live.txt', f'{self.output_dir}/parallel']),
            ('modules/speed/04_smart_fuzz.py', [self.target, f'{self.output_dir}/urls.txt', f'{self.output_dir}/fuzz'])
        ]

        for module, args in modules:
            if os.path.exists(module):
                self.run_module(module, args)

    def finalize(self):
        print(f'\n{"="*80}')
        print('FINALIZATION')
        print('='*80)

        summary = {
            'target': self.target,
            'mode': self.mode,
            'started_at': self.start_time.isoformat(),
            'completed_at': datetime.utcnow().isoformat(),
            'duration_seconds': (datetime.utcnow() - self.start_time).total_seconds(),
            'modules_run': len(self.results),
            'successful': sum(1 for r in self.results.values() if r.get('success')),
            'failed': sum(1 for r in self.results.values() if not r.get('success'))
        }

        with open(f'{self.output_dir}/pipeline_summary.json', 'w') as f:
            json.dump(summary, f, indent=2)

        print(f'\n{"#"*80}')
        print('PIPELINE COMPLETE')
        print('#'*80)
        print(f'Target: {self.target}')
        print(f'Mode: {self.mode}')
        print(f'Duration: {summary["duration_seconds"]:.1f}s')
        print(f'Modules: {summary["modules_run"]} ({summary["successful"]} success, {summary["failed"]} failed)')
        print(f'Results: ./{self.output_dir}/')
        print(f'Reports: ./reports/')
        print('#'*80 + '\n')

    def run(self):
        print(f'\n{"#"*80}')
        print('# BugBountyCI v3.0 Local Orchestrator')
        print(f'# Target: {self.target}')
        print(f'# Mode: {self.mode}')
        print(f'# Started: {self.start_time.isoformat()}')
        print('#'*80 + '\n')

        self.phase_a_recon()
        self.phase_b_analysis()
        self.phase_c_speed()
        self.finalize()

def main():
    if len(sys.argv) < 2:
        print('Usage: python orchestrate.py <target> [full|quick]')
        print('Example: python orchestrate.py example.com full')
        sys.exit(1)

    target = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else 'full'

    if mode not in ['full', 'quick']:
        print(f'Invalid mode: {mode}. Use "full" or "quick"')
        sys.exit(1)

    orch = Orchestrator(target, mode)
    orch.run()

if __name__ == '__main__':
    main()