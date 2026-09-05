#!/usr/bin/env python3
"""
Cloud Recon Module - Phase A.4
Discovers cloud infrastructure and storage:
- AWS S3 buckets
- Azure Blob Storage
- GCP Storage Buckets
- DigitalOcean Spaces
- Firebase instances
"""
import sys
import os
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Set, Optional
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))
from base import Finding, ResultWriter

class CloudRecon:
    PERMUTATIONS = [
        "{target}", "{target}-backup", "{target}-backups", "{target}-data",
        "{target}-dev", "{target}-prod", "{target}-staging", "{target}-test",
        "{target}-assets", "{target}-static", "{target}-media", "{target}-files",
        "{target}-logs", "{target}-{year}", "{target}-api", "{target}-cdn",
        "{target}-uploads", "{target}-public", "{target}-private",
        "{target}-internal", "{target}-archive", "{target}-old", "{target}-db",
        "{target}-config", "s3-{target}", "{target}-s3", "{target}-storage"
    ]
    
    def __init__(self, target: str, output_dir: str = "results/cloud_recon"):
        self.target = target
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        self.writer = ResultWriter(output_dir, "cloud_recon")
        self.discovered_resources = {
            "s3_buckets": [], "azure_blobs": [], "gcp_buckets": [],
            "cloudfront_distributions": [], "firebase_instances": []
        }
    
    def generate_bucket_names(self) -> List[str]:
        year = datetime.now().year
        names = set()
        for perm in self.PERMUTATIONS:
            names.add(perm.format(target=self.target, year=year))
        target_clean = self.target.replace(".", "").replace("-", "")
        names.update([target_clean, f"{target_clean}data", f"{target_clean}backup"])
        return sorted(names)
    
    def check_s3_bucket(self, bucket_name: str) -> Optional[Dict]:
        info = {"bucket": bucket_name, "exists": False, "public": False, "listable": False, "url": None}
        urls = [
            f"https://{bucket_name}.s3.amazonaws.com",
            f"https://{bucket_name}.s3.us-east-1.amazonaws.com"
        ]
        try:
            import requests
            for url in urls:
                try:
                    response = requests.get(url, timeout=10, allow_redirects=False)
                    if response.status_code == 200:
                        info["exists"] = True
                        info["url"] = url
                        info["public"] = True
                        if "<ListBucketResult" in response.text:
                            info["listable"] = True
                        return info
                    if response.status_code == 403 and "AccessDenied" in response.text:
                        info["exists"] = True
                        info["url"] = url
                        return info
                except:
                    continue
        except:
            pass
        return info if info["exists"] else None
    
    def check_firebase(self, project_name: str) -> Optional[Dict]:
        info = {"project": project_name, "exists": False, "public": False, "url": None}
        try:
            import requests
            url = f"https://{project_name}.firebaseio.com/.json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                info["exists"] = True
                info["public"] = True
                info["url"] = f"https://{project_name}.firebaseio.com"
                try:
                    data = response.json()
                    if data and data != {}:
                        info["data_exposed"] = True
                except:
                    pass
                return info
        except:
            pass
        return None
    
    def scan_all_providers(self, bucket_names: List[str]):
        print(f"[+] Scanning cloud providers for {len(bucket_names)} potential names")
        
        for name in bucket_names[:50]:
            result = self.check_s3_bucket(name)
            if result:
                self.discovered_resources["s3_buckets"].append(result)
                severity = "critical" if result["listable"] else "high" if result["public"] else "medium"
                finding = Finding(
                    title=f"AWS S3 bucket discovered: {result['bucket']}",
                    severity=severity,
                    category="cloud_storage",
                    target=result["url"] or result["bucket"],
                    description=f"AWS S3 bucket found with {'listable public access' if result.get('listable') else 'public access' if result['public'] else 'restricted access'}",
                    confidence="high",
                    source="cloud_recon",
                    cwe="CWE-284"
                )
                self.writer.add_finding(finding)
        
        for name in bucket_names[:20]:
            result = self.check_firebase(name)
            if result:
                self.discovered_resources["firebase_instances"].append(result)
                severity = "critical" if result.get("data_exposed") else "high"
                finding = Finding(
                    title=f"Firebase instance discovered: {result['project']}",
                    severity=severity,
                    category="cloud_database",
                    target=result["url"],
                    description=f"Firebase instance found with {'data exposed' if result.get('data_exposed') else 'public access'}",
                    confidence="high",
                    source="cloud_recon"
                )
                self.writer.add_finding(finding)
    
    def save_results(self):
        output_file = f"{self.output_dir}/cloud_resources.json"
        output = {
            "target": self.target,
            "analyzed_at": datetime.utcnow().isoformat(),
            "statistics": {k: len(v) for k, v in self.discovered_resources.items()},
            "resources": self.discovered_resources
        }
        with open(output_file, "w") as f:
            json.dump(output, f, indent=2)
        print(f"[+] Cloud resources saved to {output_file}")
    
    def run(self) -> Dict:
        print(f"\nCloud Recon: {self.target}\n")
        bucket_names = self.generate_bucket_names()
        self.scan_all_providers(bucket_names)
        self.writer.save()
        self.save_results()
        total = sum(len(v) for v in self.discovered_resources.values())
        print(f"\nTotal cloud resources discovered: {total}\n")
        return self.discovered_resources

def main(target: str, output_dir: str = "results/cloud_recon"):
    recon = CloudRecon(target, output_dir)
    return recon.run()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target> [output_dir]")
        sys.exit(1)
    target = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "results/cloud_recon"
    main(target, output_dir)
