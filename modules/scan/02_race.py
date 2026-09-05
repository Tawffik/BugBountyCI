#!/usr/bin/env python3
"""
🏃 Race Condition Auto-Detect Module
Automatically detects race conditions in API endpoints
Tests for: Last-byte sync, Single-packet attacks, etc.
"""
import subprocess
import json
import os
import sys
from pathlib import Path
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor

class RaceConditionDetector:
    def __init__(self, output_dir="results/scan"):
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    async def test_endpoint(self, session, url, method="POST", data=None, headers=None):
        """Test a single endpoint for race conditions"""
        try:
            if method == "POST":
                async with session.post(url, data=data, headers=headers) as resp:
                    return {
                        "url": url,
                        "status": resp.status,
                        "content": await resp.text(),
                        "headers": dict(resp.headers)
                    }
            else:
                async with session.get(url, headers=headers) as resp:
                    return {
                        "url": url,
                        "status": resp.status,
                        "content": await resp.text(),
                        "headers": dict(resp.headers)
                    }
        except Exception as e:
            return {"url": url, "error": str(e)}
    
    async def last_byte_sync_test(self, url, num_requests=10):
        """
        Test for Last-byte sync race condition
        Send multiple requests with same timing to detect race
        """
        print(f"[+] Testing last-byte sync on {url}...")
        
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Send requests simultaneously
            tasks = [self.test_endpoint(session, url, "POST", {"test": "data"}) for _ in range(num_requests)]
            results = await asyncio.gather(*tasks)
            
            # Analyze for race condition indicators
            responses = [r for r in results if "status" in r]
            
            if len(responses) < 2:
                return None
            
            # Check for inconsistent responses (indicator of race)
            statuses = [r["status"] for r in responses]
            contents = [r.get("content", "")[:100] for r in responses]
            
            # If we get different responses, possible race condition
            unique_statuses = set(statuses)
            unique_contents = set(contents)
            
            if len(unique_statuses) > 1 or len(unique_contents) > 1:
                return {
                    "type": "last_byte_sync",
                    "url": url,
                    "inconsistent_statuses": unique_statuses,
                    "inconsistent_responses": len(unique_contents),
                    "total_requests": len(responses)
                }
        
        return None
    
    async def single_packet_test(self, url, num_requests=10):
        """
        Test for Single-packet attack (Turbo Intruder style)
        Send requests that arrive at the same time
        """
        print(f"[+] Testing single-packet attack on {url}...")
        
        # This is a simplified version - real implementation would use
        # raw sockets with precise timing
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            tasks = [self.test_endpoint(session, url, "POST", {"amount": "100"}) for _ in range(num_requests)]
            results = await asyncio.gather(*tasks)
            
            responses = [r for r in results if "status" in r]
            
            # Look for signs of race condition
            # e.g., multiple successful transactions when only one should succeed
            success_count = sum(1 for r in responses if r["status"] == 200)
            
            if success_count > 1:
                return {
                    "type": "single_packet",
                    "url": url,
                    "successful_requests": success_count,
                    "total_requests": len(responses)
                }
        
        return None
    
    async def scan_urls(self, url_file):
        """Scan all URLs from file for race conditions"""
        print(f"[+] Loading URLs from {url_file}...")
        
        urls = []
        with open(url_file) as f:
            urls = [line.strip() for line in f if line.strip()]
        
        print(f"[+] Loaded {len(urls)} URLs to test")
        
        findings = []
        
        for url in urls:
            # Test last-byte sync
            result = await self.last_byte_sync_test(url)
            if result:
                findings.append(result)
            
            # Test single-packet
            result = await self.single_packet_test(url)
            if result:
                findings.append(result)
        
        # Save findings
        output_file = f"{self.output_dir}/race_conditions.json"
        with open(output_file, "w") as f:
            json.dump(findings, f, indent=2)
        
        print(f"[✓] Found {len(findings)} potential race conditions")
        return findings

def main(url_file, output_dir="results/scan"):
    """Main race condition detection function"""
    print(f"\n{'='*60}")
    print(f"🏃 RACE CONDITION DETECTOR")
    print(f"{'='*60}\n")
    
    detector = RaceConditionDetector(output_dir)
    
    loop = asyncio.get_event_loop()
    findings = loop.run_until_complete(detector.scan_urls(url_file))
    
    return findings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <url_file> [output_dir]")
        sys.exit(1)
    
    url_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "results/scan"
    main(url_file, output_dir)
