#!/usr/bin/env python3
"""
🔍 Dorking Engine - Multi-source dorking automation
Supports: Google (googlesearch-python), Bing scraping, 
          GitHub Search API, SerpAPI, Google Custom Search API
Usage:
    python3 dorking_engine.py --target example.com --dorks dorks_list.txt
"""

import os
import sys
import time
import json
import argparse
from pathlib import Path
from urllib.parse import quote_plus
import requests
from bs4 import BeautifulSoup

# Optional googlesearch-python (pure scraping, may get blocked)
try:
    from googlesearch import search as google_search
    HAS_GOOGLE = True
except ImportError:
    HAS_GOOGLE = False


class DorkingEngine:
    def __init__(self, target, dorks_file, delay=3, max_results=10,
                 github_token=None, serpapi_key=None,
                 google_cse_key=None, google_cse_cx=None,
                 sources=None):
        self.target = target
        self.dorks_file = Path(dorks_file)
        self.delay = delay
        self.max_results = max_results
        self.github_token = github_token
        self.serpapi_key = serpapi_key
        self.google_cse_key = google_cse_key
        self.google_cse_cx = google_cse_cx
        self.sources = sources or ["google", "bing", "github"]
        self.results = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
            )
        })

    def load_dorks(self):
        dorks = []
        with open(self.dorks_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                dork = line.replace("TARGET", self.target)
                dorks.append(dork)
        return dorks

    # ─── Search Backends ───

    def search_google(self, query):
        if not HAS_GOOGLE:
            return []
        urls = []
        try:
            for url in google_search(query, num_results=self.max_results, lang="en"):
                if url not in urls:
                    urls.append(url)
            time.sleep(self.delay)
        except Exception as e:
            print(f"    [!] Google error: {e}")
        return urls

    def search_bing(self, query):
        urls = []
        try:
            q = quote_plus(query)
            url = f"https://www.bing.com/search?q={q}&count={self.max_results}"
            resp = self.session.get(url, timeout=20)
            soup = BeautifulSoup(resp.text, "html.parser")
            for a in soup.select("li.b_algo h2 a"):
                href = a.get("href")
                if href and href.startswith("http") and href not in urls:
                    urls.append(href)
            time.sleep(self.delay)
        except Exception as e:
            print(f"    [!] Bing error: {e}")
        return urls

    def search_github(self, query):
        if not self.github_token:
            return []
        urls = []
        try:
            q = quote_plus(query)
            api_url = f"https://api.github.com/search/code?q={q}&per_page={self.max_results}"
            headers = {
                "Authorization": f"token {self.github_token}",
                "Accept": "application/vnd.github.v3+json"
            }
            resp = requests.get(api_url, headers=headers, timeout=15)
            if resp.status_code == 200:
                for item in resp.json().get("items", []):
                    u = item.get("html_url")
                    if u and u not in urls:
                        urls.append(u)
            elif resp.status_code == 403:
                print(f"    [!] GitHub rate limit / abuse detection")
            else:
                print(f"    [!] GitHub API {resp.status_code}")
            time.sleep(self.delay)
        except Exception as e:
            print(f"    [!] GitHub error: {e}")
        return urls

    def search_serpapi(self, query):
        if not self.serpapi_key:
            return []
        urls = []
        try:
            params = {
                "engine": "google",
                "q": query,
                "num": self.max_results,
                "api_key": self.serpapi_key
            }
            resp = requests.get("https://serpapi.com/search", params=params, timeout=30)
            if resp.status_code == 200:
                for result in resp.json().get("organic_results", []):
                    link = result.get("link")
                    if link and link not in urls:
                        urls.append(link)
            else:
                print(f"    [!] SerpAPI {resp.status_code}: {resp.text[:200]}")
            time.sleep(self.delay)
        except Exception as e:
            print(f"    [!] SerpAPI error: {e}")
        return urls

    def search_google_cse(self, query):
        if not (self.google_cse_key and self.google_cse_cx):
            return []
        urls = []
        try:
            params = {
                "key": self.google_cse_key,
                "cx": self.google_cse_cx,
                "q": query,
                "num": min(self.max_results, 10)
            }
            resp = requests.get(
                "https://www.googleapis.com/customsearch/v1",
                params=params, timeout=20
            )
            if resp.status_code == 200:
                for item in resp.json().get("items", []):
                    link = item.get("link")
                    if link and link not in urls:
                        urls.append(link)
            else:
                print(f"    [!] CSE {resp.status_code}: {resp.text[:200]}")
            time.sleep(self.delay)
        except Exception as e:
            print(f"    [!] CSE error: {e}")
        return urls

    def run_dork(self, dork):
        entry = {"dork": dork, "findings": []}
        is_github_dork = dork.startswith("org:")

        if is_github_dork and "github" in self.sources and self.github_token:
            print(f"    [GitHub API]")
            urls = self.search_github(dork)
            entry["findings"].extend([{"url": u, "source": "github"} for u in urls])
            return entry

        source_methods = {
            "serpapi": self.search_serpapi,
            "google_cse": self.search_google_cse,
            "google": self.search_google,
            "bing": self.search_bing,
        }

        for src in self.sources:
            if src in source_methods:
                print(f"    [{src}]")
                urls = source_methods[src](dork)
                if urls:
                    entry["findings"].extend([{"url": u, "source": src} for u in urls])
                    if src in ("serpapi", "google_cse"):
                        break
        return entry

    def run(self):
        dorks = self.load_dorks()
        print(f"[+] Loaded {len(dorks)} dorks for: {self.target}")
        print(f"[+] Active sources: {', '.join(self.sources)}\n")

        for idx, dork in enumerate(dorks, 1):
            print(f"[{idx}/{len(dorks)}] {dork}")
            result = self.run_dork(dork)
            self.results.append(result)

        return self.results

    def save(self, output_dir):
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        # 1) Full JSON
        with open(out / "results.json", "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        # 2) Markdown report
        md = [
            f"# 🔍 Dorking Recon Report",
            f"",
            f"**Target:** `{self.target}`  ",
            f"**Total Dorks:** {len(self.results)}  ",
            f"**Timestamp:** {time.strftime('%Y-%m-%d %H:%M UTC')}",
            f""
        ]

        total_findings = 0
        for r in self.results:
            if r["findings"]:
                total_findings += len(r["findings"])
                md.append(f"## `{r['dork']}`")
                md.append(f"**{len(r['findings'])} result(s)**")
                by_src = {}
                for f in r["findings"]:
                    by_src.setdefault(f["source"], []).append(f["url"])
                for src, urls in by_src.items():
                    md.append(f"### Source: {src}")
                    for u in urls:
                        md.append(f"- {u}")
                md.append("")

        md.insert(4, f"**Total Findings:** {total_findings}")

        with open(out / "report.md", "w", encoding="utf-8") as f:
            f.write("\n".join(md))

        # 3) Unique URLs flat list
        all_urls = sorted({f["url"] for r in self.results for f in r["findings"]})
        with open(out / "urls.txt", "w", encoding="utf-8") as f:
            for u in all_urls:
                f.write(u + "\n")

        print(f"\n[✓] Done: {total_findings} unique findings -> {out}")


def main():
    parser = argparse.ArgumentParser(description="Dorking Recon Engine")
    parser.add_argument("--target", required=True, help="Target domain or org")
    parser.add_argument("--dorks", required=True, help="Path to dorks file")
    parser.add_argument("--output", default="results/dorking", help="Output directory")
    parser.add_argument("--delay", type=int, default=3, help="Delay between requests")
    parser.add_argument("--max-results", type=int, default=10, help="Max results per dork")
    parser.add_argument(
        "--sources", default="google,bing,github",
        help="Comma-separated priority: serpapi,google_cse,google,bing,github"
    )
    parser.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN", ""))
    parser.add_argument("--serpapi-key", default=os.environ.get("SERPAPI_KEY", ""))
    parser.add_argument("--google-cse-key", default=os.environ.get("GOOGLE_CSE_KEY", ""))
    parser.add_argument("--google-cse-cx", default=os.environ.get("GOOGLE_CSE_CX", ""))
    args = parser.parse_args()

    sources = [s.strip() for s in args.sources.split(",") if s.strip()]

    engine = DorkingEngine(
        target=args.target,
        dorks_file=args.dorks,
        delay=args.delay,
        max_results=args.max_results,
        github_token=args.github_token,
        serpapi_key=args.serpapi_key,
        google_cse_key=args.google_cse_key,
        google_cse_cx=args.google_cse_cx,
        sources=sources
    )
    engine.run()
    engine.save(args.output)


if __name__ == "__main__":
    main()
