# 🔍 Dorking Recon Workflow

## Setup
1. Copy `dorking_engine.py` to your repo root.
2. Copy `.github/workflows/dorking-recon.yml` to `.github/workflows/`.
3. (Optional) Add your dorks file (e.g., `dorks_list.txt`) to the repo.

## Secrets (optional but recommended)
| Secret | Purpose |
|--------|---------|
| `GITHUB_TOKEN` | For `org:TARGET` GitHub code search |
| `SERPAPI_KEY` | Reliable Google results via SerpAPI |
| `GOOGLE_CSE_KEY` + `GOOGLE_CSE_CX` | Google Custom Search API |

## Usage
Go to **Actions → Dorking Recon → Run workflow** and enter:
- **Target**: `example.com`
- **Dorks file**: `dorks_list.txt` (or the file you uploaded)
- **Sources**: `serpapi,google,bing,github` (reorder by priority)

## Output
- `results.json` — full structured data
- `report.md` — readable markdown report
- `urls.txt` — flat list of all unique URLs found
