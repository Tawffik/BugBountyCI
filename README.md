# BugBountyCI v3.0 - Professional Bug Bounty Automation

> Advanced AI-powered bug bounty platform with 20+ specialized modules.

## Quick Start (GitHub Actions)

1. Go to https://github.com/Tawffik/BugBountyCI
2. Click **Actions** tab
3. Select **Full Bug Bounty Hunt - Complete Pipeline**
4. Click **Run workflow**
5. Enter your target domain (e.g., example.com)
6. Choose mode: full or quick
7. Click **Run workflow**
8. Download results from **Artifacts** after ~30-60 minutes

## What Runs

### Phase A: Smart Recon (12 steps)
- Subdomain enumeration, live probing, attack surface mapping
- **Ghost Layer**: Temporal recon, parameter mining, JS deep mining
- Source code leak detection, cloud recon, secret hunting

### Phase B: Intelligence & Analysis (7 steps)
- Nuclei scan, race condition detection
- **Chain Attack Builder**: Auto-builds attack chains
- **AI Triager**: LLM-powered false positive filtering
- Scope-aware prioritization, professional reports

### Phase C: Speed (full mode only)
- Parallel scanning (10-50x faster)
- Smart fuzzing (GraphQL, API versions, headers)

## Local Execution

Clone and run locally:

    git clone -b refactor/modular-v2 https://github.com/Tawffik/BugBountyCI.git
    cd BugBountyCI
    pip install -r requirements.txt
    python orchestrate.py example.com full

## API Keys (Optional)

Add to repo secrets for AI features:
- ANTHROPIC_API_KEY - Claude AI
- GEMINI_API_KEY - Google Gemini
- GROQ_API_KEY - Groq Llama (free tier)
- DISCORD_WEBHOOK - Discord notifications

## Key Innovations

1. **Ghost Layer** - Discovers historical/temporal attack surface
2. **Secret Hunter** - Context-aware secret detection with entropy analysis
3. **Chain Attack Builder** - Auto-builds exploitable attack chains
4. **AI Triager** - LLM-powered false positive filtering

## Output

Results are uploaded as artifact bugbounty-results-{run_id}:
- results/recon/ - Subdomains, live hosts
- results/attack_surface/ - IPs, ports, ASNs
- results/ghost/ - Temporal recon findings
- results/scan/ - Nuclei, race conditions
- results/chains/ - Attack chains
- results/triage/ - AI-validated findings
- reports/ - Final Markdown + JSON reports

## Runtime

- Quick mode: 20-40 minutes
- Full mode: 60-120 minutes

## License

MIT License

---

**Version**: 3.0.0  
**Last Updated**: 2026-09-06  
**Status**: Production Ready