# Architecture Documentation

## Overview

BugBountyCI v2.0 is a modular bug bounty automation system.

## Design Principles

1. Modularity: Each functionality is encapsulated in its own module
2. Separation of Concerns: Clear separation between recon, scan, chain analysis, and reporting
3. Innovation: Ghost Layer discovers attack surface others miss
4. Maintainability: Easy to understand, modify, and extend
5. Automation: Full pipeline automation via GitHub Actions

## Module Structure

### Reconnaissance Layer (modules/recon/)

Purpose: Discover attack surface

Modules:
- 01_subdomain.py: Subdomain enumeration using subfinder, amass, crt.sh
- 02_live_probe.py: Live host probing with httpx
- 03_temporal.py: Ghost Layer - Historical endpoint discovery
- 04_param_ghost.py: Ghost Layer - Parameter mining from old versions
- 05_js_deep.py: Ghost Layer - Deep JavaScript analysis

### Scanning Layer (modules/scan/)

Purpose: Identify vulnerabilities

Modules:
- 01_nuclei.py: Vulnerability scanning with nuclei
- 02_race.py: Race condition detection

### Chain Analysis Layer (modules/chain/)

Purpose: Correlate findings into attack chains

Modules:
- correlate.py: AI-powered attack chain identification

### Reporting Layer (modules/report/)

Purpose: Generate professional reports

Modules:
- generate.py: Multi-format report generation

## Ghost Layer Innovation

The Ghost Layer is what makes this system unique:

### Temporal Recon

Problem: Developers remove features from frontend but backend still works
Solution: Query historical sources (Wayback, CommonCrawl, URLScan) to find old endpoints
Impact: Discover forgotten admin panels, old API versions, debug endpoints

### Parameter Ghost Mining

Problem: Parameters removed from frontend may still work in backend
Solution: Extract parameters from historical URLs, compare with current site
Impact: Find hidden parameters like debug=true, admin=one, internal=true

### JS Deep Mining

Problem: Simple URL extraction misses API patterns and secrets
Solution: Deep JavaScript analysis for patterns, auth flows, secrets
Impact: Discover API keys, tokens, internal endpoints, authentication flows

## Workflow Architecture

### recon.yml
Lightweight reconnaissance workflow
Runs subdomain enum, live probing, Ghost Layer

### scan.yml
Vulnerability scanning workflow
Runs nuclei, race condition detection

### hunt.yml
Full orchestrator workflow
Calls recon.yml, then scan.yml
Runs chain correlation
Generates final report

## Extensibility

Adding a New Module:
1. Create modules/XX_module_name.py
2. Implement main() function
3. Add to workflow
4. Update documentation

## Performance Considerations

- Parallelization: Use asyncio for concurrent requests
- Rate Limiting: Respect target rate limits
- Caching: Cache tool installations
- Timeouts: Set appropriate timeouts for each tool