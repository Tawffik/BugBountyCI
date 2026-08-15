# PIPELINE_MANIFEST.md

Auto-generated reference — regenerate after structural edits.

## 0. 📥 Checkout Repository  _(uses: actions/checkout@v4)_
## 1. 🔧 Verify Toolchain
- if: `-`  timeout: -m

## 2. ⚡ Setup Go  _(uses: actions/setup-go@v5)_
## 3. 🐍 Setup Python  _(uses: actions/setup-python@v5)_
## 4. 🔒 Verify Target Is In Authorized Scope
- if: `-`  timeout: -m

## 5. ✅ Environment Validation
- if: `-`  timeout: -m

## 6. 🧅 Setup Tor Proxy (Free WAF Bypass)
- if: `-`  timeout: 12m

## 7. 📦 Install System Dependencies
- if: `-`  timeout: -m

## 8. 🩺 Target Health Check
- if: `-`  timeout: 2m

## 9. 🗄️ Cache Go Toolchain  _(uses: actions/cache@v4)_
## 10. 📦 Install Go Tools
- if: `-`  timeout: -m

## 11. 📦 Install Python Packages
- if: `-`  timeout: -m

## 12. ✅ Verify Tools
- if: `-`  timeout: -m

## 13. 🔄 Check For Newer Tool Versions
- if: `-`  timeout: -m

## 14. 📦 Update Nuclei Templates
- if: `-`  timeout: -m

## 15. 📂 Create Results Directory
- if: `-`  timeout: -m

## 16. 🗄️ Restore Previous Scan Snapshot (Diff Mode)  _(uses: actions/cache/restore@v4)_
## 17. 🌐 Subdomain Enumeration
- if: `-`  timeout: 18m
- **writes**: logs/alterx.log, logs/amass.log, logs/assetfinder.log, logs/dnsx.log, logs/subfinder.log, meta/scan_health_warning.txt, subdomains/all_subs.txt, subdomains/amass.txt, subdomains/assetfinder.txt, subdomains/crtsh.txt, subdomains/dns_brute.txt, subdomains/permutations_resolved.txt, subdomains/resolved.txt, subdomains/subfinder.txt

## 18. 🌐 ASN/CIDR Discovery
- if: `-`  timeout: 5m
- **writes**: logs/asnmap.log, logs/naabu.log, meta/asn_skipped_reason.txt, meta/asn_source.txt, subdomains/asn_ips.txt

## 19. 🏚️ Subdomain Takeover Check
- if: `-`  timeout: 8m
- **writes**: logs/takeover.log, nuclei/takeover.json
- **reads**: subdomains/all_subs.txt

## 20. 🌍 Live Host Probing & Fingerprinting
- if: `-`  timeout: 12m
- **writes**: live/live.json, live/live.txt, live/tech.json, live/waf.txt, logs/fingerprint.log, logs/httpx.log, meta/scan_health_warning.txt
- **reads**: subdomains/all_subs.txt, subdomains/asn_ips.txt

## 21. 🛡️ WAF Bypass Recon & Header Rotation
- if: `${{ env.ENABLE_WAF_BYPASS == 'true' }}`  timeout: 15m
- **writes**: waf_bypass/bypass_results.txt, waf_bypass/path_bypass.txt, waf_bypass/waf_fingerprint.txt
- **reads**: live/live.txt

## 22. 🔓 Port Scanning
- if: `-`  timeout: 12m
- **writes**: live/live.txt, live/nonstandard_live.txt, live/ports.txt, logs/httpx.log, logs/naabu.log
- **reads**: subdomains/all_subs.txt

## 23. 📜 URL Collection
- if: `-`  timeout: 18m
- **writes**: live/live.txt, logs/gau.log, logs/hakrawler.log, logs/katana.log, logs/wayback.log, urls/all.txt, urls/gau.txt, urls/gf_categorized.txt, urls/hakrawler.txt, urls/katana.txt, urls/robots_sitemap.txt, urls/wayback.txt
- **reads**: subdomains/all_subs.txt

## 24. 📦 JavaScript Analysis
- if: `-`  timeout: 12m
- **writes**: js/api_endpoints.txt, js/files.txt, js/files_discovered.txt, js/idor_candidates.txt, js/secrets.txt, logs/js_download.log
- **reads**: urls/all.txt

## 25. 🧬 JS Deep Extraction (LinkFinder + Mantra + Cariddi + TruffleHog + Gitleaks)
- if: `-`  timeout: 20m
- **writes**: js/files.txt, js_deep/cariddi_findings.txt, js_deep/gitleaks_findings.json, js_deep/linkfinder_endpoints.txt, js_deep/mantra_findings.txt, js_deep/secretfinder_secrets.txt, js_deep/trufflehog_findings.json, live/live.txt, logs/cariddi.log, logs/gitleaks.log, logs/linkfinder.log, logs/mantra.log, logs/secretfinder.log, logs/trufflehog.log

## 26. 🎯 Targeted Vulnerability Scanners (Dalfox + Corsy + wafw00f + Subzy + CRLFuzz + Arjun)
- if: `-`  timeout: 25m
- **writes**: live/live.txt, logs/arjun.log, logs/corsy.log, logs/crlfuzz.log, logs/dalfox.log, logs/subzy.log, logs/wafw00f.log, subdomains/all_subs.txt, targeted/arjun_params.txt, targeted/corsy_findings.txt, targeted/crlfuzz_findings.txt, targeted/dalfox_xss.txt, targeted/subzy_takeover.txt, targeted/wafw00f_findings.json
- **reads**: urls/gf_categorized.txt

## 27. 🔓 Information Disclosure Scan (Git, Backups, Configs)
- if: `${{ env.ENABLE_GIT_EXPOSURE == 'true' }}`  timeout: 15m
- **writes**: info_disclosure/backup_files.txt, info_disclosure/config_files.txt, info_disclosure/dir_listing.txt, info_disclosure/error_disclosure.txt, info_disclosure/git_exposure.txt
- **reads**: live/live.txt

## 28. 🗺️ Source Map Analysis
- if: `${{ env.ENABLE_SOURCE_MAPS == 'true' }}`  timeout: 10m
- **writes**: source_maps/endpoints.txt, source_maps/found.txt, source_maps/secrets.txt
- **reads**: js/files.txt

## 29. 🤖 AI Infrastructure Reconnaissance (Strix Methodology)
- if: `-`  timeout: 12m
- **writes**: ai_infra/admin_panels.txt, ai_infra/endpoints.json, ai_infra/endpoints_live.txt, ai_infra/models.txt, ai_infra/prompt_injection.txt, ai_infra/summary.md, ai_infra/supply_chain.txt, logs/ai_infra.log
- **reads**: js/files.txt, live/live.txt

## 30. 🕵️ Extended Recon (GitHub / VHosts / Cloud Storage)
- if: `-`  timeout: 8m
- **writes**: js/github_recon.txt, live/cloud_buckets.txt, live/vhosts.txt
- **reads**: live/live.txt

## 31. 🌩️ Cloud Origin Discovery (CloudFail + CloakQuest3r)
- if: `-`  timeout: 8m
- **writes**: cloud/cloakquest.txt, cloud/cloudfail.txt, logs/cloud.log

## 32. 🎯 Direct-to-Origin WAF Bypass (verify discovered IPs)
- if: `${{ env.ENABLE_WAF_BYPASS == 'true' }}`  timeout: 10m
- **writes**: waf_bypass/origin_bypass.txt
- **reads**: cloud/cloakquest.txt, cloud/cloudfail.txt

## 33. 🔎 Content Discovery Fuzzing
- if: `-`  timeout: 20m
- **writes**: fuzzing/discovered.txt, logs/ffuf.log
- **reads**: live/live.txt

## 34. 🔌 API Discovery
- if: `-`  timeout: 10m
- **writes**: js/admin.txt, js/graphql.txt, js/swagger.txt, logs/admin.log
- **reads**: live/live.txt

## 35. 🛡️ Security Analysis
- if: `-`  timeout: 10m
- **writes**: cors/vulnerable.txt, files/sensitive.txt
- **reads**: live/live.txt

## 36. 🔌 CMS Fingerprint (WordPress)
- if: `-`  timeout: 8m
- **writes**: files/cms_findings.txt, logs/wpscan.log
- **reads**: live/tech.json

## 37. 📸 Screenshots
- if: `-`  timeout: 18m
- **writes**: logs/gowitness.log
- **reads**: live/live.txt, screenshots/index.csv

## 38. ☢️ Nuclei Vulnerability Scan
- if: `-`  timeout: 75m
- **writes**: logs/nuclei.log, nuclei/findings.json, nuclei/findings_exposure.json, nuclei/findings_tech.json
- **reads**: live/live.txt, live/tech.json

## 39. 🩹 Nikto Scan
- if: `-`  timeout: 18m
- **writes**: logs/nikto.log, nuclei/nikto_findings.txt
- **reads**: live/live.txt

## 40. 🔭 OOB Setup (Interactsh)
- if: `-`  timeout: 2m

## 41. 🧠 AI Agent Phase 1: Target Intelligence
- if: `-`  timeout: 5m

## 42. ☢️ AI Agent Phase 2: Payload Injection
- if: `-`  timeout: 20m

## 43. 🔍 AI Agent Phase 3: XXE Check
- if: `-`  timeout: 8m

## 44. 🕷️ AI Agent Phase 4: GraphQL Attacks
- if: `-`  timeout: 8m

## 45. 🔄 AI Agent Phase 5: IDOR Testing
- if: `-`  timeout: 10m

## 46. 🔭 OOB Check (Interactsh)
- if: `-`  timeout: 2m
- **writes**: ai_agent/oob_findings.txt

## 47. 🧬 AI Agent Phase 6: Chain Analysis
- if: `-`  timeout: 5m

## 48. 📋 AI Final Security Report
- if: `-`  timeout: 8m
- **reads**: live/live.json, logs/nuclei.log

## 49. 🔢 Count Total Findings
- if: `always()`  timeout: -m
- **reads**: ai_agent/graphql_findings.txt, ai_agent/idor_findings.txt, ai_agent/injection_findings.txt, ai_agent/xxe_findings.txt, ai_infra/admin_panels.txt, ai_infra/endpoints_live.txt, ai_infra/models.txt, ai_infra/prompt_injection.txt, ai_infra/supply_chain.txt, cloud/cloakquest.txt, cloud/cloudfail.txt, cors/vulnerable.txt, files/sensitive.txt, fuzzing/discovered.txt, js/github_recon.txt, live/cloud_buckets.txt, live/vhosts.txt, nuclei/findings.json

## 50. 🆚 Diff Against Previous Scan
- if: `-`  timeout: 3m
- **writes**: diff/diff.md
- **reads**: live/live.txt, subdomains/all_subs.txt, urls/all.txt

## 51. 💾 Save Current Scan Snapshot
- if: `-`  timeout: -m
- **reads**: live/live.txt, subdomains/all_subs.txt, subdomains/asn_ips.txt, urls/all.txt

## 52. 💾 Save Snapshot Cache  _(uses: actions/cache/save@v4)_
## 53. 🏥 Pipeline Health Report
- if: `always()`  timeout: 3m

## 54. 📋 Triage & Prioritization
- if: `always()`  timeout: 3m

## 55. 🔑 Manual Follow-up Commands (credential/SQLi candidates)
- if: `-`  timeout: 3m
- **reads**: ai_agent/injection_findings.txt, js/admin.txt, manual_followup/commands.md, urls/gf_categorized.txt

## 56. 📄 Professional Report Export
- if: `always()`  timeout: 3m

## 57. 📦 Upload Toolchain Artifact  _(uses: actions/upload-artifact@v4)_
## 58. 📤 Upload Results Artifact  _(uses: actions/upload-artifact@v4)_
## 59. 📣 Discord Notification
- if: `${{ always() && inputs.discord_notify == true && env.DISCORD_WEBHOOK != '' }}`  timeout: 3m
- **reads**: ai_agent/graphql_findings.txt, ai_agent/idor_findings.txt, ai_agent/injection_findings.txt, ai_agent/xxe_findings.txt, cors/vulnerable.txt, files/sensitive.txt, info_disclosure/backup_files.txt, info_disclosure/config_files.txt, info_disclosure/git_exposure.txt, live/live.txt, nuclei/findings.json, source_maps/found.txt, subdomains/all_subs.txt, waf_bypass/bypass_results.txt
