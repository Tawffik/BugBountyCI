#!/usr/bin/env python3
"""Apply github_recon phase JSON + health-sync call to zero-track-hunter.yml.

Idempotent. From repo root after this PR is merged:

  python3 scripts/apply_github_recon_health_fix.py
  git add .github/workflows/zero-track-hunter.yml
  git commit -m "fix(workflow): valid github_recon phase JSON + health MD sync"
  git push

Verified offline against main zero-track-hunter.yml (2026-10-21).
"""
from __future__ import annotations

from pathlib import Path

WF = Path(".github/workflows/zero-track-hunter.yml")

# Exact lines as stored on main (broken shell quoting that produced invalid JSON on #167)
OLD1 = (
    '              echo "{"phase":"github_recon","status":"OK",'
    '"detail":"raw=${raw_n} kept=${kept_n}"}" > "$RD/meta/phases/github_recon.json"'
)
# Single-line form must match file exactly:
OLD1 = '              echo "{"phase":"github_recon","status":"OK","detail":"raw=${raw_n} kept=${kept_n}"}" > "$RD/meta/phases/github_recon.json"'
NEW1 = (
    "              printf '%s\\n' "
    '"{\\"phase\\":\\"github_recon\\",\\"status\\":\\"OK\\",'
    '\\"detail\\":\\"raw=${raw_n} kept=${kept_n}\\"}" '
    '> "$RD/meta/phases/github_recon.json"'
)
# Prefer the form verified offline:
NEW1 = (
    r"              printf '%s\n' "
    r'"{\"phase\":\"github_recon\",\"status\":\"OK\",'
    r'\"detail\":\"raw=${raw_n} kept=${kept_n}\"}" '
    r'> "$RD/meta/phases/github_recon.json"'
)

OLD2 = '              echo "{"phase":"github_recon","status":"EMPTY","detail":"domain-scoped search returned 0 raw hits"}" > "$RD/meta/phases/github_recon.json"'
NEW2 = (
    r"              printf '%s\n' "
    r"'{\"phase\":\"github_recon\",\"status\":\"EMPTY_VALID\","
    r"\"detail\":\"domain-scoped search returned 0 raw hits\"}' "
    r'> "$RD/meta/phases/github_recon.json"'
)

ANCHOR = (
    '          [ -f scripts/validate_pipeline_exports.py ] && '
    'python3 scripts/validate_pipeline_exports.py "results/${{ env.TIMESTAMP }}" || true\n'
    '          # Rebuild Hunter AFTER relationships/endpoints export so RESEARCH_CONTEXT'
)
INSERT = (
    '          [ -f scripts/validate_pipeline_exports.py ] && '
    'python3 scripts/validate_pipeline_exports.py "results/${{ env.TIMESTAMP }}" || true\n'
    '          # Sync pipeline_health.md Overall with engine_health.overall '
    '(MD must not look healthier than JSON)\n'
    '          [ -f scripts/sync_pipeline_health_md.py ] && '
    'python3 scripts/sync_pipeline_health_md.py "results/${{ env.TIMESTAMP }}" || true\n'
    '          # Rebuild Hunter AFTER relationships/endpoints export so RESEARCH_CONTEXT'
)


def main() -> int:
    if not WF.is_file():
        print(f"missing {WF}")
        return 2
    text = WF.read_text(encoding="utf-8")
    changed = False
    if OLD1 in text:
        text = text.replace(OLD1, NEW1, 1)
        changed = True
        print("patched OK phase JSON")
    if OLD2 in text:
        text = text.replace(OLD2, NEW2, 1)
        changed = True
        print("patched EMPTY->EMPTY_VALID phase JSON")
    if ANCHOR in text:
        text = text.replace(ANCHOR, INSERT, 1)
        changed = True
        print("patched health-sync call")
    elif "sync_pipeline_health_md.py" in text:
        print("health-sync already present")
    if changed:
        WF.write_text(text, encoding="utf-8")
        print(f"wrote {WF} ({len(text)} bytes)")
    else:
        print("no changes needed (already applied or patterns missing)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
