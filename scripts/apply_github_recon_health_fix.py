#!/usr/bin/env python3
"""Apply github_recon phase JSON + health-sync call to zero-track-hunter.yml.

Idempotent. Run from repo root:
  python3 scripts/apply_github_recon_health_fix.py
"""
from __future__ import annotations
from pathlib import Path

WF = Path(".github/workflows/zero-track-hunter.yml")

OLD1 = '              echo "{"phase":"github_recon","status":"OK","detail":"raw=${raw_n} kept=${kept_n}"}" > "$RD/meta/phases/github_recon.json"'
NEW1 = '              printf \'%s\\n\' "{\\"phase\\":\\"github_recon\\",\\"status\\":\\"OK\\",\\"detail\\":\\"raw=${raw_n} kept=${kept_n}\\"}" > "$RD/meta/phases/github_recon.json"'

OLD2 = '              echo "{"phase":"github_recon","status":"EMPTY","detail":"domain-scoped search returned 0 raw hits"}" > "$RD/meta/phases/github_recon.json"'
NEW2 = '              printf \'%s\\n\' \'{"phase":"github_recon","status":"EMPTY_VALID","detail":"domain-scoped search returned 0 raw hits"}\' > "$RD/meta/phases/github_recon.json"'

ANCHOR = (
    '          [ -f scripts/validate_pipeline_exports.py ] && python3 scripts/validate_pipeline_exports.py "results/${{ env.TIMESTAMP }}" || true\n'
    '          # Rebuild Hunter AFTER relationships/endpoints export so RESEARCH_CONTEXT'
)
INSERT = (
    '          [ -f scripts/validate_pipeline_exports.py ] && python3 scripts/validate_pipeline_exports.py "results/${{ env.TIMESTAMP }}" || true\n'
    '          # Sync pipeline_health.md Overall with engine_health.overall (MD must not look healthier than JSON)\n'
    '          [ -f scripts/sync_pipeline_health_md.py ] && python3 scripts/sync_pipeline_health_md.py "results/${{ env.TIMESTAMP }}" || true\n'
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
    elif "EMPTY_VALID" in text and "github_recon" in text:
        print("phase JSON patterns already addressed or OK path missing")
    if OLD2 in text:
        text = text.replace(OLD2, NEW2, 1)
        changed = True
        print("patched EMPTY\u2192EMPTY_VALID phase JSON")
    elif "EMPTY_VALID" in text:
        print("EMPTY_VALID already present")
    if ANCHOR in text:
        text = text.replace(ANCHOR, INSERT, 1)
        changed = True
        print("patched health-sync call")
    elif "sync_pipeline_health_md.py" in text:
        print("health-sync call already present")
    if changed:
        WF.write_text(text, encoding="utf-8")
        print(f"wrote {WF}")
    else:
        print("no changes needed")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
