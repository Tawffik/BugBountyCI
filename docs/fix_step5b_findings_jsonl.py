#!/usr/bin/env python3
from pathlib import Path
p = Path(".github/workflows/zero-track-hunter.yml")
t = p.read_text()
assert "Final all.txt" in t
if "Canonical findings schema" in t:
    print("already")
    raise SystemExit(0)
key = "recon leads -> triage/triage.md"
idx = t.find(key)
if idx < 0:
    raise SystemExit("triage print missing")
start = t.rfind("print(", 0, idx)
end = t.find(")", idx) + 1
marker = t[start:end]
print("marker ok", len(marker))
insert = (
    "# Canonical findings schema\n"
    "          import hashlib\n"
    '          findings_path = os.path.join(rd, "triage", "findings.jsonl")\n'
    '          leads_path = os.path.join(rd, "triage", "leads.jsonl")\n'
    "          seen = set()\n"
    '          with open(findings_path, "w") as ff:\n'
    "              for rank, sev, cat, detail in confirmed:\n"
    '                  dedupe_key = hashlib.sha256(f"{cat}|{sev}|{detail}".encode("utf-8", errors="ignore")).hexdigest()[:16]\n'
    "                  if dedupe_key in seen: continue\n"
    "                  seen.add(dedupe_key)\n"
    '                  ff.write(json.dumps({"id": dedupe_key, "source": (cat.split()[0].lower() if cat else "unknown"), "type": cat, "severity": sev, "status": "confirmed", "confidence": "high" if sev in ("critical", "high") else "medium", "evidence": detail[:2000], "dedupe_key": dedupe_key}, ensure_ascii=False) + chr(10))\n'
    '          with open(leads_path, "w") as lf:\n'
    "              for cat, detail in leads:\n"
    '                  dedupe_key = hashlib.sha256(f"lead|{cat}|{detail}".encode("utf-8", errors="ignore")).hexdigest()[:16]\n'
    '                  lf.write(json.dumps({"id": dedupe_key, "source": "recon", "type": cat, "severity": "info", "status": "lead", "confidence": "low", "evidence": detail[:2000], "dedupe_key": dedupe_key}, ensure_ascii=False) + chr(10))\n'
    "          " + marker + "\n"
    '          print(f"Canonical findings: {len(seen)} -> triage/findings.jsonl")'
)
t = t[:start] + insert + t[end:]
if "id: triage" not in t:
    t = t.replace(
        'Triage & Prioritization"\n        if: always()',
        'Triage & Prioritization"\n        id: triage\n        if: always()',
        1,
    )
hq = "Hunter queue -> triage/hunter_queue.md"
i = t.find(hq)
j = t.find("PYEOF", i)
if i > 0 and j > 0 and "finding_count=$FC" not in t[j:j+400]:
    t = (
        t[:j]
        + "PYEOF\n"
        + '          if [ -f "results/${{ env.TIMESTAMP }}/triage/findings.jsonl" ]; then\n'
        + '            FC=$(wc -l < "results/${{ env.TIMESTAMP }}/triage/findings.jsonl" | tr -d " ")\n'
        + "          else\n"
        + "            FC=0\n"
        + "          fi\n"
        + '          echo "finding_count=$FC" >> "$GITHUB_OUTPUT"\n'
        + '          echo "finding_count=$FC (from triage/findings.jsonl)"\n'
        + t[j + 5 :]
    )
t = t.replace(
    "finding_count: ${{ steps.count_findings.outputs.finding_count }}",
    "finding_count: ${{ steps.triage.outputs.finding_count }}",
    1,
)
assert "Final all.txt" in t and "Canonical findings" in t
p.write_text(t)
print("OK", len(t.splitlines()))
