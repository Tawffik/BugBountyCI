#!/usr/bin/env python3
from pathlib import Path
p = Path(".github/workflows/zero-track-hunter.yml")
t = p.read_text()
assert "Final all.txt" in t and "PLACEHOLDER" not in t
if "redact_secrets_for_llm" in t:
    print("already"); raise SystemExit(0)
m = 'live=rf("live/live.txt"); urls=top_param_urls("urls/all.txt"); sec=rf("js/secrets.txt",2000);'
if m not in t:
    raise SystemExit("sec marker missing")
helper = (
    "def redact_secrets_for_llm(path, cap_lines=80, cap_chars=2500):\n"
    "              import hashlib, re as _re\n"
    "              out = []\n"
    "              try:\n"
    "                  with open(os.path.join(rd, path), errors=\"ignore\") as f:\n"
    "                      for line in f:\n"
    "                          line = line.strip()\n"
    "                          if not line: continue\n"
    "                          label = \"SECRET\"\n"
    "                          if line.startswith(\"[\") and \"]\" in line:\n"
    "                              label = line[1:line.index(\"]\")]\n"
    "                              rest = line[line.index(\"]\")+1:].strip()\n"
    "                          else:\n"
    "                              rest = line\n"
    "                          fp = hashlib.sha256(rest.encode(\"utf-8\", errors=\"ignore\")).hexdigest()[:12]\n"
    "                          rest_safe = _re.sub(r\"[A-Za-z0-9_\\\\-/+=]{16,}\", \"[REDACTED]\", rest)[:80]\n"
    "                          out.append(f\"[{label}_REDACTED sha256={fp}] {rest_safe}\")\n"
    "                          if len(out) >= cap_lines: break\n"
    "              except Exception:\n"
    "                  return \"N/A\"\n"
    "              return \"\\n\".join(out)[:cap_chars] if out else \"N/A\"\n"
    "          live=rf(\"live/live.txt\"); urls=top_param_urls(\"urls/all.txt\"); sec=redact_secrets_for_llm(\"js/secrets.txt\");"
)
t = t.replace(m, helper, 1)
t = t.replace(
    'secretfinder=rf("js_deep/secretfinder_secrets.txt",400)',
    'secretfinder="[REDACTED - local only; not sent to LLM]"',
    1,
)
assert "redact_secrets_for_llm" in t and "Final all.txt" in t
p.write_text(t)
print("step2 ok", len(t.splitlines()))
