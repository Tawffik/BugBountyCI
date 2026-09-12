#!/usr/bin/env python3
from pathlib import Path
p = Path(".github/workflows/zero-track-hunter.yml")
t = p.read_text()
assert "Final all.txt" in t and "redact_secrets_for_llm" in t

# endpoints pure URL
if "endpoints_annotated.txt" not in t:
    mark = '> "$RD/ai_infra/endpoints_live.txt" || true'
    i = t.find(mark)
    if i < 0:
        raise SystemExit("endpoints mark missing")
    ls = t.rfind("\n", 0, i) + 1
    le = t.find("\n", i)
    exact = t[ls:le]
    pure = "          jq -r 'select(.status_code==200 or .status_code==401 or .status_code==403) | .url' \"$RD/ai_infra/endpoints.json\" 2>/dev/null | sort -u > \"$RD/ai_infra/endpoints_live.txt\" || true"
    ann = exact.replace("endpoints_live.txt", "endpoints_annotated.txt")
    t = t[:ls] + pure + "\n" + ann + t[le:]
    print("endpoints pure URL")

# ep_base for model probes
ai = t.find("AI Service Endpoint Discovery")
end = t.find("Prompt injection signals", ai)
if ai > 0 and end > ai and "ep_base=" not in t[ai:end]:
    sec = t[ai:end]
    sec = sec.replace(
        'ep="$(echo "$ep" | tr -d \'\\r\' | xargs)"; [ -z "$ep" ] && continue\n            models_resp=',
        'ep="$(echo "$ep" | tr -d \'\\r\' | xargs)"; [ -z "$ep" ] && continue\n'
        '            case "$ep" in http://*|https://*) ;; *) continue ;; esac\n'
        '            ep_base="$(echo "$ep" | sed -E \'s#(https?://[^/]+).*#\\1#\')"\n'
        '            models_resp=',
        1,
    )
    sec = sec.replace('"${ep}/v1/models"', '"${ep_base}/v1/models"', 1)
    sec = sec.replace('"${ep}/api/tags"', '"${ep_base}/api/tags"', 1)
    sec = sec.replace('"${ep}/v1/chat/completions"', '"${ep_base}/v1/chat/completions"')
    t = t[:ai] + sec + t[end:]
    print("ep_base")

# Phase2 scope filter
old = '          hvt=sorted(plan.get("high_value_targets",[]), key=lambda t: t.get("priority",99))'
if "_url_in_target_scope" not in t and old in t:
    new = '''          def _url_in_target_scope(u, tgt):
              try:
                  from urllib.parse import urlparse
                  if not u or not isinstance(u, str): return False
                  u = u.strip()
                  if not u.startswith("http"): return False
                  h = (urlparse(u).hostname or "").lower(); tgt = (tgt or "").lower()
                  return bool(h and tgt and (h == tgt or h.endswith("." + tgt)))
              except Exception:
                  return False
          _tgt = os.environ.get("TARGET", "")
          _raw = plan.get("high_value_targets", [])
          plan["high_value_targets"] = [x for x in _raw if isinstance(x, dict) and _url_in_target_scope(x.get("url", ""), _tgt)]
          for _ap in plan.get("attack_plan", []) or []:
              if isinstance(_ap, dict):
                  _ap["target_urls"] = [u for u in (_ap.get("target_urls") or []) if _url_in_target_scope(u, _tgt)]
          hvt=sorted(plan.get("high_value_targets",[]), key=lambda t: t.get("priority",99))'''
    t = t.replace(old, new, 1)
    print("phase2 scope")

# Phase1 plan filter before dump
idx = t.find('attack_plan.json"),"w") as f: json.dump(plan,f,indent=2)')
if idx > 0 and "_uis" not in t[max(0, idx - 600):idx]:
    insert = '''                  _tgt = os.environ.get("TARGET", "")
                  def _uis(u, tgt=_tgt):
                      try:
                          from urllib.parse import urlparse
                          if not u or not isinstance(u, str): return False
                          u=u.strip()
                          if not u.startswith("http"): return False
                          h=(urlparse(u).hostname or "").lower(); tgt=(tgt or "").lower()
                          return bool(h and tgt and (h==tgt or h.endswith("."+tgt)))
                      except Exception:
                          return False
                  if isinstance(plan, dict):
                      hv=plan.get("high_value_targets") or []
                      plan["high_value_targets"]=[x for x in hv if isinstance(x,dict) and _uis(x.get("url",""))]
                      for ap in (plan.get("attack_plan") or []):
                          if isinstance(ap, dict):
                              ap["target_urls"]=[u for u in (ap.get("target_urls") or []) if _uis(u)]
'''
    ls = t.rfind("\n", 0, idx) + 1
    t = t[:ls] + insert + t[ls:]
    print("phase1 plan filter")

assert "Final all.txt" in t and "redact_secrets_for_llm" in t
p.write_text(t)
print("step3 ok", len(t.splitlines()))
