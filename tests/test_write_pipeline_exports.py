"""Contract test for scripts/write_pipeline_exports.py"""
import json, os, subprocess, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "write_pipeline_exports.py"

def test_exports_contract():
    base = Path(tempfile.mkdtemp())
    rd = base / "results" / "t1"
    for d in ["meta/phases", "live", "subdomains", "urls", "targeted", "nuclei", "smart-fuzzing", "detection"]:
        (rd / d).mkdir(parents=True, exist_ok=True)
    (rd / "meta/phases/port_scan.json").write_text('{"phase":"port_scan","status":"OK"}\n')
    (rd / "live/live.txt").write_text("https://a.example.com\n")
    (rd / "live/ports.txt").write_text("1.1.1.1:443\n")
    (rd / "subdomains/resolved.txt").write_text("a.example.com\n")
    (rd / "urls/all.txt").write_text("https://a.example.com/x\n")
    (rd / "targeted/arjun_params.txt").write_text("")
    (rd / "nuclei/findings.jsonl").write_text("")
    (rd / "smart-fuzzing/vocabulary.json").write_text(json.dumps({"invoice": {"sources": ["url", "js"], "count": 2}}))
    (rd / "detection/parameter_intelligence.json").write_text(json.dumps({"endpoints": [{"path": "/x", "parameters": [{"name": "q"}]}]}))
    env = {**os.environ, "TIMESTAMP": "t1", "TARGET": "example.com"}
    subprocess.check_call(["python3", str(SCRIPT)], cwd=str(base), env=env)
    meta = rd / "meta"
    for name in [
        "engine_health.json", "target_profile.json", "hosts.jsonl", "observations.jsonl",
        "urls.jsonl", "endpoints.jsonl", "parameters.jsonl", "vocabulary.json", "relationships.jsonl", "response_clusters.json", "recon_export.json",
    ]:
        assert (meta / name).exists(), name
    v = json.loads((meta / "vocabulary.json").read_text())
    assert v["schema"] == "bugbountyci.vocabulary.v1"
    assert any(t["term"] == "invoice" for t in v["terms"])
