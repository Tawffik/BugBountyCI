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


def test_vocabulary_word_map_shape_does_not_crash(tmp_path):
    """Live #120 shape: smart-fuzzing vocabulary is {word: count}, and may include a key named terms."""
    import json, subprocess, sys
    rd = tmp_path / "results"
    for d in ["meta/phases", "live", "urls", "smart-fuzzing", "detection", "js_deep", "js"]:
        (rd / d).mkdir(parents=True, exist_ok=True)
    (rd / "meta/phases/port_scan.json").write_text(json.dumps({"phase": "port_scan", "status": "OK"}))
    (rd / "live/live.txt").write_text("https://example.com\n")
    (rd / "urls/all.txt").write_text("https://example.com/a\n")
    # Critical: key literally named "terms" must not be treated as schema list
    vocab = {"api": 5, "export": 3, "terms": 1, "booking": 2}
    (rd / "smart-fuzzing/vocabulary.json").write_text(json.dumps(vocab))
    (rd / "smart-fuzzing/response_diffs.json").write_text("[]")
    r = subprocess.run([sys.executable, "scripts/write_pipeline_exports.py", str(rd)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    out = json.loads((rd / "meta/vocabulary.json").read_text())
    terms = out.get("terms") or []
    assert len(terms) >= 3, terms
    names = {x.get("term") for x in terms}
    assert "api" in names and "export" in names
    assert (rd / "meta/recon_export.json").is_file()
    assert (rd / "meta/relationships.jsonl").is_file()
