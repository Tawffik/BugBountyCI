#!/usr/bin/env python3
import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import importlib.util
spec = importlib.util.spec_from_file_location("rd", ROOT / "scripts" / "representation_differential.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

def test_compare_same():
    b = {"status": 200, "content_type": "text/html", "fingerprint": "a", "json_keys": [], "error": None}
    a = {"status": 200, "content_type": "text/html", "fingerprint": "a", "json_keys": [], "error": None}
    d = mod.compare(b, a)
    assert d["kind"] == "SAME_REPRESENTATION"
    assert not d["meaningful"]
    print("  OK same")

def test_compare_meaningful_fields():
    b = {"status": 200, "content_type": "text/html", "fingerprint": "a", "json_keys": [], "error": None}
    a = {"status": 200, "content_type": "application/json", "fingerprint": "b",
         "json_keys": ["name", "email", "internal_role"], "error": None}
    d = mod.compare(b, a)
    assert d["meaningful"]
    assert "email" in d["sensitive_keys"] or d["kind"] == "MEANINGFUL_DIFFERENTIAL"
    print("  OK meaningful")

def test_select_rejects_static(tmp_path):
    rd = tmp_path / "results"
    (rd / "urls").mkdir(parents=True)
    (rd / "urls" / "all.txt").write_text(
        "https://x.example/api/v1/users\nhttps://x.example/static/app.js\nhttps://x.example/logo.png\n"
    )
    c = mod.select_candidates(str(rd), cap=10)
    assert any("/api/" in x["url"] for x in c)
    assert not any(x["url"].endswith(".js") for x in c)
    print("  OK select")

def test_hunter_filters(tmp_path):
    sys.path.insert(0, str(ROOT))
    from pipeline.detection.hunter_queue_builder import load_representation_diffs
    rd = tmp_path / "results"
    idir = rd / "info_disclosure"
    idir.mkdir(parents=True)
    rows = [
        {"outcome": "MEANINGFUL_DIFFERENTIAL", "url": "https://a/api", "differential": {"signals": ["x"], "sensitive_keys": ["email"]}, "evidence_ladder": "CANDIDATE", "next_pivot": "manual"},
        {"outcome": "NO_DIFFERENTIAL", "url": "https://a/b"},
        {"outcome": "NOT_RUN", "url": "https://a/c"},
    ]
    (idir / "representation_diffs.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    e = load_representation_diffs(str(rd))
    assert len(e) == 1
    assert e[0]["engine"] == "representation_differential"
    print("  OK hunter")

if __name__ == "__main__":
    import tempfile
    test_compare_same()
    test_compare_meaningful_fields()
    with tempfile.TemporaryDirectory() as td:
        test_select_rejects_static(Path(td))
    with tempfile.TemporaryDirectory() as td:
        test_hunter_filters(Path(td))

def test_out_of_scope_rejected(tmp_path):
    rd = tmp_path / "results"
    (rd / "urls").mkdir(parents=True)
    (rd / "live").mkdir(parents=True)
    (rd / "live" / "live.txt").write_text("https://nuva.finance\n")
    (rd / "urls" / "all.txt").write_text(
        "https://nuva.finance/api/v1/users\n"
        "https://www.google.com/url?q=x\n"
        "https://evil.com/api/secret\n"
    )
    c = mod.select_candidates(str(rd), cap=20, target="nuva.finance")
    urls = [x["url"] for x in c]
    assert all("nuva.finance" in u for u in urls)
    assert not any("google" in u or "evil" in u for u in urls)
    print("  OK scope")

if __name__ == "__main__":
    import tempfile
    test_compare_same()
    test_compare_meaningful_fields()
    with tempfile.TemporaryDirectory() as td:
        test_select_rejects_static(Path(td))
    with tempfile.TemporaryDirectory() as td:
        test_hunter_filters(Path(td))
    with tempfile.TemporaryDirectory() as td:
        test_out_of_scope_rejected(Path(td))
    print("all passed")
