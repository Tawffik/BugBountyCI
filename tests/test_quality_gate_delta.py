import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import build_quality_gate as qg
import build_delta_hunter as dh


def test_quality_gate_blocks_on_critical_error(tmp_path: Path):
    rd = tmp_path / "r"
    (rd / "meta" / "phases").mkdir(parents=True)
    (rd / "meta" / "phases" / "live_probe.json").write_text(
        json.dumps({"phase": "live_probe", "status": "error", "detail": "boom"})
    )
    (rd / "meta" / "engine_health.json").write_text(json.dumps({"overall": "DEGRADED"}))
    (rd / "meta" / "url_sources_health.json").write_text(json.dumps({"sources": {}}))
    report = qg.build(rd)
    assert report["verdict"] == "BLOCKED"
    assert report["blocks_clean"] is True


def test_quality_gate_passive_failed_not_blocked(tmp_path: Path):
    rd = tmp_path / "r"
    (rd / "meta" / "phases").mkdir(parents=True)
    (rd / "meta" / "url_sources_health.json").write_text(
        json.dumps(
            {
                "sources": {
                    "waymore": {"status": "SOURCE_FAILED", "detail": "provider_connection_error"}
                }
            }
        )
    )
    (rd / "meta" / "funnel_gate.json").write_text(json.dumps({"verdict": "FUNNEL_OK"}))
    report = qg.build(rd)
    assert report["verdict"] == "DEGRADED_SOURCES"
    assert report["blocks_clean"] is False


def test_delta_not_available(tmp_path: Path):
    rd = tmp_path / "r"
    rd.mkdir()
    report = dh.build(rd, None)
    assert report["status"] == "NOT_AVAILABLE"


def test_delta_added_hosts(tmp_path: Path):
    curr, prev = tmp_path / "c", tmp_path / "p"
    for d in (curr, prev):
        (d / "subdomains").mkdir(parents=True)
        (d / "urls").mkdir(parents=True)
    (prev / "subdomains" / "resolved.txt").write_text("a.example.com\n")
    (curr / "subdomains" / "resolved.txt").write_text("a.example.com\nb.example.com\n")
    (prev / "urls" / "all.txt").write_text("https://a.example.com/\n")
    (curr / "urls" / "all.txt").write_text("https://a.example.com/\nhttps://b.example.com/x\n")
    report = dh.build(curr, prev)
    assert report["status"] == "OK"
    assert report["counts"]["hosts_added"] == 1
    assert "b.example.com" in report["added_hosts"]
    assert report["counts"]["urls_added"] == 1


def test_evidence_graph_counts(tmp_path: Path):
    import build_evidence_graph_surface as eg
    rd = tmp_path / "r"
    (rd / "meta").mkdir(parents=True)
    lines = [
        json.dumps({"type": "JS_TO_ENDPOINT", "from": "js:a", "to": "url:/x"}),
        json.dumps({"type": "JS_TO_ENDPOINT", "from": "js:b", "to": "url:/y"}),
        json.dumps({"type": "HOST_HAS_URL", "from": "host:h", "to": "url:/"}),
    ]
    (rd / "meta" / "relationships.jsonl").write_text("\n".join(lines) + "\n")
    report = eg.build(rd)
    assert report["status"] == "OK"
    assert report["total"] == 3
    assert report["counts_by_type"]["JS_TO_ENDPOINT"] == 2


def test_opportunity_prefers_blocked_quality(tmp_path: Path):
    import build_opportunity_board as ob
    rd = tmp_path / "r"
    (rd / "meta").mkdir(parents=True)
    (rd / "meta" / "quality_gate.json").write_text(
        json.dumps({"verdict": "BLOCKED", "operator": "fix phases"})
    )
    report = ob.build(rd)
    assert report["items"]
    assert report["items"][0]["kind"] == "integrity"
