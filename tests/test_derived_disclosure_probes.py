from pathlib import Path
import tempfile
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from run_derived_disclosure_probes import candidates_from_js, candidates_from_paths


def test_js_map_candidates():
    with tempfile.TemporaryDirectory() as td:
        rd = Path(td)
        (rd / "js").mkdir()
        (rd / "js" / "files.txt").write_text(
            "https://cdn.example.com/static/app.js\n"
            "https://cdn.example.com/static/app.js.map\n"
            "https://cdn.example.com/x.css\n"
        )
        c = candidates_from_js(rd, 10)
        assert any(u.endswith(".js.map") for u, k in c if k == "source_map")
        assert not any(u.endswith(".js.map.map") for u, _ in c)


def test_backup_siblings_from_endpoints():
    with tempfile.TemporaryDirectory() as td:
        rd = Path(td)
        (rd / "js").mkdir()
        (rd / "live").mkdir()
        (rd / "js" / "endpoints.txt").write_text("https://app.example.com/api/config\n")
        (rd / "live" / "hostname_targets.txt").write_text("https://app.example.com/\n")
        c = candidates_from_paths(rd, 20)
        assert any(u.endswith(".bak") for u, k in c if k == "backup_sibling")
