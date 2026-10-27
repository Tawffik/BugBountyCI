import json
import tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.build_disclosure_desk import build, render_md, main
import subprocess


def test_desk_always_writes_with_empty_tree():
    with tempfile.TemporaryDirectory() as td:
        rd = Path(td)
        report = build(rd)
        md = render_md(report)
        assert "DISCLOSURE_DESK" in md
        assert report["schema"].startswith("bugbountyci.disclosure_desk")


def test_desk_includes_secrets_and_path_hits():
    with tempfile.TemporaryDirectory() as td:
        rd = Path(td)
        (rd / "js").mkdir()
        (rd / "info_disclosure").mkdir()
        (rd / "js" / "secrets_high.txt").write_text("AKIAEXAMPLEKEYDATA1234567890\n")
        (rd / "info_disclosure" / "git_exposure.txt").write_text("[GIT] https://x/.git/HEAD\n")
        report = build(rd)
        assert report["sections"]["secrets"]["secrets_high_count"] == 1
        assert report["sections"]["path_probes"]["total_hits"] >= 1
        md = render_md(report)
        assert "secrets_high" in md.lower() or "Secrets" in md


def test_cli_writes_files():
    with tempfile.TemporaryDirectory() as td:
        rd = Path(td)
        (rd / "js").mkdir(parents=True)
        (rd / "js" / "endpoints.txt").write_text("/api/v1\n")
        subprocess.check_call(
            ["python3", "scripts/build_disclosure_desk.py", "--results-dir", str(rd)],
            cwd=str(Path(__file__).resolve().parents[1]),
        )
        assert (rd / "triage" / "DISCLOSURE_DESK.md").is_file()
        assert (rd / "meta" / "disclosure_desk.json").is_file()
        assert (rd / "triage" / "DISCLOSURE_DESK.md").stat().st_size > 50
