from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_exposure_queue import collect  # noqa: E402


def test_env_ranks_high(tmp_path: Path) -> None:
    (tmp_path / "info_disclosure").mkdir()
    (tmp_path / "info_disclosure" / "config_files.txt").write_text(
        "https://app.example/.env\nhttps://app.example/robots.txt\n"
    )
    (tmp_path / "js").mkdir()
    (tmp_path / "js" / "github_recon.txt").write_text(
        "https://github.com/someone/demo README mention example.com\n"
    )
    items = collect(tmp_path)
    assert items
    assert items[0]["path"].endswith(".env") or ".env" in items[0]["path"]
