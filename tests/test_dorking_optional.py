import json
import tempfile
from pathlib import Path
import subprocess


def test_dorking_not_configured():
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "dorking"
        subprocess.check_call(
            ["python3", str(root / "scripts" / "run_dorking_optional.py"), "--target", "example.com", "--output", str(out), "--token", ""],
            cwd=str(root),
        )
        s = json.loads((out / "summary.json").read_text())
        assert s["provider_status"] == "NOT_CONFIGURED"
