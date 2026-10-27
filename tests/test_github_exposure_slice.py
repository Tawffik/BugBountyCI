import json
import tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from run_github_exposure_slice import in_scope_url, load_registry, run


def test_registry_loads():
    root = Path(__file__).resolve().parents[1]
    qs = load_registry(root / "config" / "github_exposure_queries.json")
    assert len(qs) >= 5
    assert all("{target}" in (q.get("template") or "") for q in qs)


def test_scope_gate():
    assert in_scope_url("https://github.com/acme/app/blob/main/.env", "acme.com") is False
    assert in_scope_url("https://github.com/x/y/blob/main/acme.com/config", "acme.com") is True


def test_not_configured_writes_summary():
    with tempfile.TemporaryDirectory() as td:
        rd = Path(td)
        root = Path(__file__).resolve().parents[1]
        run(rd, "example.com", None, root / "config" / "github_exposure_queries.json")
        s = json.loads((rd / "github_exposure" / "summary.json").read_text())
        assert s["provider_status"] == "NOT_CONFIGURED"
