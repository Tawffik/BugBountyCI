import json
import tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.normalize_linkfinder import normalize_file
from scripts.sanitize_cloud_origin_outputs import clean_file


def test_normalize_writes_js_endpoints():
    with tempfile.TemporaryDirectory() as td:
        rd = Path(td)
        (rd / "js_deep").mkdir(parents=True)
        raw = rd / "js_deep" / "linkfinder.txt"
        # bare paths (LINE_RE optional); /api/* → API_ROUTE
        raw.write_text(
            "/api/users\n"
            "/api/v2/orders\n"
            "/admin/dashboard\n"
            "/static/chunk.js\n"
            "https://cdn.example.com/x.js\n"
        )
        summary = normalize_file(str(raw), str(rd), "example.com")
        assert (rd / "js" / "endpoints.txt").is_file()
        assert (rd / "js_deep" / "linkfinder_endpoints.txt").is_file()
        assert summary.get("endpoints_materialized", 0) >= 1
        text = (rd / "js" / "endpoints.txt").read_text()
        assert "/api" in text


def test_sanitize_strips_banner_keeps_ip():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "cloudfail.txt"
        p.write_text(
            "_______ CloudFail _______\n"
            "scanning for stuff\n"
            "Visible IP Address: 1.2.3.4\n"
            "################\n"
        )
        n = clean_file(p)
        body = p.read_text()
        assert "1.2.3.4" in body
        assert "_______" not in body
        assert n >= 1
