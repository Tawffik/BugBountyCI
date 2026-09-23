import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
from pipeline.detection.parameter_intelligence import build, _norm_endpoint, _params_from_url


def test_norm_endpoint_strips_query():
    assert _norm_endpoint("https://api.example.com/v1/users?id=1") == "https://api.example.com/v1/users"


def test_params_from_url():
    assert "id" in _params_from_url("https://x.test/a?id=1&redirect=http://y")


def test_build_from_fixtures():
    with tempfile.TemporaryDirectory() as td:
        os.makedirs(os.path.join(td, "targeted"))
        os.makedirs(os.path.join(td, "urls"))
        os.makedirs(os.path.join(td, "js"))
        with open(os.path.join(td, "targeted", "arjun_params.txt"), "w") as f:
            f.write("https://api.example.com/orders?orderId=1&userId=2\n")
        with open(os.path.join(td, "urls", "params.txt"), "w") as f:
            f.write("https://api.example.com/orders?format=json\n")
            f.write("callback\n")
        with open(os.path.join(td, "js", "api_endpoints.txt"), "w") as f:
            f.write("https://api.example.com/invoices?invoiceId=9\n")
        data = build(td)
        assert data["endpoint_count"] >= 1
        eps = {e["endpoint"]: e for e in data["endpoints"]}
        assert "https://api.example.com/orders" in eps
        names = {p["name"] for p in eps["https://api.example.com/orders"]["parameters"]}
        assert "orderId" in names or "format" in names
        assert data["parameter_count"] >= 1


def test_empty_dir_ok():
    with tempfile.TemporaryDirectory() as td:
        data = build(td)
        assert data["endpoint_count"] == 0
