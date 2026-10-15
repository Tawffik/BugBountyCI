"""Resource caps (#17/#24) and probe body association integrity (#25 port-aware)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _port_scan_src() -> str:
    return (ROOT / "scripts" / "port_scan.sh").read_text(encoding="utf-8")


def test_asn_and_naabu_caps_present_before_naabu_invocation():
    src = _port_scan_src()
    asn_pos = src.find("ASN_PORT_IP_CAP")
    naabu_cap_pos = src.find("NAABU_IP_CAP")
    first_naabu = src.find('"$NAABU_BIN" -l')
    assert asn_pos > 0 and naabu_cap_pos > 0 and first_naabu > 0
    assert asn_pos < first_naabu
    assert naabu_cap_pos < first_naabu
    assert 'head -n "$ASN_PORT_IP_CAP"' in src
    assert 'head -n "$NAABU_IP_CAP"' in src


def test_ip_live_cap_on_both_enrichment_paths():
    src = _port_scan_src()
    assert src.count("IP_LIVE_CAP") >= 2
    assert "nonstd_ip_capped" in src
    assert "port_urls_ip_capped" in src


def test_scan_order_hostname_before_ip():
    src = _port_scan_src()
    assert "scan_order_host.txt" in src and "scan_order_ip.txt" in src
    assert src.find("cat /tmp/scan_order_host.txt /tmp/scan_order_ip.txt") > 0


def test_shell_cap_simulation_above_below_empty():
    with tempfile.TemporaryDirectory() as td:
        td_p = Path(td)
        ips = [f"203.0.113.{i}" for i in range(1, 51)]
        (td_p / "asn.txt").write_text("\n".join(ips) + "\n")
        out = subprocess.check_output(
            ["bash", "-c", f'head -n 10 "{td_p}/asn.txt" | wc -l'],
            text=True,
        ).strip()
        assert out == "10"
        (td_p / "empty.txt").write_text("")
        out0 = subprocess.check_output(
            ["bash", "-c", f'head -n 10 "{td_p}/empty.txt" | wc -l'],
            text=True,
        ).strip()
        assert out0 == "0"
        (td_p / "mixed.txt").write_text("not-an-ip\n203.0.113.9\n\nfoo\n203.0.113.10\n")
        extracted = subprocess.check_output(
            [
                "bash",
                "-c",
                f"grep -oE '([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}' '{td_p}/mixed.txt' | sort -u",
            ],
            text=True,
        ).strip().splitlines()
        assert set(extracted) == {"203.0.113.9", "203.0.113.10"}


def test_probe_scheme_alias_and_port_keys_in_source():
    src = (ROOT / "scripts" / "write_pipeline_exports.py").read_text(encoding="utf-8")
    hunter = (
        ROOT / "pipeline" / "detection" / "hunter_queue_builder.py"
    ).read_text(encoding="utf-8")
    assert "urlunparse" in src
    assert "port not in (80, 443)" in src
    assert "port not in (80, 443)" in hunter
    assert "host}:{port}|{path_key}" in src or 'f"{host}:{port}|{path_key}"' in src


def test_probe_scheme_alias_export_runs():
    with tempfile.TemporaryDirectory() as td:
        rd = Path(td)
        (rd / "info_disclosure").mkdir()
        (rd / "meta").mkdir()
        probe = {
            "url": "https://app.example.com/.git/HEAD",
            "status_code": 200,
            "body": "ref: refs/heads/main\n",
            "content_type": "text/plain",
        }
        (rd / "info_disclosure" / "probe_results.jsonl").write_text(
            json.dumps(probe) + "\n"
        )
        (rd / "info_disclosure" / "git_exposure.txt").write_text(
            "http://app.example.com/.git/HEAD\n"
        )
        env = os.environ.copy()
        env["TARGET"] = "example.com"
        env["TIMESTAMP"] = "t"
        rc = subprocess.call(
            [sys.executable, str(ROOT / "scripts" / "write_pipeline_exports.py"), str(rd)],
            env=env,
        )
        assert rc == 0


def test_live_host_asn_probe_capped_at_80():
    src = (ROOT / "scripts" / "live_host_probing.sh").read_text(encoding="utf-8")
    assert "head -80" in src and "asn_ips.txt" in src


def test_resource_caps_json_written_by_port_scan():
    src = _port_scan_src()
    assert "resource_caps.json" in src
    assert "live_enrichment_caps.json" in src
    assert "asn_ips_available" in src
    assert "naabu_truncated" in src


def test_soft_seed_host_cap_in_live_probe_recovery():
    src = (ROOT / "scripts" / "live_host_probing.sh").read_text(encoding="utf-8")
    assert "SOFT_SEED_HOST_CAP" in src
    assert 'head -n "$SOFT_SEED_HOST_CAP"' in src
