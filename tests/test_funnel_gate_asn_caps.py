import json
import tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.build_funnel_gate import build, render_md


def test_gate_shows_asn_inventory_vs_caps():
    with tempfile.TemporaryDirectory() as td:
        rd = Path(td)
        (rd / "subdomains").mkdir()
        (rd / "live").mkdir()
        (rd / "urls").mkdir()
        (rd / "js").mkdir()
        (rd / "meta").mkdir()
        (rd / "subdomains" / "resolved.txt").write_text("a.example.com\n")
        (rd / "subdomains" / "all_subs.txt").write_text("a.example.com\n")
        (rd / "subdomains" / "asn_cidrs.txt").write_text("1.0.0.0/24\n")
        (rd / "subdomains" / "asn_ips.txt").write_text("\n".join(f"1.0.0.{i}" for i in range(50)) + "\n")
        (rd / "live" / "live.txt").write_text("https://a.example.com\n")
        (rd / "live" / "hostname_targets.txt").write_text("https://a.example.com\n")
        (rd / "urls" / "all.txt").write_text("https://a.example.com/\n")
        (rd / "js" / "files.txt").write_text("https://a.example.com/app.js\n")
        (rd / "meta" / "resource_caps.json").write_text(
            json.dumps(
                {
                    "asn_ips_available": 50,
                    "asn_ips_promoted": 10,
                    "asn_port_ip_cap": 10,
                    "ip_live_cap": 10,
                    "naabu_ip_cap": 50,
                }
            )
        )
        report = build(rd)
        assert report["counts"]["asn_ips_available"] == 50
        assert report["counts"]["asn_ips_promoted"] == 10
        md = render_md(report)
        assert "ASN / CIDR" in md
        assert "asn_ips_promoted" in md or "promoted" in md.lower()
        assert any("caps" in r.lower() or "ASN inventory" in r for r in report["reasons"])
