"""ASN IPs must be capped before naabu (#162: 28k asn_ips → 28k ports)."""
from pathlib import Path

def test_port_scan_caps_asn_before_naabu():
    src = Path("scripts/port_scan.sh").read_text(encoding="utf-8")
    assert "ASN_PORT_IP_CAP" in src
    assert "NAABU_IP_CAP" in src
    assert "asn_port_ips_all.txt" in src
    # Must not still append full asn_ips unsorted into port_scan without head
    # Presence of head -n "$ASN_PORT_IP_CAP" is required
    assert 'head -n "$ASN_PORT_IP_CAP"' in src or "head -n \"$ASN_PORT_IP_CAP\"" in src

def test_ip_live_cap_still_present():
    src = Path("scripts/port_scan.sh").read_text(encoding="utf-8")
    assert "IP_LIVE_CAP" in src
