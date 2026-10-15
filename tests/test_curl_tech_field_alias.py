"""tech.json consumers expect either tech or technologies (#162 dual-write)."""
from __future__ import annotations

def test_curl_tech_detect_writes_both_keys():
    src = open("scripts/curl_tech_detect.py", encoding="utf-8").read()
    assert 'rec["technologies"] = techs' in src
    assert 'rec["tech"] = techs' in src


def test_workflow_wordpress_jq_accepts_technologies():
    wf = open(".github/workflows/zero-track-hunter.yml", encoding="utf-8").read()
    assert "technologies" in wf
    # must not only reference .tech for wordpress host selection
    assert "(.tech!=null) or (.technologies!=null)" in wf or "$r.technologies" in wf
