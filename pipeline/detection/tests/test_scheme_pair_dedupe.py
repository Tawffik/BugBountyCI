from pipeline.detection.hunter_queue_builder import dedupe_scheme_pairs, _target_host_path_key


def test_host_path_key_ignores_scheme():
    assert _target_host_path_key("http://capital.com/*?page={PAYLOAD}") == _target_host_path_key(
        "https://capital.com/*?page={PAYLOAD}"
    )


def test_dedupe_prefers_https():
    entries = [
        {
            "priority_class": "HIGH_SIGNAL",
            "engine": "ssrf-v1",
            "target": "http://capital.com/*?page={PAYLOAD}",
            "reason": "diff",
            "stable": True,
        },
        {
            "priority_class": "HIGH_SIGNAL",
            "engine": "ssrf-v1",
            "target": "https://capital.com/*?page={PAYLOAD}",
            "reason": "diff",
            "stable": True,
        },
        {
            "priority_class": "INTERESTING",
            "engine": "linkfinder_api",
            "target": "/api",
            "reason": "api",
            "stable": None,
        },
    ]
    out = dedupe_scheme_pairs(entries)
    hs = [e for e in out if e["priority_class"] == "HIGH_SIGNAL"]
    assert len(hs) == 1
    assert hs[0]["target"].startswith("https://")
    assert any(e["target"] == "/api" for e in out)
