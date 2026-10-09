from scripts.arjun_target_filter import filter_arjun_targets


def test_skips_ips_and_dedupes_scheme():
    lines = [
        "http://api.example.com",
        "https://api.example.com",
        "http://1.2.3.4",
        "http://1.2.3.4:8080",
        "https://www.example.com",
        "example.com",
    ]
    out = filter_arjun_targets(lines, limit=15)
    assert out == [
        "https://api.example.com/",
        "https://www.example.com/",
        "https://example.com/",
    ]


def test_cap():
    lines = [f"https://h{i}.example.com" for i in range(20)]
    assert len(filter_arjun_targets(lines, limit=5)) == 5
