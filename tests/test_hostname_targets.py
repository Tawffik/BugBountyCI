from scripts.hostname_targets import filter_lines


def test_skips_ip_and_dedupes():
    lines = [
        "http://api.example.com",
        "https://api.example.com",
        "http://1.2.3.4:8080",
        "https://www.example.com/",
        "example.com",
    ]
    assert filter_lines(lines, 15) == [
        "https://api.example.com",
        "https://www.example.com",
        "https://example.com",
    ]


def test_limit():
    lines = [f"https://h{i}.example.com" for i in range(20)]
    assert len(filter_lines(lines, 5)) == 5
