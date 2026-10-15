from scripts.hostname_targets import filter_lines, _host_score


def test_skips_ip_and_dedupes():
    lines = [
        "http://api.example.com",
        "https://api.example.com",
        "http://1.2.3.4:8080",
        "https://www.example.com/",
        "example.com",
    ]
    out = filter_lines(lines, 15)
    assert "https://api.example.com" in out
    assert "https://www.example.com" in out
    assert "https://example.com" in out
    assert len(out) == 3
    # pure IP dropped
    assert not any("1.2.3.4" in x for x in out)


def test_limit():
    lines = [f"https://h{i}.example.com" for i in range(20)]
    assert len(filter_lines(lines, 5)) == 5


def test_hunter_priority_test_api_before_static():
    lines = [
        "https://static.example.com",
        "https://www.example.com",
        "https://cdn.example.com",
        "https://test-api.example.com",
        "https://admin.example.com",
        "https://img.example.com",
    ]
    out = filter_lines(lines, 4)
    assert out[0] in ("https://test-api.example.com", "https://admin.example.com")
    assert "https://static.example.com" not in out or out.index("https://test-api.example.com") < out.index("https://static.example.com")
    # top slots should be high-value
    assert all(x.split("//")[1].split(".")[0] in ("test-api", "admin") or "test" in x or "admin" in x for x in out[:2])


def test_ranked_line_format():
    lines = ["105 https://api.example.com", "10 https://static.example.com"]
    out = filter_lines(lines, 10)
    assert out[0] == "https://api.example.com"


def test_capital_does_not_match_api_substring():
    assert _host_score("capital.com") == 0
    assert _host_score("api.capital.com") == 10
