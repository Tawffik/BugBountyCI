from scripts.filter_github_recon import decide, filter_lines


def test_keeps_domain_in_path():
    ok, reason = decide(
        "acme/configs :: src/example.com/.env",
        "example.com",
        "example",
    )
    assert ok and reason == "domain_in_repo_or_path"


def test_keeps_secret_path_without_domain_in_path():
    ok, reason = decide(
        "random-org/backend :: config/.env.production",
        "example.com",
        "example",
    )
    assert ok, reason
    assert reason == "secret_path_under_domain_scoped_query"


def test_drops_noise_wordlist():
    ok, reason = decide(
        "cirosantilli/awesome-wordlist :: all.txt",
        "example.com",
        "example",
    )
    assert not ok and reason == "noise_repo_or_path"


def test_drops_weak_readme():
    ok, reason = decide(
        "someone/notes :: README.md",
        "example.com",
        "example",
    )
    assert not ok and reason == "weak_attribution"


def test_filter_cap_and_summary():
    lines = [
        "acme/x :: example.com/creds.env",
        "noise/wordlist :: common.txt",
        "org/app :: .env",
    ]
    kept, dropped, summary = filter_lines(lines, "example.com", limit=80)
    assert any("example.com" in k for k in kept)
    assert any(".env" in k for k in kept)
    assert summary["kept"] >= 2
    assert summary["raw"] == 3
