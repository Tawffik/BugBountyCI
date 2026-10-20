"""Offline tests for scripts/build_secrets_review.py (RRP-1)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_secrets_review import build, render_md  # noqa: E402


def test_no_inputs(tmp_path: Path) -> None:
    report = build(tmp_path)
    assert report["status"] == "NO_INPUTS"
    assert report["review_count"] == 0
    md = render_md(report)
    assert "NO_INPUTS" in md
    assert "Diagnosis" in md


def test_filters_aws_example_and_keeps_shaped(tmp_path: Path) -> None:
    js_deep = tmp_path / "js_deep"
    js_deep.mkdir()
    # Uses the classic AWS *documentation* example key — must be noise
    (js_deep / "secretfinder_secrets.txt").write_text(
        "[app.js] AWS Access Key\t->\tAKIAIOSFODNN7EXAMPLE\n"
        "[prod.js] AWS Access Key\t->\tAKIA1234567890ABCD\n",
        encoding="utf-8",
    )
    (js_deep / "gitleaks_findings.json").write_text(
        json.dumps(
            [
                {
                    "RuleID": "aws-access-key",
                    "File": "prod.js",
                    "Secret": "AKIA1234567890ABCD",
                    "Match": "AKIA1234567890ABCD",
                },
                {
                    "RuleID": "generic-api-key",
                    "File": "modal.js",
                    "Secret": "d=i.MODAL_KEYS.DEPOSIT",
                    "Match": "MODAL_KEYS",
                },
            ]
        ),
        encoding="utf-8",
    )
    report = build(tmp_path)
    assert report["status"] == "OK"
    assert report["review_count"] >= 1
    blob = json.dumps(report)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    assert "CONFIRMED" not in blob
    for it in report["items"]:
        assert it["classification"] == "REVIEW"
        assert "[REDACTED]" in it["line_redacted"] or it["line_redacted"] == "[REDACTED]"


def test_placeholder_env_empty_after_filter(tmp_path: Path) -> None:
    js = tmp_path / "js"
    js.mkdir()
    (js / "secrets_high.txt").write_text(
        "API_KEY=your_api_key_here\nSECRET=changeme\n",
        encoding="utf-8",
    )
    report = build(tmp_path)
    assert report["status"] == "EMPTY_AFTER_FILTER"
    assert report["review_count"] == 0


def test_fixture_js_deep_results_directory() -> None:
    """Smoke against committed js_deep fixtures (may be EMPTY after EXAMPLE filter)."""
    root = ROOT / "tests" / "fixtures" / "js_deep_results"
    if not root.is_dir():
        pytest.skip("fixture missing")
    report = build(root)
    assert report["status"] in {"OK", "EMPTY_AFTER_FILTER", "NO_INPUTS"}
    assert "schema" in report
