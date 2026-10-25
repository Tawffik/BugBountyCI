import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pipeline.detection.cloud_exposure_engine import (
    classify_body,
    classify_provider,
    disposition_from_class,
    run,
)


def test_provider_s3_and_cf():
    assert classify_provider("mybucket.s3.amazonaws.com")[0] == "s3"
    assert classify_provider("d111111abcdef8.cloudfront.net")[0] == "cloudfront"
    assert classify_provider("storage.googleapis.com")[0] == "gcs"


def test_body_listing_vs_denied():
    rc, _ = classify_body(200, "<ListBucketResult xmlns=><Contents><Key>a</Key></Contents>", "")
    assert rc == "listing_evidence"
    rc, _ = classify_body(403, "<Error><Code>AccessDenied</Code></Error>", "")
    assert rc == "access_denied"
    assert disposition_from_class("access_denied", "name_guess") == "provider_clue"
    assert disposition_from_class("listing_evidence", "urls/all.txt") == "content_supported"


def test_run_passive_no_crash():
    with tempfile.TemporaryDirectory() as td:
        rd = Path(td)
        (rd / "urls").mkdir()
        (rd / "urls" / "all.txt").write_text(
            "https://example-target-assets.s3.amazonaws.com/app.js\n"
            "https://cdn.other-company.com/x\n"
        )
        summary = run(str(rd), "example-target.com", enable_active=False)
        assert summary["auto_confirmed"] == 0
        assert (rd / "detection" / "cloud_exposure_findings.jsonl").is_file()
        for line in (rd / "detection" / "cloud_exposure_findings.jsonl").read_text().splitlines():
            row = json.loads(line)
            assert row.get("never_auto_confirmed") is True
            assert row.get("final_disposition") != "confirmed"


def test_403_not_confirmed_disposition():
    assert disposition_from_class("access_denied", "urls/all.txt") == "provider_clue"
