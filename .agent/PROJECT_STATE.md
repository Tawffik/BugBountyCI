# BugBountyCI — PROJECT STATE

## MODE
HISTORICAL PIVOT CLOSED-LOOP — validation → Hunter

## TIP
8a7fb31 + closed-loop: validate_historical_pivots.py → historical_validations.jsonl → hunter

## SEMANTICS
HISTORICAL_PATH_CURRENT_HOST = path in archive on current host, not in current URL corpus.
≠ dead endpoint ≠ vulnerability. Requires bounded current validation.

## BOUNDARY
BugBountyCI recon producer. No SRA. No new scanner/fuzz engine.
