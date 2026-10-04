# BugBountyCI — PROJECT STATE

## MODE
POST-#122: historical identity fix + Representation Differential

## HISTORICAL LOOP
CLOSED LIVE (#122). Identity fix: host+path (not path-only) + scheme from current surface.

## REPRESENTATION DIFFERENTIAL
scripts/representation_differential.py — Accept html vs json on API-looking candidates only.
MEANINGFUL → Hunter. NOT a second fuzz engine.

## BOUNDARY
BugBountyCI recon producer. No SRA.
