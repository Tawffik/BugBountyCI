# Detection evidence classification contract (V4)

Engine evidence classifications (Detection Engine Framework):
| Class | Meaning |
|-------|---------|
| NOISE | matched baseline / non-signal |
| LOW_SIGNAL | weak differential, not lead-quality |
| LEAD | evidence-backed candidate requiring human verification |
| HIGH_SIGNAL | stable across replay / stronger evidence |
| CONFIRMED | reserved for explicit verification path (OOB/stable replay) |
| UNKNOWN | insufficient baseline or data |
| ERROR | tool/engine failure (must not become EMPTY_VALID) |
| PARTIAL | incomplete coverage |

Observational response classes (smart-fuzzing) remain separate:
AUTH_REQUIRED, REDIRECT, SERVER_ERROR, WAF_BLOCK, SPA_FALLBACK, DUPLICATE, INTERESTING, NOISE, UNKNOWN

Rule: ZERO_FINDINGS is never inferred from ERROR/PARTIAL/NOT_RUN.
