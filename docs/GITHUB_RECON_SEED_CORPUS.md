# GitHub recon seed corpus (Zero Track)

**Status:** domain-scoped inline workflow queries (not `docs/dorking_engine.py`).
`dorking_engine` remains **IMPLEMENTED_NOT_INVOKED**.

Queries use `"${TARGET}"` (quoted domain). **Never** use `org:TARGET` when TARGET is a DNS name.

| ID | Query pattern | Category | Validation |
|----|---------------|----------|------------|
| GH-01 | `"TARGET" password` | credentials | syntax OK (code search) |
| GH-02 | `"TARGET" api_key OR apikey OR secret` | tokens | OK |
| GH-03 | `"TARGET" aws_access OR AKIA` | cloud | OK |
| GH-04 | `"TARGET" filename:.env` | config | OK |
| GH-05 | `"TARGET" filename:credentials` | config | OK |
| GH-06 | `"TARGET" DB_PASSWORD OR DATABASE_URL OR MYSQL_PASSWORD` | database | OK |
| GH-07 | `"TARGET" AWS_SECRET_ACCESS_KEY OR AZURE_CLIENT_SECRET` | cloud | OK |
| GH-08 | `"TARGET" "-----BEGIN" OR "BEGIN PRIVATE KEY"` | private keys | OK |
| GH-09 | `"TARGET" ghp_ OR github_pat_ OR gho_` | tokens | OK |
| GH-10 | `"TARGET" filename:docker-compose.yml OR filename:kubeconfig` | config/deploy | OK |

Historical seed items using `org:TARGET` are **unsupported** for domain targets (would search wrong org namespace). Documented as Unsupported with replacement = domain-quoted forms above.

Filter: `scripts/filter_github_recon.py` keeps domain-in-path, secret-shaped paths under domain-scoped queries, and base-token-in-repo; drops noise wordlists; records drop reasons.
