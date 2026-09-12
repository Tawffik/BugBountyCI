#!/usr/bin/env python3
from pathlib import Path
p = Path(".github/workflows/zero-track-hunter.yml")
t = p.read_text()
assert "Final all.txt" in t
old_idor = 'if l.startswith("[IDOR-CANDIDATE]"): confirmed.append((SEV_RANK["medium"], "medium", "IDOR (needs manual confirmation)", l))'
new_idor = 'if l.startswith("[IDOR-CANDIDATE]"): leads.append(("IDOR candidate (needs manual verification)", l))\n              elif l.startswith("[IDOR]"): confirmed.append((SEV_RANK["medium"], "medium", "IDOR", l))'
if old_idor in t:
    t = t.replace(old_idor, new_idor, 1)
    print("idor soft")
else:
    print("idor already or missing")
old_gql = 'if l.startswith("[GRAPHQL"): confirmed.append((SEV_RANK["medium"], "medium", "GraphQL", l))'
new_gql = 'if l.startswith("[GRAPHQL-INTROSPECTION]") or l.startswith("[GRAPHQL-BATCHING]"): leads.append(("GraphQL capability (not vuln alone)", l))\n              elif l.startswith("[GRAPHQL"): confirmed.append((SEV_RANK["medium"], "medium", "GraphQL", l))'
if old_gql in t:
    t = t.replace(old_gql, new_gql, 1)
    print("graphql soft")
else:
    print("graphql already or missing")
assert "Final all.txt" in t and "redact_secrets_for_llm" in t
p.write_text(t)
print("step4 ok")
