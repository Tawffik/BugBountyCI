"""engine_health.flags must surface pipeline_health.md Flags (#142 regression)."""


def parse_flags(ph_text: str):
    overall = None
    flags = []
    in_flags = False
    for line in ph_text.splitlines():
        if line.startswith("## Overall:"):
            overall = line.split("## Overall:", 1)[1].strip()
            in_flags = False
            continue
        if line.startswith("## Flags"):
            in_flags = True
            continue
        if in_flags:
            if line.startswith("## "):
                break
            s = line.strip()
            if s.startswith("- "):
                flags.append(s[2:].strip())
    return overall, flags


def test_142_shaped_ai_flag_propagates():
    md = """# Health
## Overall: 🔴 BROKEN - one or more pipeline stages produced nothing when they should have

## Flags
- 🔴 **Every configured AI provider failed** - AI-driven phases ran with no plan.
- ⚠️ **Arjun phase=PARTIAL** — params=1
"""
    overall, flags = parse_flags(md)
    assert "BROKEN" in overall
    assert any("AI provider" in f for f in flags)
    assert len(flags) == 2


def test_no_flags_section():
    overall, flags = parse_flags("## Overall: 🟢 HEALTHY\n\n_No anomalies_\n")
    assert "HEALTHY" in overall
    assert flags == []
