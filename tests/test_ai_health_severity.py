"""AI provider total failure must DEGRADE, not BROKEN-funnel (#142)."""


def classify_verdict(flags: list[str]) -> str:
    red = sum(1 for f in flags if f.startswith("🔴") or f.startswith("📉"))
    warn = sum(1 for f in flags if f.startswith("⚠️") or f.startswith("🟡"))
    if red:
        return "BROKEN"
    if warn:
        return "DEGRADED"
    return "HEALTHY"


def test_ai_only_is_degraded():
    flags = [
        "⚠️ **Every configured AI provider failed** - AI-driven phases ran with no plan",
    ]
    assert classify_verdict(flags) == "DEGRADED"


def test_funnel_red_still_broken():
    flags = [
        "🔴 **0 live hosts despite confirmed subdomains**: WAF",
        "⚠️ **Every configured AI provider failed**",
    ]
    assert classify_verdict(flags) == "BROKEN"
