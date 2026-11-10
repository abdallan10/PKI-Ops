"""Conservative, non-authoritative detection of explicit contradictions in LLM advice."""
import re
import unicodedata


def _normalize(value):
    value = unicodedata.normalize("NFKD", value.lower())
    return "".join(c for c in value if not unicodedata.combining(c))


def check_advice(advice, policy_result):
    """Flag a few explicit claims; not a semantic security guarantee."""
    if policy_result not in {"approved", "rejected"}:
        raise ValueError("Expected authoritative policy_result")
    text = _normalize(advice)
    approval = bool(
        re.search(r"\bcertificat\s+(?:approuve|accepte|autorise)\b", text)
        or re.search(
            r"(?:certificat|demande|decision|validateur)[^.!?\n]{0,90}"
            r"(?:est |a ete |: ?)(?:bien )?(?:approuve|accepte|autorise)",
            text,
        )
    )
    denial = bool(
        re.search(r"\bcertificat\s+(?:rejete|refuse|interdit)\b", text)
        or re.search(
            r"(?:certificat|demande|decision|validateur)[^.!?\n]{0,90}"
            r"(?:est |a ete |: ?)(?:bien )?(?:rejete|refuse|interdit)",
            text,
        )
    )
    disabled = bool(re.search(
        r"politique[^.!?\n]{0,35}(?:(?:est |: ?))?"
        r"(?:desactivee|desactive|supprimee)",
        text,
    ))
    reasons = []
    if policy_result == "rejected" and approval:
        reasons.append("false_approval")
    if policy_result == "approved" and denial:
        reasons.append("false_rejection")
    if disabled:
        reasons.append("policy_disabled_claim")
    return {
        "flagged": bool(reasons),
        "reasons": reasons,
        "method": "conservative_text_patterns",
    }
