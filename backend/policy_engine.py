"""
Policy Engine — Enforcement of data handling policies.
Handles masking of sensitive values and blocking of high-risk content.
"""

import re
from typing import Optional


# ─── Masking Rules ──────────────────────────────────────────────────

MASK_CHAR = "•"

MASK_STRATEGIES = {
    "email": lambda v: v.split("@")[0][:2] + "•••@" + v.split("@")[1] if "@" in v else "•" * len(v),
    "phone": lambda v: v[:3] + "•" * (len(v) - 5) + v[-2:],
    "api_key": lambda v: v[:4] + "•" * 12 + v[-4:] if len(v) > 8 else "•" * len(v),
    "api_key_prefix": lambda v: v[:7] + "•" * 12,
    "password": lambda v: "•" * len(v),
    "token": lambda v: v[:4] + "•" * 12 + v[-4:] if len(v) > 8 else "•" * len(v),
    "jwt": lambda v: v[:10] + "•••" + v[-6:] if len(v) > 16 else "•" * len(v),
    "aws_key": lambda v: v[:4] + "•" * 16,
    "private_key": lambda v: "•••REDACTED PRIVATE KEY•••",
    "credit_card": lambda v: "•" * 12 + v[-4:] if len(v) >= 4 else "•" * len(v),
    "ssn": lambda v: "•••-••-" + v[-4:] if len(v) >= 4 else "•" * len(v),
    "connection_string": lambda v: v.split("://")[0] + "://•••REDACTED•••" if "://" in v else "•" * len(v),
    "ipv4": lambda v: v,  # IPs are low risk, keep visible
}

DEFAULT_MASK = lambda v: "•" * min(len(v), 20)


# ─── Policy Actions ────────────────────────────────────────────────

def mask_content(content: str, findings: list[dict]) -> str:
    """Replace sensitive values in content with masked versions."""
    masked = content
    # Sort findings by value length (longest first) to avoid partial replacements
    sorted_findings = sorted(findings, key=lambda f: len(f.get("value", "")), reverse=True)

    for finding in sorted_findings:
        value = finding.get("value", "")
        ftype = finding.get("type", "")
        if not value:
            continue

        mask_fn = MASK_STRATEGIES.get(ftype, DEFAULT_MASK)
        masked_value = mask_fn(value)
        masked = masked.replace(value, masked_value)

    return masked


def should_block(risk_level: str, block_high_risk: bool = False) -> bool:
    """Determine whether the content should be blocked."""
    if not block_high_risk:
        return False
    return risk_level in ("critical", "high")


def apply_policy(
    content: str,
    findings: list[dict],
    risk_level: str,
    options: dict,
) -> dict:
    """
    Apply all policy rules to the content.
    Returns action taken and processed content.
    """
    do_mask = options.get("mask", False)
    do_block = options.get("block_high_risk", False)

    # Check blocking first
    if should_block(risk_level, do_block):
        return {
            "action": "blocked",
            "content": "[CONTENT BLOCKED — High-risk data detected]",
            "blocked": True,
        }

    # Apply masking
    if do_mask and findings:
        masked_content = mask_content(content, findings)
        return {
            "action": "masked",
            "content": masked_content,
            "blocked": False,
        }

    return {
        "action": "allowed",
        "content": content,
        "blocked": False,
    }
