"""
Detection Engine — Regex-based sensitive data detection.
Identifies emails, phone numbers, API keys, passwords, tokens,
and other sensitive patterns in text content.
"""

import re
from typing import Optional


# ─── Pattern Definitions ────────────────────────────────────────────

PATTERNS = {
    "email": {
        "regex": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "risk": "low",
        "label": "Email Address",
    },
    "phone": {
        "regex": r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}",
        "risk": "low",
        "label": "Phone Number",
    },
    "api_key": {
        "regex": r"(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?",
        "risk": "high",
        "label": "API Key",
    },
    "api_key_prefix": {
        "regex": r"(?:sk|pk|ak|rk)[_-](?:live|test|prod|dev|staging)[_-][A-Za-z0-9_\-]{8,}",
        "risk": "high",
        "label": "API Key (Prefixed)",
    },
    "password": {
        "regex": r"(?:password|passwd|pwd|pass)\s*[:=]\s*['\"]?(\S+)['\"]?",
        "risk": "critical",
        "label": "Password",
    },
    "token": {
        "regex": r"(?:token|bearer|auth_token|access_token|refresh_token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{16,})['\"]?",
        "risk": "high",
        "label": "Token / Bearer",
    },
    "jwt": {
        "regex": r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        "risk": "high",
        "label": "JWT Token",
    },
    "aws_key": {
        "regex": r"AKIA[0-9A-Z]{16}",
        "risk": "critical",
        "label": "AWS Access Key",
    },
    "private_key": {
        "regex": r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----",
        "risk": "critical",
        "label": "Private Key",
    },
    "ipv4": {
        "regex": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "risk": "low",
        "label": "IPv4 Address",
    },
    "credit_card": {
        "regex": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
        "risk": "critical",
        "label": "Credit Card Number",
    },
    "ssn": {
        "regex": r"\b\d{3}-\d{2}-\d{4}\b",
        "risk": "critical",
        "label": "Social Security Number",
    },
    "connection_string": {
        "regex": r"(?:mongodb|mysql|postgres|redis|amqp)://[^\s'\"]+",
        "risk": "high",
        "label": "Database Connection String",
    },
}


# ─── Finding Data Class ─────────────────────────────────────────────

class Finding:
    """Represents a single detected sensitive data occurrence."""

    def __init__(
        self,
        finding_type: str,
        value: str,
        risk: str,
        label: str,
        line: Optional[int] = None,
        context: Optional[str] = None,
    ):
        self.type = finding_type
        self.value = value
        self.risk = risk
        self.label = label
        self.line = line
        self.context = context

    def to_dict(self) -> dict:
        result = {
            "type": self.type,
            "label": self.label,
            "value": self.value,
            "risk": self.risk,
        }
        if self.line is not None:
            result["line"] = self.line
        if self.context:
            result["context"] = self.context
        return result


# ─── Detection Functions ────────────────────────────────────────────

def detect_in_text(text: str) -> list[Finding]:
    """Scan a block of text for all sensitive patterns. Returns findings list."""
    findings: list[Finding] = []
    lines = text.split("\n")

    for line_num, line in enumerate(lines, start=1):
        for pattern_name, pattern_info in PATTERNS.items():
            for match in re.finditer(pattern_info["regex"], line, re.IGNORECASE):
                matched_value = match.group(0)
                findings.append(
                    Finding(
                        finding_type=pattern_name,
                        value=matched_value,
                        risk=pattern_info["risk"],
                        label=pattern_info["label"],
                        line=line_num,
                        context=line.strip()[:120],
                    )
                )

    return findings


def detect_in_content(content: str) -> list[dict]:
    """High-level detection returning list of finding dicts."""
    findings = detect_in_text(content)
    return [f.to_dict() for f in findings]
