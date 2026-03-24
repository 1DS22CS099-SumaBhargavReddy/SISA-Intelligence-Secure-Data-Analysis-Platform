"""
AI Insights Module — Generates intelligent summaries and recommendations.
Uses Google Gemini API when available, falls back to rule-based insights.
"""

import os
from typing import Optional

# ─── Optional Gemini Import ─────────────────────────────────────────

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False


# ─── Configuration ──────────────────────────────────────────────────

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")


def _configure_gemini():
    if GEMINI_AVAILABLE and GEMINI_API_KEY:
        genai.configure(api_key=GEMINI_API_KEY)
        return True
    return False


# ─── Rule-Based Insights (Fallback) ─────────────────────────────────

INSIGHT_RULES = {
    "email": "Email addresses found in content — potential PII exposure",
    "phone": "Phone numbers detected — may violate data privacy policies",
    "api_key": "API key exposed — rotate immediately and use environment variables",
    "api_key_prefix": "Prefixed API key detected — likely a production secret",
    "password": "Plaintext password found — critical security vulnerability",
    "token": "Authentication token exposed — risk of unauthorized access",
    "jwt": "JWT token found in logs — could allow session hijacking",
    "aws_key": "AWS access key detected — high risk of cloud account compromise",
    "private_key": "Private key exposed — immediate rotation required",
    "credit_card": "Credit card number found — PCI-DSS compliance violation",
    "ssn": "Social Security Number detected — severe PII breach risk",
    "connection_string": "Database connection string exposed — risk of data breach",
    "ipv4": "IP addresses found — may reveal network infrastructure",
    "stack_trace": "Stack trace reveals internal system details to potential attackers",
    "debug_mode": "Debug mode is enabled — may expose sensitive application internals",
    "failed_login": "Failed login attempts detected — possible brute-force attack",
    "sql_injection": "SQL injection pattern detected — application may be under attack",
    "path_traversal": "Path traversal attempt detected — potential file system access attack",
    "sensitive_endpoint": "Request to sensitive endpoint detected — access control review needed",
    "brute_force": "Brute-force attack pattern detected — implement rate limiting",
    "suspicious_ip": "Abnormally high traffic from single IP — possible DDoS or scraping",
    "error_spike": "Surge in error-level logs — system stability concern",
}


def _generate_rule_based_insights(findings: list[dict], anomalies: list[dict] | None = None) -> dict:
    """Generate insights based on predefined rules."""
    all_items = list(findings)
    if anomalies:
        all_items.extend(anomalies)

    # Deduplicate by type
    seen_types = set()
    insights = []
    for item in all_items:
        ftype = item.get("type", "")
        if ftype not in seen_types and ftype in INSIGHT_RULES:
            insights.append(INSIGHT_RULES[ftype])
            seen_types.add(ftype)

    # Build summary
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in all_items:
        risk = item.get("risk", "low").lower()
        if risk in risk_counts:
            risk_counts[risk] += 1

    summary_parts = []
    if risk_counts["critical"]:
        summary_parts.append(f"{risk_counts['critical']} critical")
    if risk_counts["high"]:
        summary_parts.append(f"{risk_counts['high']} high-risk")
    if risk_counts["medium"]:
        summary_parts.append(f"{risk_counts['medium']} medium-risk")
    if risk_counts["low"]:
        summary_parts.append(f"{risk_counts['low']} low-risk")

    if summary_parts:
        summary = f"Analysis detected {', '.join(summary_parts)} issue(s). Immediate review recommended."
    else:
        summary = "No significant security issues detected in the analyzed content."

    # Recommendations
    recommendations = []
    if risk_counts["critical"] > 0:
        recommendations.append("URGENT: Rotate all exposed credentials immediately")
    if "password" in seen_types:
        recommendations.append("Never log passwords — use secure hashing and vault services")
    if "api_key" in seen_types or "api_key_prefix" in seen_types:
        recommendations.append("Move API keys to environment variables or secret managers")
    if "stack_trace" in seen_types:
        recommendations.append("Disable verbose error output in production environments")
    if "brute_force" in seen_types:
        recommendations.append("Implement account lockout and rate-limiting policies")
    if not recommendations:
        recommendations.append("Continue monitoring for security anomalies")

    return {
        "summary": summary,
        "insights": insights,
        "recommendations": recommendations,
    }


# ─── Gemini-Powered Insights ────────────────────────────────────────

def _generate_ai_insights(content: str, findings: list[dict], anomalies: list[dict] | None = None) -> dict:
    """Generate insights using Google Gemini API."""
    if not _configure_gemini():
        return _generate_rule_based_insights(findings, anomalies)

    try:
        model = genai.GenerativeModel("gemini-1.5-flash")

        findings_summary = "\n".join(
            f"- [{f.get('risk', 'unknown').upper()}] {f.get('label', f.get('type', 'unknown'))}: "
            f"{f.get('value', 'N/A')[:50]} (line {f.get('line', '?')})"
            for f in findings[:30]  # Limit to avoid token overflow
        )

        anomaly_summary = ""
        if anomalies:
            anomaly_summary = "\n".join(
                f"- [{a.get('risk', 'unknown').upper()}] {a.get('label', a.get('type', 'unknown'))}: "
                f"{a.get('detail', 'N/A')}"
                for a in anomalies
            )

        prompt = f"""You are a security analyst AI. Analyze the following security scan results and provide:
1. A concise summary (2-3 sentences max)
2. 3-5 specific security insights
3. 2-4 actionable recommendations

FINDINGS:
{findings_summary}

{"ANOMALIES:" + chr(10) + anomaly_summary if anomaly_summary else ""}

Content preview (first 500 chars):
{content[:500]}

Respond ONLY in this exact JSON format:
{{
  "summary": "...",
  "insights": ["insight1", "insight2", ...],
  "recommendations": ["rec1", "rec2", ...]
}}"""

        response = model.generate_content(prompt)
        text = response.text.strip()

        # Extract JSON from response
        import json
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        result = json.loads(text)

        return {
            "summary": result.get("summary", "AI analysis complete."),
            "insights": result.get("insights", []),
            "recommendations": result.get("recommendations", []),
        }

    except Exception as e:
        # Fall back to rule-based on any error
        fallback = _generate_rule_based_insights(findings, anomalies)
        fallback["ai_note"] = f"AI analysis unavailable ({type(e).__name__}), using rule-based insights"
        return fallback


# ─── Public API ──────────────────────────────────────────────────────

def generate_insights(
    content: str,
    findings: list[dict],
    anomalies: list[dict] | None = None,
    use_ai: bool = True,
) -> dict:
    """
    Generate security insights for analyzed content.
    Uses Gemini if available and enabled, otherwise rule-based.
    """
    if use_ai and GEMINI_AVAILABLE and GEMINI_API_KEY:
        return _generate_ai_insights(content, findings, anomalies)
    return _generate_rule_based_insights(findings, anomalies)


def _generate_rule_based_playbook(findings: list[dict], anomalies: list[dict] | None = None) -> str:
    """Fallback static playbook generation."""
    playbook = "### 📜 SECURITY REMEDIATION PLAYBOOK (Standard Edition)\n\n"
    playbook += "1. **Immediate Lockdown**: Isolate affected systems and revoke suspect credentials.\n"
    playbook += "2. **Credential Rotation**: All detected secrets (passwords, API keys) must be rotated immediately.\n"
    playbook += "3. **Log Scrubbing**: Remove sensitive data from existing logs and fix the logging code.\n"
    playbook += "4. **Root Cause Analysis**: Audit code for hardcoded secrets or insufficient input validation.\n"
    playbook += "5. **System Hardening**: Implement Rate Limiting and MFA for all administrative endpoints.\n"
    return playbook


def generate_remediation_playbook(content: str, findings: list[dict], anomalies: list[dict] | None = None) -> str:
    """Generate a high-detail step-by-step security response playbook."""
    if not _configure_gemini():
        return _generate_rule_based_playbook(findings, anomalies)

    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
        
        findings_text = "\n".join([f"- {f.get('type')}: {f.get('risk')}" for f in findings[:20]])
        
        prompt = f"""You are a Lead Security Engineer. Based on the following findings, generate a DETAILED step-by-step 
        Security Remediation Playbook (Incident Response Plan). 
        
        FINDINGS:
        {findings_text}
        
        The playbook should include:
        - PHASE 1: CONTAINMENT (Immediate actions)
        - PHASE 2: ERADICATION (How to fix the underlying issue)
        - PHASE 3: RECOVERY (Restoring trust)
        - PHASE 4: LESSONS LEARNED (Prevention)
        
        Keep it professional, technical, and actionable. Format with Markdown.
        """
        
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception:
        return _generate_rule_based_playbook(findings, anomalies)
