"""
Log Analyzer Module — Specialized log file analysis.
Performs line-by-line parsing, pattern detection, brute-force detection,
suspicious IP identification, and debug leak detection.
"""

import re
from datetime import datetime
from collections import Counter, defaultdict
from detection import detect_in_text, Finding


# ─── Log-Specific Patterns ──────────────────────────────────────────

LOG_PATTERNS = {
    "stack_trace": {
        "regex": r"(?:Exception|Error|Traceback|at\s+[\w$.]+\([\w.]+:\d+\))",
        "risk": "medium",
        "label": "Stack Trace / Error Leak",
    },
    "debug_mode": {
        "regex": r"(?:DEBUG|debug\s*=\s*[Tt]rue|FLASK_DEBUG|NODE_ENV\s*=\s*development)",
        "risk": "medium",
        "label": "Debug Mode Leak",
    },
    "failed_login": {
        "regex": r"(?:failed\s+login|login\s+failed|authentication\s+failed|invalid\s+credentials|unauthorized|401)",
        "risk": "medium",
        "label": "Failed Login Attempt",
    },
    "sql_injection": {
        "regex": r"(?:SELECT\s+\*\s+FROM|DROP\s+TABLE|UNION\s+SELECT|OR\s+1\s*=\s*1|'\s*OR\s+')",
        "risk": "high",
        "label": "Potential SQL Injection",
    },
    "path_traversal": {
        "regex": r"(?:\.\./\.\./|\.\.\\.\.\\|/etc/passwd|/etc/shadow)",
        "risk": "high",
        "label": "Path Traversal Attempt",
    },
    "sensitive_endpoint": {
        "regex": r"(?:/admin|/debug|/config|/env|/phpinfo|/.env|/wp-admin)",
        "risk": "medium",
        "label": "Sensitive Endpoint Access",
    },
    "large_response": {
        "regex": r"(?:response_size|content.length)\s*[:=]\s*\d{7,}",
        "risk": "low",
        "label": "Unusually Large Response",
    },
}

IP_REGEX = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
TIMESTAMP_REGEX = re.compile(
    r"\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}"
)


# ─── Log Line Parser ────────────────────────────────────────────────

class LogLine:
    """Parsed representation of a single log line."""

    def __init__(self, number: int, raw: str):
        self.number = number
        self.raw = raw.rstrip("\n\r")
        self.timestamp = self._extract_timestamp()
        self.level = self._extract_level()
        self.ip = self._extract_ip()

    def _extract_timestamp(self) -> str | None:
        match = TIMESTAMP_REGEX.search(self.raw)
        return match.group(0) if match else None

    def _extract_level(self) -> str:
        upper = self.raw.upper()
        for level in ("CRITICAL", "ERROR", "WARN", "WARNING", "INFO", "DEBUG", "TRACE"):
            if level in upper:
                return level
        return "UNKNOWN"

    def _extract_ip(self) -> str | None:
        match = IP_REGEX.search(self.raw)
        return match.group(1) if match else None


# ─── Anomaly Detectors ──────────────────────────────────────────────

def detect_brute_force(lines: list[LogLine], threshold: int = 5) -> list[dict]:
    """Detect repeated failed login attempts from the same IP."""
    ip_failures: Counter = Counter()
    anomalies = []

    for line in lines:
        if line.ip and re.search(LOG_PATTERNS["failed_login"]["regex"], line.raw, re.IGNORECASE):
            ip_failures[line.ip] += 1

    for ip, count in ip_failures.items():
        if count >= threshold:
            anomalies.append({
                "type": "brute_force",
                "label": "Brute-Force Attack Detected",
                "risk": "critical",
                "detail": f"IP {ip} had {count} failed login attempts",
                "ip": ip,
                "count": count,
            })

    return anomalies


def detect_suspicious_ips(lines: list[LogLine], threshold: int = 50) -> list[dict]:
    """Flag IPs with abnormally high request volumes."""
    ip_counts: Counter = Counter()
    anomalies = []

    for line in lines:
        if line.ip:
            ip_counts[line.ip] += 1

    for ip, count in ip_counts.items():
        if count >= threshold:
            anomalies.append({
                "type": "suspicious_ip",
                "label": "Suspicious IP Activity",
                "risk": "high",
                "detail": f"IP {ip} made {count} requests",
                "ip": ip,
                "count": count,
            })

    return anomalies


def detect_error_spikes(lines: list[LogLine], threshold: int = 10) -> list[dict]:
    """Detect concentrated bursts of errors."""
    error_lines = [l for l in lines if l.level in ("ERROR", "CRITICAL")]
    anomalies = []

    if len(error_lines) >= threshold:
        anomalies.append({
            "type": "error_spike",
            "label": "Error Spike Detected",
            "risk": "high",
            "detail": f"{len(error_lines)} error-level log entries detected",
            "count": len(error_lines),
        })

    return anomalies


# ─── Main Analyzer ──────────────────────────────────────────────────

def analyze_log(content: str) -> dict:
    """
    Full log analysis pipeline.
    Returns findings, anomalies, and log metadata.
    """
    raw_lines = content.split("\n")
    parsed_lines = [LogLine(i + 1, line) for i, line in enumerate(raw_lines) if line.strip()]

    # 1. Regex detection from the generic detection engine
    base_findings = detect_in_text(content)

    # 2. Log-specific pattern detection
    log_findings: list[Finding] = []
    for line in parsed_lines:
        for pattern_name, pattern_info in LOG_PATTERNS.items():
            if re.search(pattern_info["regex"], line.raw, re.IGNORECASE):
                log_findings.append(
                    Finding(
                        finding_type=pattern_name,
                        value=re.search(pattern_info["regex"], line.raw, re.IGNORECASE).group(0),
                        risk=pattern_info["risk"],
                        label=pattern_info["label"],
                        line=line.number,
                        context=line.raw.strip()[:120],
                    )
                )

    all_findings = base_findings + log_findings

    # 3. Anomaly detection
    anomalies = []
    anomalies.extend(detect_brute_force(parsed_lines))
    anomalies.extend(detect_suspicious_ips(parsed_lines))
    anomalies.extend(detect_error_spikes(parsed_lines))

    # 4. Log metadata / stats
    level_counts = Counter(l.level for l in parsed_lines)
    unique_ips = set(l.ip for l in parsed_lines if l.ip)

    metadata = {
        "total_lines": len(raw_lines),
        "parsed_lines": len(parsed_lines),
        "level_distribution": dict(level_counts),
        "unique_ips": len(unique_ips),
        "time_range": _get_time_range(parsed_lines),
    }

    return {
        "findings": [f.to_dict() for f in all_findings],
        "anomalies": anomalies,
        "metadata": metadata,
        "sensitive_lines": sorted(set(f.line for f in all_findings if f.line)),
    }


def _get_time_range(lines: list[LogLine]) -> dict | None:
    """Extract the time range of log entries."""
    timestamps = [l.timestamp for l in lines if l.timestamp]
    if len(timestamps) >= 2:
        return {"start": timestamps[0], "end": timestamps[-1]}
    elif timestamps:
        return {"start": timestamps[0], "end": timestamps[0]}
    return None
