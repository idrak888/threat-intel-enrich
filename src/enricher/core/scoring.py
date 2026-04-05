"""Scoring algorithm that weighs provider findings into a risk verdict."""

from enricher.core.models import ProviderFinding

_PROVIDER_WEIGHTS: dict[str, float] = {
    "virustotal": 0.6,
    "abuseipdb": 0.4,
}

_RISK_LEVELS = [
    (1.0, "clean"),
    (3.0, "low"),
    (5.0, "medium"),
    (7.0, "high"),
    (10.0, "critical"),
]


def calculate_score(findings: list[ProviderFinding]) -> float:
    """Return a risk score from 0.0 to 10.0 based on weighted provider findings.

    Only findings where malicious=True contribute to the score.
    Unknown (None) findings are ignored.
    """
    weighted_sum = 0.0
    total_weight = 0.0

    for finding in findings:
        weight = _PROVIDER_WEIGHTS.get(finding.provider, 0.5)
        total_weight += weight
        if finding.malicious:
            weighted_sum += finding.confidence * weight

    if total_weight == 0.0:
        return 0.0

    # Normalize to 0–10
    return round((weighted_sum / total_weight) * 10, 1)


def risk_level(score: float) -> str:
    """Map a numeric score to a risk level label."""
    for threshold, level in _RISK_LEVELS:
        if score <= threshold:
            return level
    return "critical"


def summarize(score: float, findings: list[ProviderFinding]) -> str:
    """Generate a one-line human-readable summary of the verdict."""
    level = risk_level(score).capitalize()
    parts: list[str] = []

    for finding in findings:
        if finding.malicious is None:
            continue

        if finding.provider == "virustotal":
            total = finding.details.get("total_engines", 0)
            malicious = finding.details.get("malicious_count", 0)
            if finding.malicious:
                parts.append(f"flagged as malicious by VirusTotal ({malicious}/{total} engines)")
            else:
                parts.append(f"clean on VirusTotal (0/{total} engines)")

        elif finding.provider == "abuseipdb":
            reports = finding.details.get("total_reports", 0)
            abuse_score = finding.details.get("abuse_confidence_score", 0)
            if finding.malicious:
                parts.append(f"reported {reports} times on AbuseIPDB (score: {abuse_score})")
            else:
                parts.append("no reports on AbuseIPDB")

    detail = ", ".join(parts) if parts else "no data from providers"
    return f"{level} risk ({score}/10) — {detail}"
