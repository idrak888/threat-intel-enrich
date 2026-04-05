"""Pydantic models for indicators, findings, and verdicts."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel


class IndicatorType(str, Enum):
    """Supported indicator types."""

    IP = "ip"
    DOMAIN = "domain"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"


class Indicator(BaseModel):
    """A security indicator to be enriched."""

    value: str
    type: IndicatorType


class ProviderFinding(BaseModel):
    """Normalized result from a single threat intel provider."""

    provider: str
    malicious: bool | None
    confidence: float  # 0.0 to 1.0
    details: dict
    tags: list[str] = []
    reference_url: str | None = None


class Verdict(BaseModel):
    """Aggregated enrichment result across all providers."""

    indicator: Indicator
    risk_score: float  # 0.0 to 10.0
    risk_level: str  # clean / low / medium / high / critical
    findings: list[ProviderFinding]
    summary: str
    cached: bool = False
    queried_at: datetime
