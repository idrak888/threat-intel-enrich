"""Auto-detect indicator type from a raw string value."""

import ipaddress
import re

from enricher.core.models import Indicator, IndicatorType

# Regex patterns
_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
# Domain: labels separated by dots, each label is alphanumeric + hyphens (not starting/ending
# with hyphen), with at least one dot and a valid TLD (2+ alpha chars)
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}$"
)


class InvalidIndicatorError(ValueError):
    """Raised when an input string cannot be classified as any known indicator type."""


def detect(raw: str) -> Indicator:
    """Detect the indicator type for *raw* and return an :class:`Indicator`.

    Detection order (most-specific first):
    1. MD5 / SHA1 / SHA256 hashes (pure hex strings of fixed length)
    2. IPv4
    3. IPv6
    4. Domain

    Parameters
    ----------
    raw:
        The raw indicator string provided by the user.

    Returns
    -------
    Indicator
        A frozen dataclass with ``value`` (normalised) and ``type``.

    Raises
    ------
    InvalidIndicatorError
        If *raw* does not match any supported indicator pattern.
    """
    value = raw.strip()

    if not value:
        raise InvalidIndicatorError("Indicator cannot be empty.")

    # Hashes — check before domain/IP so that hex strings aren't misclassified
    if _MD5_RE.match(value):
        return Indicator(value=value.lower(), type=IndicatorType.HASH_MD5)
    if _SHA1_RE.match(value):
        return Indicator(value=value.lower(), type=IndicatorType.HASH_SHA1)
    if _SHA256_RE.match(value):
        return Indicator(value=value.lower(), type=IndicatorType.HASH_SHA256)

    # IPv4 / IPv6 — delegate to the stdlib for correctness (handles all edge cases)
    try:
        addr = ipaddress.ip_address(value)
        return Indicator(value=str(addr), type=IndicatorType.IP)
    except ValueError:
        pass

    # Domain
    if _DOMAIN_RE.match(value):
        return Indicator(value=value.lower(), type=IndicatorType.DOMAIN)

    raise InvalidIndicatorError(
        f"Could not detect indicator type for {value!r}. "
        "Supported formats: IPv4, IPv6, domain, MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex)."
    )
