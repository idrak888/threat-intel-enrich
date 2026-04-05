"""AbuseIPDB API v2 provider."""

import logging

import aiohttp

from enricher.core.models import Indicator, IndicatorType, ProviderFinding
from enricher.providers.base import BaseProvider

logger = logging.getLogger(__name__)

_BASE_URL = "https://api.abuseipdb.com/api/v2/check"
_TIMEOUT = aiohttp.ClientTimeout(total=10)


class AbuseIPDBProvider(BaseProvider):
    """Queries AbuseIPDB API v2 for IP addresses."""

    name = "abuseipdb"
    supported_types = [IndicatorType.IP]

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    async def lookup(
        self, indicator: Indicator, session: aiohttp.ClientSession
    ) -> ProviderFinding | None:
        """Query AbuseIPDB for the given indicator.

        Returns None if the indicator type is unsupported or the request fails.
        """
        if indicator.type not in self.supported_types:
            return None

        headers = {"Key": self._api_key, "Accept": "application/json"}
        params = {"ipAddress": indicator.value, "maxAgeInDays": 90}

        try:
            async with session.get(
                _BASE_URL, headers=headers, params=params, timeout=_TIMEOUT
            ) as resp:
                if resp.status != 200:
                    logger.warning(
                        "AbuseIPDB returned HTTP %s for %s", resp.status, indicator.value
                    )
                    return None

                data = await resp.json()
        except aiohttp.ClientError as exc:
            logger.warning("AbuseIPDB request failed for %s: %s", indicator.value, exc)
            return None

        return self._parse(data, indicator)

    def _parse(self, data: dict, indicator: Indicator) -> ProviderFinding:
        """Parse a successful AbuseIPDB API response into a ProviderFinding."""
        d = data.get("data", {})

        abuse_score = d.get("abuseConfidenceScore", 0)
        confidence = abuse_score / 100.0
        total_reports = d.get("totalReports", 0)
        is_whitelisted = d.get("isWhitelisted", False)

        # Whitelisted IPs are not considered malicious regardless of score
        is_malicious = not is_whitelisted and total_reports > 0

        tags: list[str] = []
        usage_type = d.get("usageType")
        if usage_type:
            tags.append(usage_type.lower().replace(" ", "-"))

        details = {
            "abuse_confidence_score": abuse_score,
            "total_reports": total_reports,
            "is_whitelisted": is_whitelisted,
            "isp": d.get("isp"),
            "usage_type": usage_type,
            "domain": d.get("domain"),
            "country_code": d.get("countryCode"),
        }

        return ProviderFinding(
            provider=self.name,
            malicious=is_malicious,
            confidence=confidence,
            details=details,
            tags=tags,
            reference_url=f"https://www.abuseipdb.com/check/{indicator.value}",
        )
