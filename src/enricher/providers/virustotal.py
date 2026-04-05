"""VirusTotal API v3 provider."""

import logging

import aiohttp

from enricher.core.models import Indicator, IndicatorType, ProviderFinding
from enricher.providers.base import BaseProvider

logger = logging.getLogger(__name__)

_BASE_URL = "https://www.virustotal.com/api/v3"
_TIMEOUT = aiohttp.ClientTimeout(total=10)


class VirusTotalProvider(BaseProvider):
    """Queries VirusTotal API v3 for IPs, domains, and file hashes."""

    name = "virustotal"
    supported_types = [
        IndicatorType.IP,
        IndicatorType.DOMAIN,
        IndicatorType.HASH_MD5,
        IndicatorType.HASH_SHA1,
        IndicatorType.HASH_SHA256,
    ]

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    def _endpoint(self, indicator: Indicator) -> str:
        """Return the VT API endpoint for the given indicator."""
        match indicator.type:
            case IndicatorType.IP:
                return f"{_BASE_URL}/ip_addresses/{indicator.value}"
            case IndicatorType.DOMAIN:
                return f"{_BASE_URL}/domains/{indicator.value}"
            case _:
                return f"{_BASE_URL}/files/{indicator.value}"

    def _reference_url(self, indicator: Indicator) -> str:
        """Return a VirusTotal GUI URL for the given indicator."""
        match indicator.type:
            case IndicatorType.IP:
                return f"https://www.virustotal.com/gui/ip-address/{indicator.value}"
            case IndicatorType.DOMAIN:
                return f"https://www.virustotal.com/gui/domain/{indicator.value}"
            case _:
                return f"https://www.virustotal.com/gui/file/{indicator.value}"

    async def lookup(
        self, indicator: Indicator, session: aiohttp.ClientSession
    ) -> ProviderFinding | None:
        """Query VirusTotal for the given indicator.

        Returns None if the indicator type is unsupported or the request fails.
        """
        if indicator.type not in self.supported_types:
            return None

        url = self._endpoint(indicator)
        headers = {"x-apikey": self._api_key}

        try:
            async with session.get(url, headers=headers, timeout=_TIMEOUT) as resp:
                if resp.status == 404:
                    logger.debug("VirusTotal: no record for %s", indicator.value)
                    return ProviderFinding(
                        provider=self.name,
                        malicious=None,
                        confidence=0.0,
                        details={"status": "not_found"},
                    )
                if resp.status != 200:
                    logger.warning(
                        "VirusTotal returned HTTP %s for %s", resp.status, indicator.value
                    )
                    return None

                data = await resp.json()
        except aiohttp.ClientError as exc:
            logger.warning("VirusTotal request failed for %s: %s", indicator.value, exc)
            return None

        return self._parse(data, indicator)

    def _parse(self, data: dict, indicator: Indicator) -> ProviderFinding:
        """Parse a successful VT API response into a ProviderFinding."""
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious_count = stats.get("malicious", 0)
        harmless_count = stats.get("harmless", 0)
        suspicious_count = stats.get("suspicious", 0)
        undetected_count = stats.get("undetected", 0)

        total = malicious_count + harmless_count + suspicious_count + undetected_count
        confidence = malicious_count / total if total > 0 else 0.0
        is_malicious = malicious_count > 0 or suspicious_count > 0

        tags: list[str] = attrs.get("tags", [])

        details = {
            "malicious_count": malicious_count,
            "harmless_count": harmless_count,
            "suspicious_count": suspicious_count,
            "undetected_count": undetected_count,
            "total_engines": total,
            "reputation": attrs.get("reputation"),
        }

        return ProviderFinding(
            provider=self.name,
            malicious=is_malicious,
            confidence=confidence,
            details=details,
            tags=tags,
            reference_url=self._reference_url(indicator),
        )
