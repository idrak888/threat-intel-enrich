"""Main orchestrator — fans out to providers, aggregates results into a Verdict."""

import logging
from datetime import datetime, timezone

import aiohttp

from enricher.cache.sqlite import Cache
from enricher.core.models import Indicator, ProviderFinding, Verdict
from enricher.core.scoring import calculate_score, risk_level, summarize
from enricher.providers.base import BaseProvider

logger = logging.getLogger(__name__)


async def enrich(
    indicator: Indicator,
    providers: list[BaseProvider],
    cache: Cache,
    use_cache: bool = True,
) -> Verdict:
    """Query all providers for *indicator* and return an aggregated Verdict.

    Providers are queried in parallel. Results are cached per provider.
    """
    findings: list[ProviderFinding] = []

    async with aiohttp.ClientSession() as session:
        import asyncio

        tasks = [
            _lookup_with_cache(provider, indicator, session, cache, use_cache)
            for provider in providers
        ]
        results = await asyncio.gather(*tasks)

    for result in results:
        if result is not None:
            findings.append(result)

    if not findings:
        logger.warning("All providers returned no data for %s", indicator.value)

    score = calculate_score(findings)
    return Verdict(
        indicator=indicator,
        risk_score=score,
        risk_level=risk_level(score),
        findings=findings,
        summary=summarize(score, findings),
        cached=False,
        queried_at=datetime.now(timezone.utc),
    )


async def _lookup_with_cache(
    provider: BaseProvider,
    indicator: Indicator,
    session: aiohttp.ClientSession,
    cache: Cache,
    use_cache: bool,
) -> ProviderFinding | None:
    """Wrap a provider lookup with cache read/write."""
    cache_key = Cache.make_key(provider.name, indicator.type.value, indicator.value)

    if use_cache:
        cached = await cache.get(cache_key)
        if cached is not None:
            logger.debug("Cache hit for %s", cache_key)
            return ProviderFinding.model_validate(cached)

    finding = await provider.lookup(indicator, session)

    if finding is not None and use_cache:
        await cache.set(cache_key, finding.model_dump())

    return finding
