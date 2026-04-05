"""Abstract base class for all threat intel providers."""

from abc import ABC, abstractmethod

import aiohttp

from enricher.core.models import Indicator, IndicatorType, ProviderFinding


class BaseProvider(ABC):
    """Base class every provider must subclass."""

    name: str
    supported_types: list[IndicatorType]

    @abstractmethod
    async def lookup(
        self, indicator: Indicator, session: aiohttp.ClientSession
    ) -> ProviderFinding | None:
        """Query this provider for the given indicator.

        Returns None if the indicator type is not supported or the request fails.
        """
