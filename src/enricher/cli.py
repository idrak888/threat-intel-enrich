"""Click CLI entrypoint for the threat intel enrichment tool."""

import asyncio
import json
import logging

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from enricher.cache.sqlite import Cache
from enricher.config import Settings
from enricher.core.enrich import enrich
from enricher.core.models import Verdict
from enricher.providers.abuseipdb import AbuseIPDBProvider
from enricher.providers.base import BaseProvider
from enricher.providers.virustotal import VirusTotalProvider
from enricher.utils.indicators import InvalidIndicatorError, detect

console = Console()

_RISK_COLORS = {
    "clean": "green",
    "low": "yellow",
    "medium": "orange3",
    "high": "red",
    "critical": "bright_red",
}


def _build_providers(settings: Settings) -> list[BaseProvider]:
    """Instantiate available providers based on configured API keys."""
    providers: list[BaseProvider] = []

    if settings.virustotal_api_key:
        providers.append(VirusTotalProvider(settings.virustotal_api_key))
    else:
        console.print("[yellow]Warning:[/] VIRUSTOTAL_API_KEY not set — skipping VirusTotal.")

    if settings.abuseipdb_api_key:
        providers.append(AbuseIPDBProvider(settings.abuseipdb_api_key))
    else:
        console.print("[yellow]Warning:[/] ABUSEIPDB_API_KEY not set — skipping AbuseIPDB.")

    return providers


def _render_verdict(verdict: Verdict, verbose: bool) -> None:
    """Render a Verdict as a Rich panel to the terminal."""
    level = verdict.risk_level
    color = _RISK_COLORS.get(level, "white")
    score_str = f"{verdict.risk_score} / 10"

    lines: list[str] = []
    lines.append(f"[bold]Type:[/] {verdict.indicator.type.value.replace('_', ' ').title()}")
    lines.append("")
    lines.append(
        f"[bold]Risk Score:[/] [{color}]{score_str} — {level.upper()}[/{color}]"
    )

    if verdict.cached:
        lines.append("[dim](cached result)[/dim]")

    lines.append("")

    for finding in verdict.findings:
        provider_label = finding.provider.title()
        if finding.malicious is None:
            lines.append(f"[bold]{provider_label}:[/]  no data")
            continue

        status_color = color if finding.malicious else "green"
        if finding.provider == "virustotal":
            total = finding.details.get("total_engines", 0)
            mal = finding.details.get("malicious_count", 0)
            status = f"malicious ({mal}/{total} engines)" if finding.malicious else f"clean (0/{total} engines)"
        elif finding.provider == "abuseipdb":
            reports = finding.details.get("total_reports", 0)
            score = finding.details.get("abuse_confidence_score", 0)
            status = f"reported {reports} times (score: {score})" if finding.malicious else "no reports"
        else:
            status = "malicious" if finding.malicious else "clean"

        lines.append(f"[bold]{provider_label}:[/]  [{status_color}]{status}[/{status_color}]")

        if verbose:
            for k, v in finding.details.items():
                if v is not None:
                    lines.append(f"  [dim]{k}:[/dim] {v}")

    all_tags = sorted({tag for f in verdict.findings for tag in f.tags})
    if all_tags:
        lines.append("")
        lines.append(f"[bold]Tags:[/] {', '.join(all_tags)}")

    ref_urls = [(f.provider, f.reference_url) for f in verdict.findings if f.reference_url]
    if ref_urls:
        lines.append("")
        lines.append("[bold]Links:[/]")
        for provider, url in ref_urls:
            lines.append(f"  • {provider.title()}: {url}")

    body = "\n".join(lines)
    panel = Panel(
        body,
        title=f"[bold]Threat Intel Report: {verdict.indicator.value}[/bold]",
        box=box.ROUNDED,
        expand=False,
    )
    console.print(panel)


@click.command()
@click.argument("indicator")
@click.option("--no-cache", is_flag=True, default=False, help="Skip cache, force fresh queries.")
@click.option("--json", "output_json", is_flag=True, default=False, help="Output raw JSON.")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Show per-provider details.")
def cli(indicator: str, no_cache: bool, output_json: bool, verbose: bool) -> None:
    """Enrich a security indicator (IP, domain, or file hash) against threat intel sources."""
    logging.basicConfig(level=logging.WARNING)

    settings = Settings()
    providers = _build_providers(settings)

    if not providers:
        console.print("[red]Error:[/] No API keys configured. Set at least one in your .env file.")
        raise SystemExit(1)

    try:
        parsed = detect(indicator)
    except InvalidIndicatorError as exc:
        console.print(f"[red]Error:[/] {exc}")
        raise SystemExit(1)

    cache = Cache(ttl=settings.enricher_cache_ttl)

    try:
        verdict = asyncio.run(
            enrich(parsed, providers, cache, use_cache=not no_cache)
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Error:[/] Enrichment failed — {exc}")
        raise SystemExit(1)

    if output_json:
        click.echo(verdict.model_dump_json(indent=2))
    else:
        _render_verdict(verdict, verbose=verbose)
