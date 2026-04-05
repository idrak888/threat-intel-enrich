# Threat Intel Enrichment Tool

## Project Overview
A CLI tool that takes a security indicator (IP address, domain, or file hash), queries multiple threat intelligence sources in parallel, normalizes the results, and outputs a consolidated risk verdict with a confidence score.

**Target user:** Any security analyst across Global Security (SOC, IR, cloud sec, vuln management).
**Core value prop:** "I have an indicator — is it bad?" answered in one command.

## Tech Stack
- **Language:** Python 3.11+
- **Async:** asyncio + aiohttp for parallel API calls
- **CLI framework:** Click
- **Output formatting:** Rich (for terminal tables/colors)
- **Caching:** SQLite via aiosqlite (cache API responses to avoid rate limits)
- **Config:** pydantic-settings for API key management (.env file)
- **Testing:** pytest + pytest-asyncio

## Architecture

```
threat-intel-enrich/
├── CLAUDE.md
├── README.md
├── pyproject.toml
├── .env.example
├── src/
│   └── enricher/
│       ├── __init__.py
│       ├── cli.py              # Click CLI entrypoint
│       ├── core/
│       │   ├── __init__.py
│       │   ├── models.py       # Pydantic models for indicators, findings, verdicts
│       │   ├── enrich.py       # Main orchestrator — fans out to providers, aggregates results
│       │   └── scoring.py      # Scoring algorithm that weighs results across sources
│       ├── providers/
│       │   ├── __init__.py
│       │   ├── base.py         # Abstract base class for all intel providers
│       │   ├── virustotal.py   # VirusTotal API v3 integration
│       │   └── abuseipdb.py    # AbuseIPDB API v2 integration
│       ├── cache/
│       │   ├── __init__.py
│       │   └── sqlite.py       # SQLite-backed async cache with TTL
│       └── utils/
│           ├── __init__.py
│           └── indicators.py   # Auto-detect indicator type (IP, domain, hash)
└── tests/
    ├── __init__.py
    ├── conftest.py             # Shared fixtures, mock API responses
    ├── test_indicators.py      # Test indicator type detection
    ├── test_scoring.py         # Test scoring logic
    ├── test_virustotal.py      # Test VT provider with mocked responses
    ├── test_abuseipdb.py       # Test AbuseIPDB provider with mocked responses
    └── test_enrich.py          # Integration test for full enrichment flow
```

## Data Models

### IndicatorType (Enum)
- `IP` — IPv4/IPv6 address
- `DOMAIN` — domain name
- `HASH_MD5` — MD5 file hash
- `HASH_SHA1` — SHA1 file hash
- `HASH_SHA256` — SHA256 file hash

### Indicator (Pydantic model)
- `value: str` — the raw indicator string
- `type: IndicatorType` — auto-detected type

### ProviderFinding (Pydantic model)
- `provider: str` — source name ("virustotal", "abuseipdb")
- `malicious: bool | None` — true/false/unknown
- `confidence: float` — 0.0 to 1.0, how confident the provider is
- `details: dict` — provider-specific raw details
- `tags: list[str]` — e.g., ["malware", "c2", "phishing"]
- `reference_url: str | None` — link to the provider's page for this indicator

### Verdict (Pydantic model)
- `indicator: Indicator`
- `risk_score: float` — 0.0 (clean) to 10.0 (critical)
- `risk_level: str` — "clean", "low", "medium", "high", "critical"
- `findings: list[ProviderFinding]`
- `summary: str` — one-line human-readable summary
- `cached: bool` — whether this result came from cache
- `queried_at: datetime`

## Indicator Auto-Detection Logic (`utils/indicators.py`)
- IPv4: regex match for dotted quad
- IPv6: regex match for colon-hex format
- Domain: contains a dot, no spaces, not an IP, valid TLD
- MD5: 32 hex characters
- SHA1: 40 hex characters
- SHA256: 64 hex characters
- Raise a clear error if the input doesn't match any pattern

## Provider Interface (`providers/base.py`)
Abstract base class that every provider must implement:
```python
class BaseProvider(ABC):
    name: str  # e.g., "virustotal"
    supported_types: list[IndicatorType]  # what indicator types this provider handles

    async def lookup(self, indicator: Indicator, session: aiohttp.ClientSession) -> ProviderFinding | None:
        """Query this provider for the given indicator. Return None if not supported or rate limited."""
```

## Provider Details

### VirusTotal (`providers/virustotal.py`)
- **API:** v3 — `https://www.virustotal.com/api/v3/`
- **Endpoints:**
  - IP: `GET /ip_addresses/{ip}`
  - Domain: `GET /domains/{domain}`
  - Hash: `GET /files/{hash}`
- **Auth:** `x-apikey` header
- **Rate limit:** 4 requests/min on free tier — respect this
- **Key response fields to extract:**
  - `last_analysis_stats.malicious` / `last_analysis_stats.harmless` — use ratio for confidence
  - `reputation` score
  - `tags` if present
- **Confidence calculation:** `malicious_count / total_engines`
- **Supported types:** IP, DOMAIN, HASH_MD5, HASH_SHA1, HASH_SHA256

### AbuseIPDB (`providers/abuseipdb.py`)
- **API:** v2 — `https://api.abuseipdb.com/api/v2/check`
- **Auth:** `Key` header
- **Rate limit:** 1000 checks/day on free tier
- **Key response fields:**
  - `abuseConfidenceScore` — 0-100, map to 0.0-1.0
  - `totalReports`
  - `isWhitelisted`
  - `usageType`, `isp`, `domain`
- **Supported types:** IP only (skip gracefully for domains/hashes)

## Scoring Algorithm (`core/scoring.py`)
Takes a list of `ProviderFinding` results and produces a risk score 0.0-10.0:

1. For each finding where `malicious` is True, add `confidence * provider_weight`
2. Provider weights (configurable): `virustotal=0.6, abuseipdb=0.4`
3. Normalize the weighted sum to a 0-10 scale
4. Map to risk levels:
   - 0.0-1.0: "clean"
   - 1.1-3.0: "low"
   - 3.1-5.0: "medium"
   - 5.1-7.0: "high"
   - 7.1-10.0: "critical"
5. Generate a one-line summary: e.g., "High risk (7.2/10) — flagged as malicious by VirusTotal (43/70 engines), reported 12 times on AbuseIPDB"

## Cache (`cache/sqlite.py`)
- SQLite database at `~/.enricher/cache.db`
- Table: `cache(key TEXT PRIMARY KEY, value TEXT, created_at REAL)`
- Key format: `{provider}:{indicator_type}:{indicator_value}`
- Default TTL: 1 hour (configurable)
- Async using aiosqlite
- Methods: `get(key) -> dict | None`, `set(key, value)`, `clear()`
- CLI flag `--no-cache` to bypass

## CLI Interface (`cli.py`)

### Main command
```
$ enrich <indicator> [OPTIONS]
```

### Options
- `--no-cache` — skip cache, force fresh queries
- `--json` — output raw JSON instead of formatted table
- `--verbose` / `-v` — show per-provider details

### Example output (default)
```
╭─────────────────────────────────────────────╮
│ Threat Intel Report: 185.220.101.34         │
│ Type: IPv4 Address                          │
├─────────────────────────────────────────────┤
│ Risk Score: 8.4 / 10 — CRITICAL            │
│                                             │
│ VirusTotal:  malicious (12/87 engines)      │
│ AbuseIPDB:   reported 247 times (score: 95) │
│                                             │
│ Tags: tor-exit-node, malware, scanner       │
│                                             │
│ Links:                                      │
│ • VT: https://virustotal.com/...            │
│ • Abuse: https://abuseipdb.com/...          │
╰─────────────────────────────────────────────╯
```

### Example output (--json)
Print the `Verdict` model as formatted JSON.

## Configuration
Use a `.env` file for API keys:
```
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
ENRICHER_CACHE_TTL=3600
```

Load via pydantic-settings `BaseSettings` class with `env_file=".env"`.

## Error Handling
- If a provider API key is missing: skip that provider, warn the user, continue with others
- If a provider returns an error or times out (10s timeout): log warning, return None from that provider
- If ALL providers fail: show an error with details on what went wrong
- If indicator type isn't recognized: show a clear error with supported formats
- Never crash with a traceback — always show human-readable errors via Click

## Testing Strategy
- Mock all API responses using aiohttp test utilities or `aioresponses`
- Test indicator detection with edge cases (IPv6, internationalized domains, mixed case hashes)
- Test scoring with various combinations of findings
- Test cache TTL expiry
- Test graceful degradation when providers fail

## Code Style
- Type hints everywhere
- Docstrings on all public functions
- No hardcoded API keys anywhere — not in code, not in tests
- Use `logging` module with configurable verbosity
- Format with `ruff`

## Future Enhancements (do NOT build these now)
- Shodan and OTX AlienVault providers
- FastAPI web UI
- Slack bot integration (`/enrich` slash command)
- Bulk enrichment from CSV
- STIX/TAXII output format