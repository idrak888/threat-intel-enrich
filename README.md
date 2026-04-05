# threat-intel-enrich

A CLI tool for security analysts. Give it an IP, domain, or file hash — get back a consolidated risk verdict with a confidence score, queried from multiple threat intel sources in parallel.

```
$ enrich 185.220.101.34
╭─────────────────────────────────────────────────╮
│ Threat Intel Report: 185.220.101.34             │
│ Type: Ip                                        │
│                                                 │
│ Risk Score: 8.4 / 10 — CRITICAL                │
│                                                 │
│ Virustotal:  malicious (12/87 engines)          │
│ Abuseipdb:   reported 247 times (score: 95)     │
│                                                 │
│ Tags: tor-exit-node, data-center/web-hosting    │
│                                                 │
│ Links:                                          │
│   • Virustotal: https://virustotal.com/gui/...  │
│   • Abuseipdb:  https://abuseipdb.com/check/…  │
╰─────────────────────────────────────────────────╯
```

## Features

- **Parallel queries** — all providers are called concurrently via `asyncio`
- **Auto-detection** — IPv4, IPv6, domains, MD5, SHA1, SHA256 are detected automatically
- **SQLite cache** — responses cached at `~/.enricher/cache.db` to respect rate limits (TTL: 1 hour by default)
- **Weighted scoring** — VirusTotal (60%) + AbuseIPDB (40%) produce a single 0–10 risk score
- **Rich terminal output** — colour-coded panel or `--json` for piping into other tools
- **Graceful degradation** — missing API keys or provider errors skip that source; the tool continues with the rest

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    CLI  (cli.py)                    │
│  click command → detect indicator → call enrich()   │
└───────────────────────┬─────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│               Orchestrator  (core/enrich.py)        │
│                                                     │
│   asyncio.gather() ──► provider_1.lookup()          │
│                   └──► provider_2.lookup()          │
│                                                     │
│   Each call wrapped with cache read/write           │
└──────┬────────────────────────┬────────────────────-┘
       │                        │
       ▼                        ▼
┌─────────────┐        ┌─────────────────┐
│  VirusTotal │        │   AbuseIPDB     │
│  (API v3)   │        │   (API v2)      │
│             │        │  IP only        │
└──────┬──────┘        └───────┬─────────┘
       │                       │
       └──────────┬────────────┘
                  │  list[ProviderFinding]
                  ▼
┌─────────────────────────────────────────────────────┐
│               Scoring  (core/scoring.py)            │
│                                                     │
│   weighted_sum = Σ confidence × provider_weight     │
│   risk_score   = (weighted_sum / total_weight) × 10 │
│                                                     │
│   Weights: virustotal=0.6  abuseipdb=0.4            │
└──────────────────────┬──────────────────────────────┘
                       │  Verdict
                       ▼
              Rich panel  /  JSON output

Cache layer (cache/sqlite.py)
  ~/.enricher/cache.db
  key = {provider}:{indicator_type}:{indicator_value}
  TTL  = ENRICHER_CACHE_TTL (default 3600 s)
```

### Module map

```
src/enricher/
├── cli.py               Click entrypoint, Rich rendering
├── config.py            pydantic-settings — loads .env
├── core/
│   ├── models.py        Indicator, ProviderFinding, Verdict (Pydantic)
│   ├── enrich.py        Orchestrator — parallel fan-out + cache
│   └── scoring.py       Weighted score, risk level, summary line
├── providers/
│   ├── base.py          BaseProvider ABC
│   ├── virustotal.py    VirusTotal API v3 (IP, domain, hash)
│   └── abuseipdb.py     AbuseIPDB API v2 (IP only)
├── cache/
│   └── sqlite.py        Async SQLite cache with TTL
└── utils/
    └── indicators.py    Indicator type auto-detection
```

## Installation

Requires Python 3.11+.

```bash
git clone <repo>
cd threat-intel-enrich
pip install -e .
```

For development (linting + tests):

```bash
pip install -e ".[dev]"
```

## Configuration

Copy `.env.example` to `.env` and fill in your keys:

```bash
cp .env.example .env
```

```dotenv
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
ENRICHER_CACHE_TTL=3600
```

- **VirusTotal** free key: https://www.virustotal.com/gui/join-us (4 req/min)
- **AbuseIPDB** free key: https://www.abuseipdb.com/account/api (1 000 checks/day)

The tool works with just one key configured — it warns about the missing provider and continues.

## Usage

```bash
# Enrich an IP address
enrich 185.220.101.34

# Enrich a domain
enrich malware-c2.example.com

# Enrich a file hash (MD5 / SHA1 / SHA256)
enrich 44d88612fea8a8f36de82e1278abb02f

# Skip cache (force fresh queries)
enrich 185.220.101.34 --no-cache

# Machine-readable JSON output
enrich 185.220.101.34 --json

# Per-provider detail breakdown
enrich 185.220.101.34 --verbose
```

### Example outputs

**Default (Rich panel)**
```
╭──────────────────────────────────────────────────────╮
│ Threat Intel Report: 44d88612fea8a8f36de82e1278abb02f│
│ Type: Hash Md5                                       │
│                                                      │
│ Risk Score: 6.0 / 10 — HIGH                         │
│                                                      │
│ Virustotal:  malicious (43/70 engines)               │
│                                                      │
│ Tags: trojan, ransomware                             │
│                                                      │
│ Links:                                               │
│   • Virustotal: https://virustotal.com/gui/file/...  │
╰──────────────────────────────────────────────────────╯
```

**`--json`**
```json
{
  "indicator": {
    "value": "44d88612fea8a8f36de82e1278abb02f",
    "type": "hash_md5"
  },
  "risk_score": 6.0,
  "risk_level": "high",
  "findings": [
    {
      "provider": "virustotal",
      "malicious": true,
      "confidence": 0.614,
      "details": {
        "malicious_count": 43,
        "harmless_count": 0,
        "suspicious_count": 2,
        "undetected_count": 25,
        "total_engines": 70,
        "reputation": -50
      },
      "tags": ["trojan", "ransomware"],
      "reference_url": "https://www.virustotal.com/gui/file/44d88612fea8a8f36de82e1278abb02f"
    }
  ],
  "summary": "High risk (6.0/10) — flagged as malicious by VirusTotal (43/70 engines)",
  "cached": false,
  "queried_at": "2026-04-03T10:22:01.456Z"
}
```

## Risk Score Reference

| Score   | Level    |
|---------|----------|
| 0–1.0   | clean    |
| 1.1–3.0 | low      |
| 3.1–5.0 | medium   |
| 5.1–7.0 | high     |
| 7.1–10  | critical |

## Running Tests

```bash
pytest
```

All provider tests use mocked HTTP responses (`aioresponses`) — no live API calls.

## Adding a Provider

1. Subclass `BaseProvider` in `src/enricher/providers/`
2. Set `name`, `supported_types`, implement `lookup()`
3. Instantiate it in `cli.py`'s `_build_providers()`

The orchestrator, cache, and scoring engine pick it up automatically.
