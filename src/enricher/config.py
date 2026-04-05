"""Application configuration loaded from environment / .env file."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """API keys and runtime configuration."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    enricher_cache_ttl: int = 3600
