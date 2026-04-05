"""SQLite-backed async cache with TTL."""

import json
import logging
import time
from pathlib import Path

import aiosqlite

logger = logging.getLogger(__name__)

_DEFAULT_TTL = 3600  # 1 hour
_DB_PATH = Path.home() / ".enricher" / "cache.db"


class Cache:
    """Async SQLite cache for provider API responses."""

    def __init__(self, db_path: Path = _DB_PATH, ttl: int = _DEFAULT_TTL) -> None:
        self._db_path = db_path
        self._ttl = ttl

    async def _connect(self) -> aiosqlite.Connection:
        """Open a connection, creating the DB file and table if needed."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = await aiosqlite.connect(self._db_path)
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cache (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                created_at REAL NOT NULL
            )
            """
        )
        await conn.commit()
        return conn

    @staticmethod
    def make_key(provider: str, indicator_type: str, indicator_value: str) -> str:
        """Return a canonical cache key."""
        return f"{provider}:{indicator_type}:{indicator_value}"

    async def get(self, key: str) -> dict | None:
        """Return the cached value for key, or None if missing or expired."""
        conn = await self._connect()
        try:
            async with conn.execute(
                "SELECT value, created_at FROM cache WHERE key = ?", (key,)
            ) as cursor:
                row = await cursor.fetchone()

            if row is None:
                return None

            value, created_at = row
            if time.time() - created_at > self._ttl:
                logger.debug("Cache expired for key %s", key)
                await self._delete(conn, key)
                return None

            return json.loads(value)
        finally:
            await conn.close()

    async def set(self, key: str, value: dict) -> None:
        """Store value under key, replacing any existing entry."""
        conn = await self._connect()
        try:
            await conn.execute(
                """
                INSERT INTO cache (key, value, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                               created_at = excluded.created_at
                """,
                (key, json.dumps(value), time.time()),
            )
            await conn.commit()
        finally:
            await conn.close()

    async def clear(self) -> None:
        """Delete all entries from the cache."""
        conn = await self._connect()
        try:
            await conn.execute("DELETE FROM cache")
            await conn.commit()
            logger.debug("Cache cleared")
        finally:
            await conn.close()

    @staticmethod
    async def _delete(conn: aiosqlite.Connection, key: str) -> None:
        await conn.execute("DELETE FROM cache WHERE key = ?", (key,))
        await conn.commit()
