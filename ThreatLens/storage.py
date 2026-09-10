"""SQLite TTL cache; each transactional operation explicitly closes its connection."""

import hashlib
import json
import logging
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

logger = logging.getLogger("threatlens")


class Cache:
    def __init__(self, directory: Path, enabled=True, clock=time.time):
        self.enabled = enabled
        self.clock = clock
        self.path = directory / "cache.sqlite3"
        if enabled:
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                with self.connection() as db:
                    db.execute(
                        "CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, body TEXT NOT NULL, expires REAL NOT NULL, saved REAL NOT NULL)"
                    )
                    db.execute("DELETE FROM cache WHERE expires < ?", (clock() - 30 * 86400,))
            except sqlite3.Error:
                raise ValueError(
                    "Cannot open cache database; use --no-cache or a writable --data-dir, and inspect the existing cache"
                ) from None
            self.path.chmod(0o600)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def key(namespace: str, value: str):
        return namespace + ":" + hashlib.sha256(value.encode()).hexdigest()

    def get(self, namespace, value, *, stale=False):
        if not self.enabled:
            return None
        try:
            with self.connection() as db:
                row = db.execute(
                    "SELECT body, expires, saved FROM cache WHERE key=?",
                    (self.key(namespace, value),),
                ).fetchone()
            if not row or (not stale and row[1] <= self.clock()):
                return None
            return {"value": json.loads(row[0]), "stale": row[1] <= self.clock(), "saved": row[2]}
        except (sqlite3.Error, ValueError):
            logger.warning("Cache read failed; treating entry as a miss")
            return None

    def put(self, namespace, value, payload, ttl):
        if not self.enabled:
            return
        try:
            with self.connection() as db:
                db.execute(
                    "INSERT OR REPLACE INTO cache VALUES (?,?,?,?)",
                    (
                        self.key(namespace, value),
                        json.dumps(payload),
                        self.clock() + ttl,
                        self.clock(),
                    ),
                )
        except (sqlite3.Error, TypeError, ValueError):
            logger.warning("Cache write failed; scan results remain available")

    def clear(self):
        if self.enabled:
            try:
                with self.connection() as db:
                    db.execute("DELETE FROM cache")
            except sqlite3.Error:
                raise ValueError("Unable to clear cache database") from None
