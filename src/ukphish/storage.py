"""SQLite persistence for detections."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .scoring import ScoreResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS detections (
    domain      TEXT PRIMARY KEY,
    brand       TEXT,
    score       INTEGER NOT NULL,
    reasons     TEXT NOT NULL,
    source      TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    hits        INTEGER NOT NULL DEFAULT 1,
    status      TEXT NOT NULL DEFAULT 'new'   -- new | confirmed | benign | reported
);
CREATE INDEX IF NOT EXISTS idx_detections_brand ON detections(brand);
CREATE INDEX IF NOT EXISTS idx_detections_score ON detections(score);
"""


class DetectionStore:
    def __init__(self, path: str | Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # timeout + WAL let the stream and dnstwist containers share the file.
        self.conn = sqlite3.connect(path, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)

    def upsert(self, result: ScoreResult, source: str) -> bool:
        """Save a detection. Returns True if the domain is new."""
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        exists = self.conn.execute(
            "SELECT 1 FROM detections WHERE domain = ?", (result.domain,)
        ).fetchone()
        if exists:
            self.conn.execute(
                "UPDATE detections SET last_seen = ?, hits = hits + 1, "
                "score = MAX(score, ?) WHERE domain = ?",
                (now, result.score, result.domain),
            )
        else:
            self.conn.execute(
                "INSERT INTO detections (domain, brand, score, reasons, source, "
                "first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (result.domain, result.brand, result.score,
                 json.dumps(result.reasons), source, now, now),
            )
        self.conn.commit()
        return not exists

    def top(self, limit: int = 20, brand: str | None = None) -> list[sqlite3.Row]:
        query = "SELECT * FROM detections"
        params: list = []
        if brand:
            query += " WHERE brand = ?"
            params.append(brand)
        query += " ORDER BY score DESC, first_seen DESC LIMIT ?"
        params.append(limit)
        return self.conn.execute(query, params).fetchall()

    def stats_by_brand(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT brand, COUNT(*) AS total, MAX(score) AS max_score "
            "FROM detections GROUP BY brand ORDER BY total DESC"
        ).fetchall()
