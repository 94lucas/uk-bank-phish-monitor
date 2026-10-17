"""Glue between collectors, scoring, storage and notifications."""

from __future__ import annotations

from .alerts import notify
from .config import Settings
from .scoring import ScoreResult, score_domain
from .storage import DetectionStore


class Pipeline:
    def __init__(self, settings: Settings, store: DetectionStore):
        self.settings = settings
        self.store = store

    def process(self, domain: str, source: str) -> ScoreResult:
        result = score_domain(domain, self.settings)
        if result.allowlisted or result.score < self.settings.thresholds["store"]:
            return result
        if self.store.upsert(result, source):  # only notify on first sighting
            notify(result, source, self.settings.thresholds)
        return result
