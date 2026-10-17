"""Load YAML configuration into simple dataclasses."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import os

import yaml


def _default_config_dir() -> Path:
    """Resolution order: $UKPHISH_CONFIG_DIR, ./config, then the repo layout
    (useful when running from source with an editable install)."""
    env = os.getenv("UKPHISH_CONFIG_DIR")
    if env:
        return Path(env)
    cwd = Path.cwd() / "config"
    if (cwd / "brands.yaml").is_file():
        return cwd
    return Path(__file__).resolve().parents[2] / "config"


@dataclass(frozen=True)
class Brand:
    name: str
    keywords: tuple[str, ...]
    legit_domains: tuple[str, ...]


@dataclass
class Settings:
    brands: list[Brand]
    weights: dict
    thresholds: dict
    suspicious_words: list[str]
    abused_tlds: set[str]
    certstream_url: str = "ws://localhost:8080/"
    db_path: str = "data/detections.db"


def load_settings(config_dir: Path | str | None = None) -> Settings:
    config_dir = Path(config_dir) if config_dir else _default_config_dir()
    brands_raw = yaml.safe_load((config_dir / "brands.yaml").read_text())
    settings_raw = yaml.safe_load((config_dir / "settings.yaml").read_text())

    brands = [
        Brand(
            name=b["name"],
            keywords=tuple(k.lower() for k in b["keywords"]),
            legit_domains=tuple(d.lower() for d in b["legit_domains"]),
        )
        for b in brands_raw["brands"]
    ]

    return Settings(
        brands=brands,
        weights=settings_raw["weights"],
        thresholds=settings_raw["thresholds"],
        suspicious_words=[w.lower() for w in settings_raw["suspicious_words"]],
        abused_tlds={t.lower() for t in settings_raw["abused_tlds"]},
        # Environment variables override the YAML (handy in Docker).
        certstream_url=os.getenv("CERTSTREAM_URL")
        or settings_raw.get("certstream", {}).get("url", "ws://localhost:8080/"),
        db_path=os.getenv("UKPHISH_DB_PATH")
        or settings_raw.get("database", {}).get("path", "data/detections.db"),
    )
