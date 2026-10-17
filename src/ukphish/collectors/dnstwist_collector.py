"""Daily collector: generate look-alike permutations of each legit domain with
dnstwist and keep only those that are actually registered.

Requires the dnstwist CLI (pip install dnstwist).
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess

from ..pipeline import Pipeline

log = logging.getLogger(__name__)


def registered_permutations(domain: str, timeout: int = 900) -> list[str]:
    if not shutil.which("dnstwist"):
        raise RuntimeError("dnstwist not found. Install it with: pip install dnstwist")
    proc = subprocess.run(
        ["dnstwist", "--registered", "--format", "json", domain],
        capture_output=True, text=True, timeout=timeout, check=True,
    )
    rows = json.loads(proc.stdout or "[]")
    return [r["domain"] for r in rows if r.get("fuzzer") != "*original"]


def run(pipeline: Pipeline) -> None:
    for brand in pipeline.settings.brands:
        for legit in brand.legit_domains:
            log.info("dnstwist: %s (%s)", legit, brand.name)
            try:
                for candidate in registered_permutations(legit):
                    pipeline.process(candidate, source="dnstwist")
            except (subprocess.SubprocessError, RuntimeError) as exc:
                log.warning("dnstwist failed for %s: %s", legit, exc)
