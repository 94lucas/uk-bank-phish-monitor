"""Real-time collector for Certificate Transparency logs via certstream.

Works with the public certstream server or a local certstream-server-go
instance (recommended, see docker-compose.yml).
"""

from __future__ import annotations

import logging
from collections import OrderedDict

import certstream

from ..pipeline import Pipeline

log = logging.getLogger(__name__)


class SeenCache:
    """Bounded cache so the same domain is not re-scored thousands of times."""

    def __init__(self, maxsize: int = 200_000):
        self.maxsize = maxsize
        self._data: OrderedDict[str, None] = OrderedDict()

    def add(self, key: str) -> bool:
        """Returns True if the key was not seen before."""
        if key in self._data:
            self._data.move_to_end(key)
            return False
        self._data[key] = None
        if len(self._data) > self.maxsize:
            self._data.popitem(last=False)
        return True


def run(pipeline: Pipeline, url: str) -> None:
    seen = SeenCache()

    def callback(message: dict, context) -> None:
        if message.get("message_type") != "certificate_update":
            return
        domains = message["data"]["leaf_cert"].get("all_domains", [])
        for domain in domains:
            if seen.add(domain):
                pipeline.process(domain, source="certstream")

    log.info("Connecting to certstream at %s", url)
    certstream.listen_for_events(callback, url=url, skip_heartbeats=True)
