"""Notification outputs.

Two modes, chosen by environment variables:

1. n8n (recommended): every NEW detection at or above the storage threshold is
   POSTed to an n8n webhook. The n8n workflow enriches it (RDAP, DNS), decides
   whether it deserves an alert and sends it to Telegram.
       N8N_WEBHOOK_URL    e.g. http://localhost:5678/webhook/ukphish-detection
       N8N_WEBHOOK_TOKEN  optional, sent as the X-UKPhish-Token header

2. Direct Telegram (fallback, used only when N8N_WEBHOOK_URL is not set):
   detections at or above the alert threshold go straight to Telegram.
       TELEGRAM_BOT_TOKEN  from @BotFather
       TELEGRAM_CHAT_ID    your user, group or channel id

Alerts are always printed to the console as well. Indicators are defanged in
every human-facing message; the raw domain is only sent to n8n, which needs it
for lookups.
"""

from __future__ import annotations

import html
import json
import logging
import os
import urllib.request
from datetime import datetime, timezone

from .defang import defang
from .scoring import ScoreResult

log = logging.getLogger(__name__)


def build_payload(result: ScoreResult, source: str, thresholds: dict) -> dict:
    return {
        "domain": result.domain,
        "domain_defanged": defang(result.domain),
        "brand": result.brand,
        "score": result.score,
        "reasons": result.reasons,
        "source": source,
        "detected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "store_threshold": thresholds["store"],
        "alert_threshold": thresholds["alert"],
    }


def format_console(result: ScoreResult, source: str) -> str:
    reasons = "\n".join(f"  - {r}" for r in result.reasons)
    return (
        f"[DETECTION] score={result.score} brand={result.brand} source={source}\n"
        f"  domain: {defang(result.domain)}\n{reasons}"
    )


def format_telegram(result: ScoreResult, source: str) -> str:
    """Telegram message in HTML parse mode (all dynamic text is escaped)."""
    e = html.escape
    reasons = "\n".join(f"• {e(r)}" for r in result.reasons)
    return (
        f"🚨 <b>Possible {e(result.brand or 'unknown')} phishing domain</b>\n\n"
        f"<b>Domain:</b> <code>{e(defang(result.domain))}</code>\n"
        f"<b>Score:</b> {result.score}\n"
        f"<b>Source:</b> {e(source)}\n\n"
        f"<b>Why:</b>\n{reasons}"
    )


def _post_json(url: str, payload: dict, headers: dict | None = None) -> None:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    urllib.request.urlopen(req, timeout=10)


def send_to_n8n(payload: dict) -> None:
    headers = {}
    token = os.getenv("N8N_WEBHOOK_TOKEN")
    if token:
        headers["X-UKPhish-Token"] = token
    _post_json(os.environ["N8N_WEBHOOK_URL"], payload, headers)


def send_to_telegram(text: str) -> None:
    token = os.environ["TELEGRAM_BOT_TOKEN"]
    _post_json(
        f"https://api.telegram.org/bot{token}/sendMessage",
        {
            "chat_id": os.environ["TELEGRAM_CHAT_ID"],
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        },
    )


def notify(result: ScoreResult, source: str, thresholds: dict) -> None:
    """Called for every NEW detection at or above the storage threshold.
    Notification failures are logged and never crash the collector."""
    is_alert = result.score >= thresholds["alert"]
    if is_alert:
        print(format_console(result, source), flush=True)

    try:
        if os.getenv("N8N_WEBHOOK_URL"):
            send_to_n8n(build_payload(result, source, thresholds))
        elif is_alert and os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_CHAT_ID"):
            send_to_telegram(format_telegram(result, source))
    except Exception as exc:
        log.warning("Notification failed for %s: %s", defang(result.domain), exc)
