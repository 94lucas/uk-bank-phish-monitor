"""Command-line interface.

    ukphish score <domain> [<domain> ...]   score domains and explain why
    ukphish stream                          watch CT logs in real time
    ukphish dnstwist                        run permutation scan for all brands
    ukphish top [--brand NAME] [--limit N]  show highest-scoring detections
    ukphish stats                           detections per brand
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path

from .config import load_settings
from .defang import defang
from .pipeline import Pipeline
from .scoring import score_domain
from .storage import DetectionStore


def load_dotenv(path: str | Path = ".env") -> None:
    """Minimal .env loader (KEY=VALUE lines). Existing env vars take precedence."""
    path = Path(path)
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if value.strip():
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def main(argv: list[str] | None = None) -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(prog="ukphish", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default=None, help="config directory")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    p_score = sub.add_parser("score", help="score one or more domains")
    p_score.add_argument("domains", nargs="+")
    sub.add_parser("stream", help="monitor Certificate Transparency logs")
    sub.add_parser("dnstwist", help="scan registered permutations of legit domains")
    p_top = sub.add_parser("top", help="show top detections")
    p_top.add_argument("--brand")
    p_top.add_argument("--limit", type=int, default=20)
    sub.add_parser("stats", help="detections per brand")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = load_settings(args.config)

    if args.command == "score":
        for d in args.domains:
            r = score_domain(d, settings)
            status = "ALLOWLISTED" if r.allowlisted else f"score={r.score} brand={r.brand}"
            print(f"{defang(r.domain)}  {status}")
            for reason in r.reasons:
                print(f"    - {reason}")
        return

    store = DetectionStore(settings.db_path)
    pipeline = Pipeline(settings, store)

    if args.command == "stream":
        from .collectors import certstream_collector
        certstream_collector.run(pipeline, settings.certstream_url)
    elif args.command == "dnstwist":
        from .collectors import dnstwist_collector
        dnstwist_collector.run(pipeline)
    elif args.command == "top":
        for row in store.top(limit=args.limit, brand=args.brand):
            reasons = "; ".join(json.loads(row["reasons"]))
            print(f"{row['score']:>4}  {row['brand']:<24} {defang(row['domain'])}  [{reasons}]")
    elif args.command == "stats":
        for row in store.stats_by_brand():
            print(f"{row['brand']:<24} total={row['total']:<6} max_score={row['max_score']}")


if __name__ == "__main__":
    main()
