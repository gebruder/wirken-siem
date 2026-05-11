"""Webhook consumer for Wirken 1.3.x audit events.

Verifies ``X-Wirken-Signature: sha256=<hex>`` over the raw POST
body bytes (the wirken webhook builder factors the body and the
HMAC from a single ``serde_json::to_vec`` call; receivers must
recompute over the same wire bytes, never over a re-parsed
envelope), then evaluates each event in the JSON array against
``rules.evaluate``. Matches are emitted as NDJSON to stdout, one
line per match.

Usage::

    consumer.py --port 9000 --secret $WIRKEN_WEBHOOK_SECRET \\
                --skill-dirs ~/.wirken/skills/

Environment::

    WIRKEN_WEBHOOK_SECRET   (alternative to --secret)
    WIRKEN_SKILL_DIRS       (alternative to --skill-dirs, comma-
                             separated)
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
import os
import sys
from collections.abc import Iterable

from flask import Flask, abort, request

import rules


def _constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def verify_signature(raw_body: bytes, header_value: str | None, secret: str) -> bool:
    """Return True if the X-Wirken-Signature header matches an
    HMAC-SHA-256 over ``raw_body`` keyed by ``secret``. Returns
    False on any malformed header, missing prefix, or mismatch.

    Wire format: ``sha256=<hex>`` (lowercase hex, 64 chars).
    """
    if not header_value or not header_value.startswith("sha256="):
        return False
    presented = header_value[len("sha256="):]
    expected = hmac.new(
        secret.encode("utf-8"), raw_body, hashlib.sha256
    ).hexdigest()
    return _constant_time_eq(presented, expected)


def make_app(secret: str, skill_dirs: list[str], logger: logging.Logger) -> Flask:
    app = Flask(__name__)

    @app.post("/")
    def receive():  # pyright: ignore[reportUnusedFunction]
        raw = request.get_data(cache=False, as_text=False)
        header = request.headers.get("X-Wirken-Signature")
        if secret and not verify_signature(raw, header, secret):
            logger.warning("HMAC verification failed; rejecting")
            abort(401)
        try:
            events = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as e:
            logger.warning("body is not JSON: %s", e)
            abort(400)
        if not isinstance(events, list):
            logger.warning("body is JSON but not an array")
            abort(400)
        emitted = 0
        for event in events:
            if not isinstance(event, dict):
                continue
            for match in rules.evaluate(event, skill_dirs):
                sys.stdout.write(json.dumps(match) + "\n")
                emitted += 1
        sys.stdout.flush()
        return {"received": len(events), "matches": emitted}

    return app


def _parse_skill_dirs(arg: str | None, env: str | None) -> list[str]:
    raw = arg or env or ""
    return [d.strip() for d in raw.split(",") if d.strip()]


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--secret",
        default=os.environ.get("WIRKEN_WEBHOOK_SECRET", ""),
        help="HMAC secret. Required unless the wirken side runs "
        "without `hmac_secret`, in which case detections cannot "
        "verify provenance and the receiver must be on a private "
        "network.",
    )
    parser.add_argument(
        "--skill-dirs",
        default=os.environ.get("WIRKEN_SKILL_DIRS", ""),
        help="Comma-separated list of skill directory prefixes "
        "for Detection 4. Empty disables that detection.",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    logger = logging.getLogger("wirken-siem.webhook")

    skill_dirs = _parse_skill_dirs(args.skill_dirs, None)
    if not skill_dirs:
        logger.info(
            "no skill_dirs configured; Detection 4 disabled this run"
        )
    if not args.secret:
        logger.warning(
            "no HMAC secret configured; events accepted without "
            "verification. Set --secret or WIRKEN_WEBHOOK_SECRET."
        )

    app = make_app(args.secret, skill_dirs, logger)
    app.run(host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
