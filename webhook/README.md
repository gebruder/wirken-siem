# webhook/

Reference Python webhook consumer for Wirken 1.3.x audit events.

## Install

```
pip install -r requirements.txt
```

Python 3.11+.

## Run

```
consumer.py --port 9000 --secret $WIRKEN_WEBHOOK_SECRET --skill-dirs ~/.wirken/skills/
```

Or via environment::

```
WIRKEN_WEBHOOK_SECRET=... WIRKEN_SKILL_DIRS=~/.wirken/skills/ python consumer.py
```

The consumer listens on the configured port, verifies the
`X-Wirken-Signature: sha256=<hex>` header against the secret over
the raw POST body, decodes the JSON array, and emits NDJSON on
stdout for every detection match.

## Signature semantics

The Wirken webhook forwarder factors the body and the HMAC from a
single `serde_json::to_vec` call. Receivers must recompute the
HMAC over the raw POST bytes, never over a re-parsed envelope.
The test
`test_verify_signature_is_over_exact_body_bytes_not_reparsed_envelope`
pins this invariant.

## Rules

`rules.py` exports nine pure detection functions (detections 1-8 and
13) plus `evaluate(event, skill_dirs, installs=None) -> list[match]`.
Each rule consumes one webhook event dict and returns
`Optional[Match]`. Detections 9 to 11 are not ported to the webhook
consumer.

Detection 12 needs state across events, so it lives in
`InstallTracker`, which `evaluate` runs when given one; the consumer
keeps one for its lifetime. It holds each `gateway.start` until a
typed row from the same host, timestamped at or after the start,
shows the typed feed has caught up, because `binary_installed` is
written while the gateway is stopped and arrives after the restart.
`InstallTracker.flush()` judges whatever is still held.

`chain_tamper_severity(chain_broken, alarm_records)` is Detection 5's
escalation: `high` when the alarm log holds a record for the same
`(session_id, seq)` within 60 seconds, otherwise `critical`. The
consumer does not read the alarm log; pass it the parsed lines of
`audit-alarms.log`.

Detection 4 reads the operator-supplied `--skill-dirs` list; an
empty list disables it. The consumer logs a one-line note at
startup when Detection 4 is disabled so operators see the gap
explicitly.

## Tests

```
pytest -q
```

The fixtures under `tests/fixtures/` match the typed webhook
envelope (lowercase `kind`, `session_id`, `seq`, ...), the legacy
webhook envelope (consumed by Detections 5 and 12), and one line of
`audit-alarms.log` (Detection 5's alarm join).
