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

`rules.py` exports five pure detection functions plus
`evaluate(event, skill_dirs) -> list[match]`. Each rule consumes
one webhook event dict and returns `Optional[Match]`.

Detection 4 reads the operator-supplied `--skill-dirs` list; an
empty list disables it. The consumer logs a one-line note at
startup when Detection 4 is disabled so operators see the gap
explicitly.

## Tests

```
pytest -q
```

The fixtures under `tests/fixtures/` match the 1.3.x typed
webhook envelope (lowercase `kind`, `session_id`, `seq`, ...) and
the legacy webhook envelope for Detection 6.
