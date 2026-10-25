"""Detection rules against the Wirken 1.3.x webhook envelope.

Each rule is a pure function: it takes a single webhook event dict
(one entry from the JSON array the Wirken webhook forwarder POSTs)
and returns an Optional[Match] dict on a hit. Empty list of
matches when no detection fires.

Envelope shapes:

- Typed events (``wirken_audit::build_webhook_typed_request``)::

    {
      "timestamp": "...",
      "session_id": "...",
      "seq": N,
      "kind": "assistant_tool_calls" | "tool_result" | ...,
      "trust": "system" | "user" | "tool" | "compaction",
      "event": { <the SessionEvent payload> },
      "service": "...",
      "environment": "...",
      "hostname": "..."
    }

- Legacy events (``wirken_audit::build_webhook_request``)::

    {
      "timestamp": "...",
      "actor_kind": "user" | "agent" | "service",
      "actor_id": "...",
      "action": "...",
      "target": "...",
      "channel": "..." | null,
      "session": "..." | null,
      "detail": { ... },
      "service": "...",
      "environment": "...",
      "hostname": "..."
    }
"""
from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any

Event = dict[str, Any]
Match = dict[str, Any]

# ---------------------------------------------------------------
# Detection 1: shell-driven outbound fetch
# ---------------------------------------------------------------

SHELL_OUTBOUND_VERBS = {
    "curl",
    "wget",
    "msiexec",
    "invoke-webrequest",
    "iwr",
    "bitsadmin",
    "certutil",
}

URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)


def _is_typed_kind(event: Event, kind: str) -> bool:
    return event.get("kind") == kind and isinstance(event.get("event"), dict)


def _first_argv_token(arguments_json: str) -> str | None:
    """Return the first whitespace-separated token of the
    ``command`` argument inside ``arguments``. Wirken's exec tool
    accepts ``command`` either as a string or an array of strings;
    we normalise to a string and split on whitespace, matching the
    wirken-side `extract_exec_command` shape."""
    try:
        args = json.loads(arguments_json)
    except (ValueError, TypeError):
        return None
    cmd = args.get("command") if isinstance(args, dict) else None
    if isinstance(cmd, list):
        cmd = " ".join(str(c) for c in cmd)
    if not isinstance(cmd, str):
        return None
    cmd = cmd.strip()
    if not cmd:
        return None
    return cmd.split()[0]


def _canonical_verb(token: str) -> str:
    """Strip path components and lower-case the verb so
    ``/usr/bin/curl`` and ``CURL`` both match ``curl``."""
    base = os.path.basename(token)
    return base.lower()


def detect_shell_outbound_fetch(event: Event) -> Match | None:
    if not _is_typed_kind(event, "assistant_tool_calls"):
        return None
    payload = event["event"]
    for call in payload.get("calls", []) or []:
        if call.get("name") != "exec":
            continue
        argv = call.get("arguments") or ""
        token = _first_argv_token(argv)
        if not token:
            continue
        if _canonical_verb(token) not in SHELL_OUTBOUND_VERBS:
            continue
        try:
            cmd = json.loads(argv).get("command")
        except (ValueError, TypeError):
            cmd = argv
        if isinstance(cmd, list):
            cmd = " ".join(str(c) for c in cmd)
        url_match = URL_RE.search(cmd or "") if isinstance(cmd, str) else None
        url = url_match.group(0) if url_match else None
        host = None
        if url:
            host_match = re.match(r"https?://([^/:?#]+)", url, re.IGNORECASE)
            host = host_match.group(1) if host_match else None
        return {
            "detection": "shell_outbound_fetch",
            "severity": "medium",
            "session_id": event.get("session_id"),
            "seq": event.get("seq"),
            "agent_id": payload.get("agent_id"),
            "adapter_id": payload.get("adapter_id"),
            "sender_id": payload.get("sender_id"),
            "tool_call_id": call.get("id"),
            "host": host,
            "url": url,
            "raw_argv": cmd,
        }
    return None


# ---------------------------------------------------------------
# Detection 2: child process fork pairing
# ---------------------------------------------------------------
#
# Pairing is stateful: a ToolResult is only meaningful joined to
# its prior AssistantToolCalls in the same session. The stateless
# rule below returns a "partial" match on each side so the SIEM
# (or the consumer harness) can join. Splunk does this via
# `transaction`, Datadog via log-link, Sentinel via KQL join.
#
# The harness emits two partial-match shapes:
#
# - ``shape: "tool_call"``   carries the argv and the call_id.
# - ``shape: "tool_result"`` carries the call_id, success, output
#   size, and the result's ts.
#
# A consumer joins them by ``(session_id, call_id)``. Long-running
# / failed branches are decided post-join.


def detect_exec_fork_pairing(event: Event) -> Match | None:
    if _is_typed_kind(event, "assistant_tool_calls"):
        payload = event["event"]
        for call in payload.get("calls", []) or []:
            if call.get("name") != "exec":
                continue
            return {
                "detection": "exec_fork_pairing",
                "shape": "tool_call",
                "severity": "info",
                "session_id": event.get("session_id"),
                "seq": event.get("seq"),
                "ts": event.get("timestamp"),
                "agent_id": payload.get("agent_id"),
                "adapter_id": payload.get("adapter_id"),
                "sender_id": payload.get("sender_id"),
                "call_id": call.get("id"),
                "argv": call.get("arguments"),
            }
        return None
    if _is_typed_kind(event, "tool_result"):
        payload = event["event"]
        if payload.get("tool_name") != "exec":
            return None
        output = payload.get("output") or ""
        return {
            "detection": "exec_fork_pairing",
            "shape": "tool_result",
            "severity": "info",
            "session_id": event.get("session_id"),
            "seq": event.get("seq"),
            "ts": event.get("timestamp"),
            "agent_id": payload.get("agent_id"),
            "adapter_id": payload.get("adapter_id"),
            "sender_id": payload.get("sender_id"),
            "call_id": payload.get("call_id"),
            "success": payload.get("success"),
            "output_size": len(output),
        }
    return None


# ---------------------------------------------------------------
# Detection 3: binary write via write_file
# ---------------------------------------------------------------

BINARY_EXT_RE = re.compile(
    r"\.(exe|dll|so|dylib|msi|scr|bat|ps1|sh|cmd|com|vbs|jar)$",
    re.IGNORECASE,
)

# Magic-byte prefixes as they would appear at the start of a
# write_file ``content`` argument. Wirken's write_file takes a
# string; an attacker writing a binary either base64-encodes
# (caught at a higher layer) or embeds the raw bytes as a UTF-8
# string, which yields these literal byte prefixes.
MAGIC_BYTE_PREFIXES = {
    "pe_or_ne": b"MZ",
    "elf": bytes.fromhex("7f454c46"),
    "macho_be_32": bytes.fromhex("cafebabe"),
    "macho_le_32": bytes.fromhex("feedface"),
    "macho_le_64": bytes.fromhex("feedfacf"),
    "zip_or_jar": b"PK\x03\x04",
}


def _content_magic(content: str | None) -> str | None:
    if not isinstance(content, str) or not content:
        return None
    head = content[:8].encode("utf-8", errors="replace")
    for name, prefix in MAGIC_BYTE_PREFIXES.items():
        if head.startswith(prefix):
            return name
    return None


def detect_binary_write(event: Event) -> Match | None:
    if not _is_typed_kind(event, "assistant_tool_calls"):
        return None
    payload = event["event"]
    for call in payload.get("calls", []) or []:
        if call.get("name") != "write_file":
            continue
        try:
            args = json.loads(call.get("arguments") or "{}")
        except (ValueError, TypeError):
            continue
        path = args.get("path") if isinstance(args, dict) else None
        content = args.get("content") if isinstance(args, dict) else None
        if not isinstance(path, str):
            continue
        ext_match = BINARY_EXT_RE.search(path)
        magic = _content_magic(content)
        if not ext_match and not magic:
            continue
        return {
            "detection": "binary_write",
            "severity": "high",
            "session_id": event.get("session_id"),
            "seq": event.get("seq"),
            "agent_id": payload.get("agent_id"),
            "adapter_id": payload.get("adapter_id"),
            "sender_id": payload.get("sender_id"),
            "file_path": path,
            "extension": ext_match.group(1).lower() if ext_match else None,
            "suspected_magic": magic,
        }
    return None


# ---------------------------------------------------------------
# Detection 4: skill-dir-resident binary executed
# ---------------------------------------------------------------


def detect_skill_dir_exec(event: Event, skill_dirs: Iterable[str]) -> Match | None:
    """Detection 4. ``skill_dirs`` is the operator-supplied prefix
    list. An empty iterable disables this detection (returns None
    on every event); the consumer logs a one-line note at startup
    so operators see the gap.
    """
    prefixes = [p for p in skill_dirs if p]
    if not prefixes:
        return None
    if not _is_typed_kind(event, "assistant_tool_calls"):
        return None
    payload = event["event"]
    for call in payload.get("calls", []) or []:
        if call.get("name") != "exec":
            continue
        try:
            args = json.loads(call.get("arguments") or "{}")
        except (ValueError, TypeError):
            continue
        cmd = args.get("command") if isinstance(args, dict) else None
        if isinstance(cmd, list):
            cmd = " ".join(str(c) for c in cmd)
        if not isinstance(cmd, str):
            continue
        for prefix in prefixes:
            if prefix in cmd:
                return {
                    "detection": "skill_dir_exec",
                    "severity": "high",
                    "session_id": event.get("session_id"),
                    "seq": event.get("seq"),
                    "agent_id": payload.get("agent_id"),
                    "adapter_id": payload.get("adapter_id"),
                    "sender_id": payload.get("sender_id"),
                    "skill_dir": prefix,
                    "argv": cmd,
                }
    return None


# ---------------------------------------------------------------
# Detection 5: chain tamper correlation
# ---------------------------------------------------------------
#
# The chain-broken signal is a legacy AuditEvent (the writer's
# self-report when its periodic verify pass fails). Baseline
# severity is high; the consumer can promote to critical when the
# alarm-log feed does not show a matching row inside the window
# the operator configures. The alarm-log feed is a separate ingest
# path: the rule here flags every chain-broken event and carries
# enough context (session_id, seq) that downstream correlation can
# decide promotion.


def detect_chain_tamper(event: Event) -> Match | None:
    if event.get("kind") is not None:
        # Typed envelope; chain-broken rides the legacy pipe.
        return None
    if event.get("action") != "audit.chain_broken":
        return None
    detail = event.get("detail") or {}
    return {
        "detection": "chain_tamper",
        "severity": "high",
        # The row names the session in its detail as `session`; the
        # envelope's own `session` is null on this row.
        "session_id": detail.get("session"),
        "seq": detail.get("seq"),
        "expected_hash": detail.get("expected_hash"),
        "actual_hash": detail.get("actual_hash"),
        "verified_count": detail.get("verified_count"),
    }


# ---------------------------------------------------------------
# Detection 6: MCP entry refused at proxy load
# ---------------------------------------------------------------
#
# Fires on any McpEntryRefused row. The MCP client never spawned;
# the proxy refused the entry at load. `reason` is closed-set
# (signature_invalid / unsigned / signer_key_missing /
# signer_key_decode_failed / delegation_required).


def detect_mcp_entry_refused(event: Event) -> Match | None:
    if not _is_typed_kind(event, "mcp_entry_refused"):
        return None
    body = event["event"]
    return {
        "detection": "mcp_entry_refused",
        "severity": "high",
        "session_id": event.get("session_id"),
        "seq": event.get("seq"),
        "server_name": body.get("server_name"),
        "reason": body.get("reason"),
    }


# ---------------------------------------------------------------
# Detection 7: veto hook denied, timed out or not connected
# ---------------------------------------------------------------
#
# Fires on HookDispatched rows whose decision.kind is deny, timeout
# or unavailable (3.0.0: a registered hook that is not connected).
# Timeout and unavailable refuse the tool call.


def detect_hook_refused(event: Event) -> Match | None:
    if not _is_typed_kind(event, "hook_dispatched"):
        return None
    body = event["event"]
    decision = body.get("decision") or {}
    kind = decision.get("kind") if isinstance(decision, dict) else None
    if kind not in ("deny", "timeout", "unavailable"):
        return None
    return {
        "detection": "hook_refused",
        "severity": "medium",
        "session_id": event.get("session_id"),
        "seq": event.get("seq"),
        "agent_id": body.get("agent_id"),
        "adapter_id": body.get("adapter_id"),
        "sender_id": body.get("sender_id"),
        "hook_id": body.get("hook_id"),
        "tool_name": body.get("tool_name"),
        "decision_kind": kind,
        "decision_reason": decision.get("reason"),
    }


# ---------------------------------------------------------------
# Detection 8: tool output redacted by egress hook
# ---------------------------------------------------------------
#
# Fires on any ToolOutputRedacted row. Plaintext is not on the
# chain by design; original_sha256 is the only on-chain reference
# to the bytes the tool produced.


def detect_tool_output_redacted(event: Event) -> Match | None:
    if not _is_typed_kind(event, "tool_output_redacted"):
        return None
    body = event["event"]
    return {
        "detection": "tool_output_redacted",
        "severity": "medium",
        "session_id": event.get("session_id"),
        "seq": event.get("seq"),
        "agent_id": body.get("agent_id"),
        "adapter_id": body.get("adapter_id"),
        "sender_id": body.get("sender_id"),
        "call_id": body.get("call_id"),
        "hook_id": body.get("hook_id"),
        "reason": body.get("reason"),
        "original_sha256": body.get("original_sha256"),
        "original_size": body.get("original_size"),
        "redacted_sha256": body.get("redacted_sha256"),
        "redacted_size": body.get("redacted_size"),
    }


# ---------------------------------------------------------------
# Entry point used by consumer.py
# ---------------------------------------------------------------


def _parse_ts(value: str | None) -> datetime | None:
    """Parse an RFC 3339 timestamp as Wirken writes it, which can carry
    nanoseconds; ``datetime`` keeps microseconds."""
    if not isinstance(value, str):
        return None
    m = re.match(r"^(.*T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$", value)
    if m is None:
        return None
    base, frac, tz = m.groups()
    text = base + ("." + (frac + "000000")[:6] if frac else "") + ("+00:00" if tz == "Z" else tz)
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


# Detection 5 escalation: the alarm-log join.

ALARM_WINDOW = timedelta(seconds=60)


def chain_tamper_severity(
    chain_broken: Event, alarm_records: Iterable[dict[str, Any]]
) -> str:
    """``high`` when the alarm log holds a ``chain_broken`` record for
    the same ``(session_id, seq)`` within 60 seconds of the
    ``audit.chain_broken`` row, otherwise ``critical``: an integrity
    break the out-of-chain alarm log does not document.

    ``alarm_records`` are lines of ``audit-alarms.log``, each a flat
    JSON object with ``session_id`` and ``seq``. The chain-broken row
    names its session as ``detail.session``."""
    match = detect_chain_tamper(chain_broken)
    if match is None:
        raise ValueError("not an audit.chain_broken row")
    at = _parse_ts(chain_broken.get("timestamp"))
    for rec in alarm_records:
        if rec.get("session_id") != match["session_id"] or rec.get("seq") != match["seq"]:
            continue
        when = _parse_ts(rec.get("timestamp"))
        if at is not None and when is not None and abs(when - at) <= ALARM_WINDOW:
            return "high"
    return "critical"


# ---------------------------------------------------------------
# Detection 12: binary changed outside `wirken update`
# ---------------------------------------------------------------


def _version_tuple(v: Any) -> tuple[int, ...] | None:
    if not isinstance(v, str):
        return None
    parts = v.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


class InstallTracker:
    """Correlates ``gateway.start`` legacy rows with the most recent
    ``binary_installed`` typed row from the same host.

    ``binary_installed`` is written while the gateway is stopped and
    reaches the typed pipe only after the next start, so a
    ``gateway.start`` can arrive before the install row it should be
    judged against. A start is held until a typed row from the same
    host, timestamped at or after the start, shows the typed pipe has
    caught up, or until :meth:`flush`."""

    def __init__(self) -> None:
        self._installs: dict[str, list[tuple[datetime, Event]]] = {}
        self._pending: dict[str, list[Event]] = {}

    def observe(self, event: Event) -> list[Match]:
        host = event.get("hostname")
        at = _parse_ts(event.get("timestamp"))
        if host is None or at is None:
            return []
        if event.get("kind") is None:
            detail = event.get("detail") or {}
            if event.get("action") == "gateway.start" and detail.get("version"):
                self._pending.setdefault(host, []).append(event)
            return []
        if _is_typed_kind(event, "binary_installed"):
            self._installs.setdefault(host, []).append((at, event))
        ready = [s for s in self._pending.get(host, []) if _parse_ts(s["timestamp"]) <= at]
        if not ready:
            return []
        self._pending[host] = [s for s in self._pending[host] if s not in ready]
        return [m for s in ready if (m := self._judge(host, s)) is not None]

    def flush(self) -> list[Match]:
        """Judge every held start against what has been seen."""
        out: list[Match] = []
        for host, starts in self._pending.items():
            out.extend(m for s in starts if (m := self._judge(host, s)) is not None)
        self._pending = {}
        return out

    def _judge(self, host: str, start: Event) -> Match | None:
        at = _parse_ts(start["timestamp"])
        detail = start.get("detail") or {}
        before = [(t, e) for t, e in self._installs.get(host, []) if at is not None and t <= at]
        base = {
            "detection": "binary_changed_outside_update",
            "hostname": host,
            "started_at": start.get("timestamp"),
            "started_version": detail.get("version"),
            "started_commit": detail.get("commit"),
            "started_dirty": detail.get("dirty"),
        }
        if not before:
            # install.sh and source builds leave no install row.
            return {**base, "severity": "informational", "finding": "no_install_record"}
        _, last = max(before, key=lambda te: te[0])
        installed = last["event"].get("to_version")
        base["installed_version"] = installed
        base["installed_at"] = last.get("timestamp")
        if detail.get("version") != installed:
            return {**base, "severity": "high", "finding": "version_differs"}
        if detail.get("commit") == "unknown" or detail.get("dirty") != "clean":
            # A release binary is built from a clean tree at a known
            # commit; this one was not.
            return {**base, "severity": "high", "finding": "not_a_release_build"}
        return None


# ---------------------------------------------------------------
# Detection 13: downgrade or rollback
# ---------------------------------------------------------------


def detect_downgrade_or_rollback(event: Event) -> Match | None:
    if not _is_typed_kind(event, "binary_installed"):
        return None
    payload = event["event"]
    rollback = payload.get("rollback") is True
    from_v = _version_tuple(payload.get("from_version"))
    to_v = _version_tuple(payload.get("to_version"))
    downgrade = from_v is not None and to_v is not None and to_v < from_v
    if not (rollback or downgrade):
        return None
    return {
        "detection": "downgrade_or_rollback",
        "severity": "medium",
        "finding": "rollback" if rollback else "downgrade",
        "hostname": event.get("hostname"),
        "session_id": event.get("session_id"),
        "seq": event.get("seq"),
        "from_version": payload.get("from_version"),
        "to_version": payload.get("to_version"),
        "rollback": rollback,
        "binary_sha256": payload.get("binary_sha256"),
        "target": payload.get("target"),
        "verifying_key": payload.get("verifying_key"),
    }


def evaluate(
    event: Event, skill_dirs: Iterable[str], installs: InstallTracker | None = None
) -> list[Match]:
    """Run every detection against a single event. Returns the
    list of matches (zero, one, or more). Detection 12 runs only with
    an ``installs`` tracker, which carries state across events."""
    matches: list[Match] = []
    for fn in (
        detect_shell_outbound_fetch,
        detect_exec_fork_pairing,
        detect_binary_write,
        detect_chain_tamper,
        detect_mcp_entry_refused,
        detect_hook_refused,
        detect_tool_output_redacted,
        detect_downgrade_or_rollback,
    ):
        result = fn(event)
        if result is not None:
            matches.append(result)
    sd = detect_skill_dir_exec(event, skill_dirs)
    if sd is not None:
        matches.append(sd)
    if installs is not None:
        matches.extend(installs.observe(event))
    return matches
