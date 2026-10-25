# splunk/

Saved searches, macros, and event types for Splunk against the
Wirken 1.3.x audit forwarder.

## Install

Copy the three conf files to your Splunk app's `local/`
directory:

```
cp savedsearches.conf macros.conf eventtypes.conf \
    $SPLUNK_HOME/etc/apps/wirken/local/
$SPLUNK_HOME/bin/splunk restart
```

Or import via a Splunk app: drop the files in
`<app>/default/` and package as a `.spl`.

## Ingestion

The detections read from two HEC sourcetypes:

- `wirken:audit`: legacy `AuditEvent` rows (gateway lifecycle,
  inbound / outbound messages, `audit.chain_broken`, etc.). Set
  this in your HEC token's input config or as the sourcetype
  parameter on the wirken `siem.json`.
- `wirken:session`: typed `SessionEvent` rows (1.3.x typed
  forwarder). Same HEC, distinct sourcetype so search and
  retention can split.

HEC indexes the object the forwarder sends as `event`, so field
paths start inside it. A typed row is searchable as `kind`,
`level`, `session_id`, `seq` and `trust`, with the `SessionEvent`
payload under `event.` (`event.agent_id`, `event.calls{}.name`,
`event.to_version`). A legacy row is searchable as `action`,
`actor_id`, `actor_kind`, `target`, `channel` and `session`, with its
detail under `detail.` (`detail.seq`, `detail.version`); there is no
`detail` field of its own, so `spath input=detail` finds nothing. The
macros in `macros.conf` read these paths; the saved searches were
checked against rows posted to Splunk 10.6.0's HEC in the forwarder's
own shape.

## Lookup: `wirken_skill_dirs`

Detection 4 reads from a lookup table named `wirken_skill_dirs`.
Create it as a single-column CSV named `prefix`:

```
prefix
/home/wirken/.wirken/skills/
/opt/wirken/skills/
```

Save as `$SPLUNK_HOME/etc/apps/wirken/lookups/wirken_skill_dirs.csv`,
then register in `transforms.conf`:

```
[wirken_skill_dirs]
filename = wirken_skill_dirs.csv
```

An empty lookup makes `wirken_d4_skill_dir_exec` return zero rows;
the search still parses cleanly but never matches.

## Alarm log (Detection 5)

The audit-alarms log is a separate file (default
`~/.wirken/audit-alarms.log`, one JSON object per line, optionally
HMAC-SHA256 tagged). Wire it
into Splunk as a file input with sourcetype `wirken:alarm-log`:

```
[monitor:///path/to/audit-alarms.log]
sourcetype = wirken:alarm-log
```

The Detection 5 saved search joins on `(session_id, seq)` with a
+/-60s window. The alarm log's record carries `session_id` and `seq`
at the top level; the `audit.chain_broken` row carries them in its
detail as `session` and `seq`.

## Detection summary

| Saved search                                  | Source           | Notes |
|-----------------------------------------------|------------------|-------|
| `wirken_d1_shell_outbound_fetch`              | `wirken:session` | Detection 1 |
| `wirken_d2_exec_fork_pairing`                 | both             | Detection 2 (join) |
| `wirken_d2_exec_fork_pairing_long_running`    | derived          | duration > 30s |
| `wirken_d2_exec_fork_pairing_failed`          | derived          | success = false |
| `wirken_d3_binary_write`                      | `wirken:session` | Detection 3 |
| `wirken_d4_skill_dir_exec`                    | `wirken:session` | Detection 4, needs lookup |
| `wirken_d5_chain_tamper`                      | `wirken:audit`   | Detection 5 |
| `wirken_d6_mcp_entry_refused`                 | `wirken:session` | Detection 6 |
| `wirken_d7_hook_refused`                      | `wirken:session` | Detection 7, fires on decision.kind in {deny, timeout, unavailable} |
| `wirken_d8_tool_output_redacted`              | `wirken:session` | Detection 8 |
| `wirken_d9_agent_cost_anomaly`                | `wirken:session` | Detection 9, needs `llm_response` opt-in |
| `wirken_d10_budget_exceeded`                  | `wirken:session` | Detection 10, forwarded by default |
| `wirken_d11_exec_location_disagreement`       | `wirken:session` | Detection 11, forwarded by default, recorded by `sessions verify` |
| `wirken_d12_binary_changed_outside_update`    | both             | Detection 12, informational with no install row |
| `wirken_d13_downgrade_or_rollback`            | `wirken:session` | Detection 13, forwarded by default |
