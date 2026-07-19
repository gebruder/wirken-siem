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
`~/.wirken/audit-alarms.log`, signed Ed25519 entries). Wire it
into Splunk as a file input with sourcetype `wirken:alarm-log`:

```
[monitor:///path/to/audit-alarms.log]
sourcetype = wirken:alarm-log
```

The Detection 5 saved search joins on `(session_id, seq)` with a
+/-60s window. The alarm log's row carries the same two fields in
its detail JSON.

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
| `wirken_d7_hook_refused`                      | `wirken:session` | Detection 7, fires on decision.kind in {deny, timeout} |
| `wirken_d8_tool_output_redacted`              | `wirken:session` | Detection 8 |
| `wirken_d9_agent_cost_anomaly`                | `wirken:session` | Detection 9, needs `llm_response` opt-in |
| `wirken_d10_budget_exceeded`                  | `wirken:session` | Detection 10, forwarded by default |
