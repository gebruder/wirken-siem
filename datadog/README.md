# datadog/

Monitors and a dashboard for Datadog against the Wirken 1.3.x
audit forwarder.

## Import

Either via the Datadog API:

```
for f in monitors/*.json; do
  curl -X POST "https://api.datadoghq.com/api/v1/monitor" \
    -H "DD-API-KEY: $DD_API_KEY" \
    -H "DD-APPLICATION-KEY: $DD_APP_KEY" \
    -H "Content-Type: application/json" \
    -d @"$f"
done
```

Or via the terraform-datadog provider with
`datadog_monitor` resources, one per file. The JSON shapes match
the provider's `monitor` argument set; copy each file into a
`jsondecode(file(...))` call.

Dashboard import:

```
curl -X POST "https://api.datadoghq.com/api/v1/dashboard" \
  -H "DD-API-KEY: $DD_API_KEY" \
  -H "DD-APPLICATION-KEY: $DD_APP_KEY" \
  -H "Content-Type: application/json" \
  -d @dashboards/wirken_overview.json
```

## Required log parsing pipeline

The monitor queries reference these `@`-prefixed attributes:

- `@argv_first` - first whitespace token of
  `@wirken.event.calls.arguments`'s `command` field, lowercased and
  stripped of any path component. Used by Detection 1.
- `@argv_command` - full `command` argument value. Used by
  Detection 1 and 4 to extract URL / skill-dir context.
- `@argv_skill_dir_match` (boolean) and `@argv_skill_dir` - set by
  comparing `@argv_command` against the `wirken_skill_dirs`
  reference table. Used by Detection 4.
- `@write_file_extension`, `@write_file_path`, `@write_file_magic`
  - from JSON-parsing `@wirken.event.calls.arguments` on `write_file`
  events, regex against `path`, magic-byte prefix-match on
  `content`. Used by Detection 3.
- `@exec_duration_ms` - for `tool_result` rows, the delta between
  the result's timestamp and the matching `assistant_tool_calls`
  row's timestamp (join by `session_id`+`call_id`). Used by
  Detection 2 long-running subset.

Build this with a Datadog log parsing pipeline (Logs >
Configuration > Pipelines). The detection content here does not
ship the pipeline JSON because it depends on per-org parsing
infra; the field names above are the contract.

## Required log-based metric (Detection 9)

Detection 9 (`monitors/agent_cost_anomaly.json`) reads a log-based
metric, not raw logs. Define it under Logs > Configuration >
Generate Metrics:

- Name: `wirken.llm.cost_usd_micros`
- Filter: `@ddsource:wirken @wirken.kind:llm_response`
- Measure: `@wirken.event.total_cost_usd_micros` (aggregate: sum)
- Group-by tag: `agent_id` from `@wirken.event.agent_id`
  (optionally `credential_id` from `@wirken.event.credential_id`)

The monitor divides each agent's last-hour spend by the trailing
7-day moving average of its hourly spend and alerts on a 3x breach.
The measure is `total_cost_usd_micros`, the cost the forwarder
computes once per call; do not sum input and output client-side.
The monitor query is a template: validate the `moving_rollup` and
rollup tuning against your org's data volume before enabling.
Requires the `llm_response` forwarder opt-in
(`wirken/docs/cost-monitoring.md`) and audit schema 1.6.0+ cost
fields.

## Reference table: `wirken_skill_dirs`

Detection 4 reads from a Datadog reference table named
`wirken_skill_dirs`. Schema: one column `prefix` (string). Populate
with operator-supplied prefixes:

```
prefix
/home/wirken/.wirken/skills/
/opt/wirken/skills/
```

Empty table makes the monitor never fire; document this as a
known gap on first deploy.

## Alarm log for Detection 5

Wire the wirken alarm log (default `~/.wirken/audit-alarms.log`)
as a separate Datadog log source with `@ddsource:wirken-alarm-log`.
Then convert the chain-tamper monitor into a composite that
escalates from high (chain-broken seen) to critical (chain-broken
seen AND no matching alarm-log row within 60s).

## Detection summary

| Monitor                       | File                              |
|-------------------------------|-----------------------------------|
| Shell-driven outbound fetch   | `monitors/shell_outbound_fetch.json` |
| Long-running exec             | `monitors/exec_fork_pairing.json` |
| Binary write                  | `monitors/binary_write.json`      |
| Skill-dir exec                | `monitors/skill_dir_exec.json`    |
| Chain tamper                  | `monitors/chain_tamper.json`      |
| MCP entry refused             | `monitors/mcp_entry_refused.json` |
| Veto hook deny or timeout     | `monitors/hook_refused.json`      |
| Tool output redacted          | `monitors/tool_output_redacted.json` |
| Per-agent LLM cost anomaly    | `monitors/agent_cost_anomaly.json` |
| Per-agent budget exceeded     | `monitors/budget_exceeded.json`   |
