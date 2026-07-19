# wirken-siem

Detection content for the Wirken audit schema. The repo ships
saved searches, monitors, analytics rules, and a reference
webhook consumer that SOC teams can wire up without reading the
upstream code. Versions track the audit schema, not the wirken
binary.

## Compatibility

| wirken-siem | Wirken audit schema |
|-------------|---------------------|
| 0.1         | 1.3.x – 1.8.x       |
| 0.2         | 1.3.x – 1.12.x      |

wirken-siem 0.1 shipped detections 1-8 against audit schema 1.3.x
through 1.8.x. 0.2 adds detections 9 (per-agent cost anomaly) and 10
(per-agent budget exceeded) and extends support through 1.12.x.

Every audit-schema change from 1.4.0 through 1.12.0 has been
forward-compatible (`#[serde(default)]` on new fields, new variants
sitting alongside existing ones): 1.8.0 added a `wasm_skill_call`
value to the `Action` label vocabulary (it rides the existing
`PermissionDenied` event), 1.10.0 added the `http_request` typed
variant, and 1.12.0 added the `budget_exceeded` typed variant plus
`sender_id` on the `LlmRequest` and `LlmResponse` variants. Existing
detection content in this repo continues to fire unmodified across the
range.

`SessionEvent` variants added since 1.4.x. Detections 6, 7, and 8
consume `McpEntryRefused`, `HookDispatched`, and
`ToolOutputRedacted`. The remaining variants are reserved.

- `HookRegistered`, `HookDispatched` (out-of-process hook protocol)
- `EgressHookDispatched`, `ToolOutputRedacted` (egress dispatcher
  on post-execution tool output)
- `McpEntryVerified`, `McpEntryRefused` (mcp.json signature anchor)
- `PhaseEntered`, `PhaseExited`, `SkillPermissionDenied`
  (per-skill phase deny overlay)
- `SessionScopedApprovalsCleared` (session-scoped approval lifecycle)
- `ChainHead` (gateway-keyed signature over chain ranges)
- `Compaction` (context-engine compaction extracts)

Fields added to existing variants since 1.4.x:

- `PermissionDenied` / `PermissionApproved`: `denial_source`,
  `denied_via`, `denial_reason`, `approved_via`, `adapter_id`,
  `sender_id`, `scope` (`ApprovalScopeKind`), `session_id`.
- `LlmResponse`: `input_cost_usd_micros`, `output_cost_usd_micros`,
  `total_cost_usd_micros`, `cache_creation_input_tokens`,
  `cache_read_input_tokens`.
- `HttpFetch`: `expansion_id`, `skill_name`.
- `LlmRequest` / `LlmResponse`: `sender_id` (1.12.0), the platform-side
  human the call is on behalf of; `None` for operator-originated
  sessions. Carries the originating principal across the LLM call
  boundary for correlation with the sibling `UserMessage` / `ToolResult`
  rows.

### Detection 9 minimum

Detection 9 (per-agent cost anomaly) requires the `LlmResponse` cost
fields added in audit schema 1.6.0, plus the forwarder opt-in
documented in `wirken/docs/cost-monitoring.md`. `LlmResponse` is
excluded from typed forwarding by default; the detection sees nothing
until an operator adds `llm_response` to `typed_include_variants`. A
row whose (provider, model) pair is absent from the pricing table
carries no cost and is invisible to the detection. The logic is
baseline-relative, so it does not fire for an agent that is expensive
from its first hour: an agent compromised or misconfigured on day one
reads as its own baseline. See `wirken/docs/cost-monitoring.md`
(Enforcement) and detection 10 for the absolute-ceiling complement,
now shipped.

### Detection 10 minimum

Detection 10 (per-agent budget exceeded) requires the `budget_exceeded`
event added in audit schema 1.12.0. Unlike detection 9 it needs no
forwarder opt-in: `BudgetExceeded` is forwarded by default. It fires on
any breach the wirken runtime records; `action` distinguishes a block
(the call was refused) from an alert (the call proceeded). The wirken
runtime does the ceiling comparison, so this detection only surfaces
the event.

## Field index

The detections read from these typed `SessionEvent` variants and
the legacy `AuditEvent` shape. After the 1.3.1 identity additions,
every variant below carries an `agent_id` and a 1.3.x-typed
`adapter_id` / `sender_id` pair where listed.

| Variant                | Identity fields                                                         | Used by detection |
|------------------------|-------------------------------------------------------------------------|-------------------|
| `AssistantToolCalls`   | `agent_id`, `adapter_id?`, `sender_id?`, `calls[].{id,name,arguments}`  | 1, 2, 3, 4        |
| `ToolResult`           | `agent_id`, `adapter_id?`, `sender_id?`, `call_id`, `tool_name`, `success`, `output` | 2 |
| `HttpFetch`            | `agent_id?`, `skill_name?`, `host`, `url`, `outcome`, `http_status_code?`, `bytes` | (none here; reserved) |
| `AuditLegacy`          | `actor_kind`, `actor_id`, `action`, `target`, `detail`                  | 5                 |
| `McpEntryRefused`      | `server_name`, `reason` (`signature_invalid` / `unsigned` / `signer_key_missing` / `signer_key_decode_failed` / `delegation_required`) | 6 |
| `HookDispatched`       | `hook_id`, `tool_name`, `agent_id`, `adapter_id?`, `sender_id?`, `decision.kind` (`allow` / `deny` / `timeout`), `decision.reason?` | 7 |
| `ToolOutputRedacted`   | `call_id`, `hook_id`, `agent_id`, `adapter_id?`, `sender_id?`, `reason`, `original_sha256`, `original_size`, `redacted_sha256`, `redacted_size` | 8 |
| `LlmResponse`          | `agent_id`, `credential_id?`, `sender_id?`, `total_cost_usd_micros?`, `input_cost_usd_micros?`, `output_cost_usd_micros?` | 9 |
| `BudgetExceeded`       | `agent_id`, `credential_id?`, `action` (`alerted` / `blocked`), `window`, `window_spend_usd_micros`, `ceiling_usd_micros` | 10 |

Row metadata on every typed event: `session_id`, `seq`, `ts`,
`trust`, `kind`. The forwarder wraps each row in a per-target
envelope; see the platform READMEs for the exact field names per
target.

## Detection summary

| #  | Title                              | Source variants                | Severity baseline |
|----|------------------------------------|--------------------------------|-------------------|
| 1  | Shell-driven outbound fetch        | `AssistantToolCalls`           | medium            |
| 2  | Child process fork pairing         | `AssistantToolCalls` + `ToolResult` | low (info) |
| 3  | Binary write via `write_file`      | `AssistantToolCalls`           | high              |
| 4  | Skill-dir-resident binary executed | `AssistantToolCalls`           | high              |
| 5  | Chain tamper correlation           | `AuditLegacy` (`audit.chain_broken`) | high; critical when alarm log missing |
| 6  | MCP entry refused at proxy load    | `McpEntryRefused`              | high              |
| 7  | Veto hook denied or timed out      | `HookDispatched`               | medium            |
| 8  | Tool output redacted by egress hook | `ToolOutputRedacted`          | medium            |
| 9  | Per-agent LLM cost anomaly         | `LlmResponse`                  | medium            |
| 10 | Per-agent budget exceeded          | `BudgetExceeded`               | medium            |

## Layout

- `splunk/` saved searches, macros, eventtypes; ingestion via
  HEC `sourcetype=wirken:audit` (legacy) and `sourcetype=wirken:session`
  (typed).
- `datadog/` monitor JSON and dashboard JSON; ingestion via
  Datadog Log Intake under `@ddsource:wirken`.
- `sentinel/` analytics rule YAML and workbook JSON; ingestion via
  DCR streams `Custom-WirkenAudit_CL` and `Custom-WirkenSession_CL`.
- `webhook/` reference Python consumer that verifies the
  `X-Wirken-Signature` HMAC over the raw POST body, then runs
  detections 1-8 in-process; detection 9 is not ported to the
  webhook consumer.

## Operating notes

### Tier 3 deny-but-detected

Detections 1 (shell outbound fetch) and 4 (skill-dir-resident
exec) fire on `AssistantToolCalls` before Wirken's runtime
permission tier decision. The detection sees the model's attempt;
whether the action then runs depends on the channel:

- **Channels without a human approval loop** (`webchat`, `cron`,
  unattended subagents): Tier 3 verbs auto-deny. The paired
  `ToolResult` carries `success: false` and the model's request
  does not execute. The detection still fires because the source
  variant for both rules is `AssistantToolCalls`, which records
  the model's intent at the moment of the call.
- **Channels with a human approval loop** (Telegram, Signal,
  Slack, Discord, and other adapter-bound channels): the operator
  is prompted to approve or deny the tool call. The detection
  fires either way; whether the paired `ToolResult` indicates
  success depends on the operator's decision.

This is the right shape: the detection is a record of the LLM's
behavior. The tier gate is wirken's enforcement. Treating them as
the same signal would conflate "the model tried to do X" with "X
happened," and the SOC needs both.

## What this repo is not

- Not a Splunk app, a Datadog terraform module, or a Sentinel
  solution package. Bare content first; packaging if and when an
  operator adopts the content at scale.
- Not a documentation site. The field index above is the only
  prose; everything else is rules.
- Not the audit-schema reference. That lives in
  `wirken/docs/audit-schema.md` (forthcoming).
