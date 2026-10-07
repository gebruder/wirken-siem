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
| 0.2         | 1.3.x – 1.28.x      |

wirken-siem 0.1 shipped detections 1-8 against audit schema 1.3.x
through 1.8.x. 0.2 adds detections 9 (per-agent cost anomaly) and 10
(per-agent budget exceeded) and extends support through 1.28.x.

Every audit-schema change from 1.4.0 through 1.28.0 has been
forward-compatible (`#[serde(default)]` on new fields, new variants
sitting alongside existing ones): 1.8.0 added a `wasm_skill_call`
value to the `Action` label vocabulary (it rides the existing
`PermissionDenied` event), 1.10.0 added the `http_request` typed
variant, 1.12.0 added the `budget_exceeded` typed variant plus
`sender_id` on the `LlmRequest` and `LlmResponse` variants, 1.15.0
added the `memory_entry_written` and `cross_channel_memory_read` typed
variants plus a `cross_channel_memory_read` value in the `Action` label
vocabulary, and 1.16.0 added the `sandbox_egress_verdict` and
`sandbox_egress_unsupported` typed variants. 1.17.0 and 1.18.0 changed
the audit schema not at all. 1.19.0 added the `import_started`,
`import_completed`, `imported_chat_read` and `imported_chat_searched`
typed variants, plus `imported_chat_read` and `imported_chat_search`
values in the `Action` label vocabulary. 1.20.0 added the
`permission_renewed`, `permission_grant_expired`,
`permission_grant_pruned` and `subagent_session_bound` typed variants,
plus `tool` on `BudgetExceeded`, `tools_hash_version` on `LlmRequest`
and `max_permission_tier` on `SubagentSpawned`. 1.21.0 changed the
audit schema not at all. 1.22.0 added the `delivery_confirmed` and
`delivery_failed` typed variants. 1.23.0 changed nothing. 1.24.0 added
the `permission_approval_refused` and `permission_revoked` typed
variants, plus `text` on `AssistantToolCalls`, `redaction`,
`superseded_chain_hash` and `superseded_signature` on `ChainHead`,
`tier` and `expires_at` on `PermissionApproved`, and `sandbox` on
`ToolResult`. 1.24.1 through 1.27.0 changed the audit schema not at
all. 1.28.0 added `exec_location` on `PermissionApproved` and
`PermissionDenied`. The `Action` label vocabulary is unchanged since
1.19.0. Existing detection content fires unmodified across the range.

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
- `SandboxEgressVerdict` (1.16.0, one row per sandbox egress request,
  allow or deny, carrying the confidentiality basis it was decided on)
- `SandboxEgressUnsupported` (1.16.0, egress configured on a platform
  with no decision-broker transport, so the exec was refused)
- `MemoryEntryWritten`, `CrossChannelMemoryRead` (1.15.0,
  cross-channel memory provenance and trust-zone crossings)
- `PermissionRenewed`, `PermissionGrantExpired`, `PermissionGrantPruned`
  (1.20.0, grant lifecycle: a grant extended, lapsed, or removed as
  unreadable)
- `SubagentSessionBound` (1.20.0, a child session's own record of what
  it was granted)
- `DeliveryConfirmed`, `DeliveryFailed` (1.22.0, the adapter's report of
  what the platform did with an outbound message)
- `PermissionApprovalRefused` (1.24.0, an approval attempt by a caller
  with no authority to make it)
- `PermissionRevoked` (1.24.0, an operator removing a stored grant)

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
- `BudgetExceeded`: `tool` (1.20.0).
- `LlmRequest`: `tools_hash_version` (1.20.0).
- `SubagentSpawned`: `max_permission_tier` (1.20.0).
- `AssistantToolCalls`: `text` (1.24.0), what the model said in the
  same message as the calls.
- `ChainHead`: `redaction`, `superseded_chain_hash`,
  `superseded_signature` (1.24.0).
- `PermissionApproved`: `tier`, `expires_at` (1.24.0).
- `ToolResult`: `sandbox` (1.24.0), `{mode, runtime, container_id?}`
  for an `exec`: where the command ran.
- `PermissionApproved` / `PermissionDenied`: `exec_location` (1.28.0),
  `{mode, text}` for an `exec` an operator was asked about: the line
  the approval prompt showed.

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
| `SandboxEgressVerdict` | `agent_id`, `channel?`, `adapter_id?`, `sender_id?`, `host`, `port`, `allowed`, `reason?` (`mode_none` / `not_allowed` / `ip_literal` / `port_not_allowed` / `method_not_allowed` / `malformed` / `resolution_failed` / `sensitivity_refused`), `mode` (`none` / `allowlist` / `open`), `sensitivity_basis[]`, `escalated` | (none here; reserved) |
| `SandboxEgressUnsupported` | `agent_id`, `channel?`, `adapter_id?`, `sender_id?`, `mode` | (none here; reserved) |
| `MemoryEntryWritten`   | `agent_id`, `channel`, `adapter_id`, `sender_id`, `entry_id`, `origin_session_id` | (none here; reserved) |
| `CrossChannelMemoryRead` | `agent_id`, `adapter_id?`, `sender_id?`, `from_channel`, `to_channel`, `entry_count` | (none here; reserved) |
| `ImportStarted`        | `actor`, `source_id`, `provider`, `source_account`, `archive_sha256` | (none here; reserved) |
| `ImportCompleted`      | `actor`, `source_id`, `provider`, `source_account`, `archive_sha256`, `added`, `updated`, `unchanged`, `unorderable`, `skipped` | (none here; reserved) |
| `ImportedChatRead`     | `agent_id`, `adapter_id?`, `sender_id?`, `source_id`, `source_account?`, `conversation_uuid`, `message_count` | (none here; reserved) |
| `ImportedChatSearched` | `agent_id`, `adapter_id?`, `sender_id?`, `source_id?`, `outcome` (`hits` / `empty` / `refused`), `match_count`, `query_digest?` | (none here; reserved) |
| `PermissionGrantExpired` | `agent_id`, `adapter_id?`, `sender_id?`, `action_key`, `tool?`, `tier?`, `expired_at`, `detected_by?` (`tool_call` / `store_open`) | (none here; reserved) |
| `PermissionGrantPruned` | `agent_id`, `action_key`, `expires_at` | (none here; reserved) |
| `PermissionRenewed`    | `agent_id`, `adapter_id?`, `sender_id?`, `action_key`, `approved_by`, `approved_via?`, `previous_expires_at`, `expires_at` | (none here; reserved) |
| `PermissionRevoked`    | `agent_id`, `action_key`, `revoked_by`, `tier?`, `expires_at?` | (none here; reserved) |
| `PermissionApprovalRefused` | `request_id`, `action_key?`, `caller`, `reason` (`unauthorized_actor` / `wrong_channel` / `wrong_conversation`), `adapter_id?` | (none here; reserved) |
| `SubagentSessionBound` | `agent_id`, `parent_session_id`, `depth`, `max_permission_tier`, `tools_granted[]`, `offered_tools[]` | (none here; reserved) |
| `DeliveryConfirmed`    | `target`, `message_id`, `adapter_id?` | (none here; reserved) |
| `DeliveryFailed`       | `target`, `error`, `adapter_id?` | (none here; reserved) |

`SandboxEgressVerdict` is emitted for every request the proxy decides, allow included, not only refusals. An allow row carries the same `sensitivity_basis`, which is what lets a detection assert that a connection was permitted after a given set of reads rather than seeing only what was turned away. Expect one row per proxied CONNECT.

`sandbox_egress_denied` appears in no released binary: it existed in the 1.14.0 and 1.15.0 trees, neither of which produced release artifacts, and was replaced before the next release. No consumer needs to handle it.

An import is an operator action, not an agent turn, so `ImportStarted` and `ImportCompleted` attribute differently from every other typed variant: the extractor puts `actor` in the sender position and leaves the agent and adapter columns empty. A query that groups on `agent_id` will not see them. `ImportedChatRead` and `ImportedChatSearched` are agent turns and attribute normally.

`ImportedChatSearched` is emitted for every search attempt, including ones that returned nothing and ones that never ran. `outcome` is what separates them, and the separation is load-bearing: `empty` means the term was not found in what was searched, while `refused` means the search did not happen and says nothing about the corpus. Counting rows without reading `outcome` will treat a refusal as evidence of absence.

`query_digest` is a keyed HMAC of the query, not the query. Equal digests mean equal queries, which is enough to correlate repetition, and the query text is not recoverable from a row. The field is absent when the key was unavailable at gateway start, which the gateway records separately as an `imported-search.digest-unavailable` legacy audit action.

The `Action` label vocabulary gains `imported_chat_read` and `imported_chat_search`, which ride the existing `PermissionDenied` and `PermissionApproved` events. Their `action_key` values are `imported_chat:<source>`, `imported_search:<source>`, and `imported_search_corpus` for a search not scoped to one source.

Of the variants added since 1.20.0, the typed forwarder sends
`PermissionGrantExpired`, `PermissionGrantPruned` and
`SubagentSessionBound` by default. `PermissionRenewed`,
`PermissionRevoked`, `PermissionApprovalRefused`, `DeliveryConfirmed`
and `DeliveryFailed` are outside the default set and reach a SIEM only
when listed in `typed_include_variants`.

`exec_location` rides `PermissionDenied`, which is forwarded by default,
and `PermissionApproved`, which is not. Its `mode` is the sandbox mode
the prompt described; the `mode` and `runtime` on the paired
`ToolResult.sandbox` are where the command ran. A row pair where the
prompt said a container and the result says `runtime: host` is the
mismatch `wirken sessions verify` reports as an `exec_location`
divergence.

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
