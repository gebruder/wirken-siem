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
| 0.3         | 1.3.x – 2.3.x       |
| 0.4         | 1.3.x – 2.3.x       |
| 0.4.1       | 1.3.x – 2.3.x       |
| 0.5         | 1.3.x – 3.0.x       |
| 0.6         | 1.3.x – 3.1.x       |

wirken-siem 0.1 shipped detections 1-8 against audit schema 1.3.x
through 1.8.x. 0.2 adds detections 9 (per-agent cost anomaly) and 10
(per-agent budget exceeded) and extends support through 1.28.x. 0.3
adds detection 11 (exec approval prompt disagreed with where it ran),
which needs audit schema 1.28.0, and extends support through 2.3.x;
detections 1-10 fire unmodified across the range. 0.4 corrects
detection 5, which read the chain-broken row's session from
`detail.session_id`; the row has always written it as
`detail.session`, so the join to the alarm log never matched and every
break read as critical. 0.4 adds detections 12 (binary changed outside
`wirken update`) and 13 (downgrade or rollback), which need audit
schema 2.3.0. 0.4.1 corrects the Splunk searches to read fields where
HEC indexes them: a typed row's `kind` at the top level and its
payload under `event.`, a legacy row's detail under `detail.`. Every
Splunk detection, 1 to 13, is checked against rows posted to HEC in
the forwarder's own shape. 0.5 extends support through 3.0.x and has
detection 7 fire on `unavailable` too: from 3.0.0 a registered veto
hook that is not connected refuses the call with that decision.
Detections 1-6 and 8-13 fire unmodified. 0.6 extends support through
3.1.x; detections 1-13 fire unmodified.

Audit-schema changes in the 2.x and 3.x series, one row per minor that
changed something. 2.1.0, 2.4.x and 2.5.x changed the audit schema not
at all.

| Wirken | What changed |
|--------|--------------|
| 2.0.x  | Twelve typed variants: `llm_request_failed`; the adapter lifecycle events `adapter_connect`, `adapter_disconnect`, `adapter_restart` and `adapter_restart_abandoned`; the MCP server lifecycle events `mcp_server_sandboxed`, `mcp_server_unsandboxed`, `mcp_server_exited`, `mcp_server_restart` and `mcp_server_restart_abandoned`; `mcp_credential_refetched`; and `leak_refused`. `mcp_server` on `SandboxEgressVerdict`. A level on every typed row. The `connection.panic` legacy action. Sequence numbers are never reused after a rewind. No 2.x binary writes the `wasm_skill_call` `Action` label. |
| 2.2.x  | `request_bytes` and `purpose` on `LlmRequest`. Compaction summary and tool-call probe model calls are recorded as `llm_request` / `llm_response` pairs. |
| 2.3.x  | The `binary_installed` typed variant. `build` on the `SessionStart` chain head. A `{version, commit, dirty}` detail on the `gateway.start` legacy row. |
| main after 3.1.0 (unreleased) | The `session_liveness_unavailable` typed variant. `operator_command_refused` written on `gateway-operator` for the authority-changing subcommands of sixteen `wirken` commands. The `agent_stopped` and `agent_resumed` typed variants. `agent stopped` as a `denial_reason` on `PermissionDenied`. The `message.refused` and `cron.skipped` legacy actions. |
| 3.1.x  | Four typed variants: `read_sensitivity_observed`, `read_sensitivity_exempted`, `operator_command` and `authority_reloaded`. The cause `credential_changed` on `AdapterRestart` and `McpServerRestart`. Every actor field a `wirken` command writes, `added_by`, `removed_by`, `granted_by`, `revoked_by`, `set_by`, `run_by`, the `approved_by` and `denied_by` of a decision made with `wirken permissions pending`, and an import's `actor`, names the OS account the command ran as, `uid:<n> (<name>)` or `uid:<n>`, `sid:<SID>` on Windows, where it held the login name from `$USER`. |
| 3.0.x  | Fourteen typed variants: `inbound_sender_refused`, `inbound_sender_added`, `inbound_sender_removed`, `approver_added`, `approver_removed`, `approval_chat_set`, `operator_command_refused`, `update_refused`, `mcp_credential_refresh_discarded`, `credential_destination_refused`, `credential_destination_granted`, `credential_destination_revoked`, `credential_handed_out` and `vault_migrated`. `approved_by` on `PermissionApproved` now holds the verified identity of the approver; the display name moves to `approver_display`. `denied_by` and `denier_display` on `PermissionDenied`. `channel` on `PermissionApproved`, `PermissionRenewed`, `PermissionRevoked`, `PermissionGrantExpired` and `PermissionGrantPruned`. `unavailable` in `HookDispatched` and `EgressHookDispatched` decisions. The Sentinel `DecidedBy` column. |

Every audit-schema change from 1.4.0 through 3.1.0 has been
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
all. 1.28.0 added the `exec_location_disagreement` typed variant, plus
`exec_location` on `PermissionApproved` and `PermissionDenied`. 2.0.0
added the twelve typed variants in the table above, plus `mcp_server`
on `SandboxEgressVerdict`, a `level` on every typed row and the
`connection.panic` legacy action; it removed the Wasm skill loader, so
no 2.x binary writes `wasm_skill_call`, which rows written before it
still carry. 2.1.0 changed the audit schema not at all. 2.2.0 added
`request_bytes` and `purpose` on `LlmRequest`, both optional and
omitted for a normal turn. 2.3.0 added the `binary_installed` typed
variant, `build` on `ChainHead`, optional and only on the head after
`session_start`, and a detail on the `gateway.start` legacy row, which
was null before. 3.0.0 added the fourteen variants and the optional
fields in the table above. One change is in meaning rather than shape:
from 3.0.0 `approved_by` is a verified identity (a channel approver's
platform user id, `operator:<key id>` or `webchat:<label>`), where it
held a display name before; read `approver_display` for the name. A binary from 1.7.0 on that is older than a row reads
a kind it does not know as schema drift, reported and skipped, not as
a broken chain, and ignores fields it does not know. The `Action` label vocabulary has
gained nothing since 1.19.0. Existing detection content fires
unmodified across the range.

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
- `ExecLocationDisagreement` (1.28.0, `wirken sessions verify` finding
  an exec that ran somewhere other than its approval prompt said)
- `LlmRequestFailed` (2.0.0, a model call that failed, in place of its
  `LlmResponse`)
- `AdapterConnect`, `AdapterDisconnect`, `AdapterRestart`,
  `AdapterRestartAbandoned` (2.0.0, an adapter's connection and
  restarts)
- `McpServerSandboxed`, `McpServerUnsandboxed`, `McpServerExited`,
  `McpServerRestart`, `McpServerRestartAbandoned` (2.0.0, what each
  stdio MCP server started with, and a contained server's exits and
  restarts)
- `McpCredentialRefetched` (2.0.0, the gateway giving the MCP proxy a
  credential's current vault value after a server refused it)
- `LeakRefused` (2.0.0, content carrying a stored secret, refused)
- `BinaryInstalled` (2.3.0, `wirken update` or `--rollback` swapping
  the installed binary)
- `InboundSenderRefused`, `InboundSenderAdded`, `InboundSenderRemoved`
  (3.0.0, the inbound sender allowlist: a message dropped, and the
  operator's changes to who may drive an agent)
- `ApproverAdded`, `ApproverRemoved`, `ApprovalChatSet` (3.0.0, the
  operator's changes to who may approve and where prompts post)
- `OperatorCommandRefused` (3.0.0, `wirken senders` or `wirken
  approvers` refused inside a Wirken `exec`; on Wirken main after
  3.1.0, also every `wirken` subcommand that changes authority or
  configuration)
- `AgentStopped`, `AgentResumed` (Wirken main after 3.1.0, `wirken agents
  stop` and `wirken agents resume`)
- `SessionLivenessUnavailable` (Wirken main after 3.1.0, `wirken run`
  could not open the session store it asks about liveness, so no
  session-scoped grant is served until it restarts)
- `UpdateRefused` (3.0.0, `wirken update` refused inside a Wirken
  `exec`, or a rollback a migrated vault would break)
- `McpCredentialRefreshDiscarded` (3.0.0, a refreshed OAuth credential
  not written because the entry changed during the refresh)
- `CredentialDestinationRefused`, `CredentialDestinationGranted`,
  `CredentialDestinationRevoked`, `CredentialHandedOut`, `VaultMigrated`
  (3.0.0, where vault credentials may go and where they went)

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
- `SandboxEgressVerdict`: `mcp_server` (2.0.0), the contained MCP
  server the request came from; absent for an agent's own `exec`.
- `LlmRequest`: `request_bytes` (2.2.0), the size of the messages and
  tool definitions the call sent, what `messages_hash` and `tools_hash`
  cover; `purpose` (2.2.0), absent for a normal turn, otherwise
  `compaction_summary` or `tool_call_probe`.
- `ChainHead`: `build` (2.3.0), `{version, commit, dirty}`, only on the
  head written after `session_start`.
- `PermissionApproved`: `approver_display` (3.0.0); `approved_by` holds
  the verified identity from 3.0.0.
- `PermissionDenied`: `denied_by`, `denier_display` (3.0.0), absent when
  no one decided (a timeout or a gate refusal).
- `PermissionApproved`, `PermissionRenewed`, `PermissionRevoked`,
  `PermissionGrantExpired`, `PermissionGrantPruned`: `channel` (3.0.0),
  the channel a persisted grant applies on; absent for a one-shot
  approval and for a grant pruned because it was stored without one.

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

From audit schema 2.2.0, compaction summary calls produce priced
`llm_response` rows; before, they were made but not recorded. An agent
whose conversations compact shows a one-time step up in recorded cost
after the upgrade, which can trip the baseline-relative anomaly until
the baseline absorbs it.

### Detection 10 minimum

Detection 10 (per-agent budget exceeded) requires the `budget_exceeded`
event added in audit schema 1.12.0. Unlike detection 9 it needs no
forwarder opt-in: `BudgetExceeded` is forwarded by default. It fires on
any breach the wirken runtime records; `action` distinguishes a block
(the call was refused) from an alert (the call proceeded). The wirken
runtime does the ceiling comparison, so this detection only surfaces
the event.

From audit schema 2.2.0, compaction summary calls are charged to the
agent's budget like a turn; before, they were made but not charged.
An agent near its ceiling can trip this detection sooner after the
upgrade.

### Detection 12 minimum

Detection 12 (binary changed outside `wirken update`) compares each
`gateway.start` row's detail version with the `to_version` of the most
recent `binary_installed` row from the same host, and needs audit
schema 2.3.0; `gateway.start` rows from older binaries name no build
and are skipped. A version that differs is high. So is a start whose
`commit` is `unknown` or whose `dirty` is not `clean`, while the host
has an install record: a release binary is built from a clean tree at
a known commit. `binary_installed` carries no commit, so the commit is
checked for release provenance rather than compared.

A host with no `binary_installed` row at all is informational, not
high: installs through `install.sh` and source builds leave no row, so
a missing row is not evidence of tampering. The detection keys the
install on the forwarding host name, so two installs on one host read
as one. `binary_installed` reaches the typed feed after the restart
that follows it, so each platform waits before judging a start.

### Detection 13 minimum

Detection 13 (downgrade or rollback) fires on a `binary_installed` row
with `rollback: true` or a `to_version` lower than its `from_version`.
It needs audit schema 2.3.0 and no forwarder opt-in: `binary_installed`
is forwarded by default. A rollback can move forward, when it undoes a
downgrade; it fires either way.

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
| `AuditLegacy`          | `actor_kind`, `actor_id`, `action`, `target`, `detail`                  | 5, 12             |
| `McpEntryRefused`      | `server_name`, `reason` (`signature_invalid` / `unsigned` / `signer_key_missing` / `signer_key_decode_failed` / `delegation_required`) | 6 |
| `HookDispatched`       | `hook_id`, `tool_name`, `agent_id`, `adapter_id?`, `sender_id?`, `decision.kind` (`allow` / `deny` / `timeout` / `unavailable`), `decision.reason?` | 7 |
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
| `PermissionGrantExpired` | `agent_id`, `channel?`, `adapter_id?`, `sender_id?`, `action_key`, `tool?`, `tier?`, `expired_at`, `detected_by?` (`tool_call` / `store_open`) | (none here; reserved) |
| `PermissionGrantPruned` | `agent_id`, `channel?`, `action_key`, `expires_at` | (none here; reserved) |
| `PermissionRenewed`    | `agent_id`, `channel?`, `adapter_id?`, `sender_id?`, `action_key`, `approved_by`, `approved_via?`, `previous_expires_at`, `expires_at` | (none here; reserved) |
| `PermissionRevoked`    | `agent_id`, `channel?`, `action_key`, `revoked_by`, `tier?`, `expires_at?` | (none here; reserved) |
| `PermissionApprovalRefused` | `request_id`, `action_key?`, `caller`, `reason` (`unauthorized_actor` / `wrong_channel` / `wrong_conversation`), `adapter_id?` | (none here; reserved) |
| `SubagentSessionBound` | `agent_id`, `parent_session_id`, `depth`, `max_permission_tier`, `tools_granted[]`, `offered_tools[]` | (none here; reserved) |
| `DeliveryConfirmed`    | `target`, `message_id`, `adapter_id?` | (none here; reserved) |
| `DeliveryFailed`       | `target`, `error`, `adapter_id?` | (none here; reserved) |
| `ExecLocationDisagreement` | `agent_id`, `adapter_id?`, `sender_id?`, `verified_session_id`, `approval_seq`, `result_seq`, `told.{mode,text}`, `ran.{mode,runtime,container_id?}` | 11 |
| `AdapterConnect`       | `adapter_id`, `channel`, `pubkey_fingerprint` | (none here; reserved) |
| `AdapterDisconnect`    | `adapter_id`, `channel`, `pubkey_fingerprint`, `reason` (`ended` / `panic`) | (none here; reserved) |
| `AdapterRestart`       | `adapter_id`, `channel`, `attempt`, `cause` (`process_exited` / `connection_ended` / `connection_panicked` / `spawn_failed` / `credential_changed`), `exit`, `delay_ms`, `connected_for_ms?` | (none here; reserved) |
| `AdapterRestartAbandoned` | `adapter_id`, `channel`, `attempts`, `last_cause`, `last_exit` | (none here; reserved) |
| `LlmRequest`           | `agent_id`, `credential_id?`, `sender_id?`, `request_id`, `provider`, `model`, `messages_hash`, `tools_hash`, `tools_hash_version`, `request_bytes?`, `purpose?` (`compaction_summary` / `tool_call_probe`; absent for a turn) | (none here; reserved) |
| `LlmRequestFailed`     | `agent_id`, `credential_id?`, `sender_id?`, `request_id`, `error`, `latency_ms` | (none here; reserved) |
| `LeakRefused`          | `agent_id`, `channel?`, `adapter_id?`, `sender_id?`, `credential`, `surface` (`tool_output` / `tool_arguments` / `provider_request` / `reply` / `user_message` / `skill_load`), `tool_name?`, `server_name?`, `skill_name?` | (none here; reserved) |
| `McpServerSandboxed`   | `agent_id`, `server_name`, `container_id`, `image`, `image_id?`, `image_digest?`, `runtime` (`docker` / `gvisor` / `host`), `memory_bytes`, `nano_cpus`, `pids`, `mounts[]`, `egress_hosts[]`, `secrets_as_files[]`, `secrets_in_env[]` | (none here; reserved) |
| `McpServerUnsandboxed` | `agent_id`, `server_name` | (none here; reserved) |
| `McpServerExited`      | `agent_id`, `server_name`, `container_id`, `exit_code?`, `stopped_by_proxy` | (none here; reserved) |
| `McpServerRestart`     | `agent_id`, `server_name`, `attempt`, `cause` (`exited` / `start_failed` / `initialize_failed` / `credential_changed`), `detail`, `delay_ms`, `ran_for_ms?` | (none here; reserved) |
| `McpServerRestartAbandoned` | `agent_id`, `server_name`, `attempts`, `last_cause`, `last_detail` | (none here; reserved) |
| `McpCredentialRefetched` | `credential` | (none here; reserved) |
| `ChainHead`            | `reason` (`session_start` / `session_end` / `checkpoint` / `rotation` / `redaction`), `sequence_range_start`, `sequence_range_end`, `signing_pubkey`, `build?` (`{version, commit, dirty}`, only when `reason` is `session_start`) | (none here; reserved) |
| `BinaryInstalled`      | `from_version`, `to_version`, `binary_sha256`, `target`, `verifying_key?` (fingerprint `SHA256:...`), `rollback` | 12, 13 |
| `EgressHookDispatched` | `hook_id`, `tool_name`, `agent_id`, `adapter_id?`, `sender_id?`, `decision.kind` (`allow` / `replace` / `refuse` / `timeout` / `unavailable`) | (none here; reserved) |
| `InboundSenderRefused` | `channel`, `adapter_id`, `sender_id`, `conversation_id`, `reason` (`not_allowed` / `allowlist_unreadable`), `suppressed`, `suppressed_on_lane` | (none here; reserved) |
| `InboundSenderAdded`   | `channel`, `id`, `group`, `label`, `added_by` | (none here; reserved) |
| `InboundSenderRemoved` | `channel`, `id`, `group`, `removed_by` | (none here; reserved) |
| `ApproverAdded`        | `adapter_id`, `user_id`, `display_name`, `added_by` | (none here; reserved) |
| `ApproverRemoved`      | `adapter_id`, `user_id`, `removed_by` | (none here; reserved) |
| `ApprovalChatSet`      | `adapter_id`, `previous_conversation_id?`, `conversation_id`, `set_by` | (none here; reserved) |
| `OperatorCommandRefused` | `command` (`senders` / `approvers`; on main after 3.1.0 also `permissions` / `skills` / `mcp` / `credentials` / `vault` / `audit` / `agents` / `channel` / `cron` / `hooks` / `persona` / `preset` / `webchat` / `zirkel` / `setup` / `import`), `invocation` (the subcommand; empty for `setup` and `import`), `reason` (`inside_exec`) | (none here; reserved) |
| `SessionLivenessUnavailable` | `error` | (none here; reserved) |
| `AgentStopped`         | `agent_id`, `stopped_by`, `grants_revoked`, `session_grants_cleared` | (none here; reserved) |
| `AgentResumed`         | `agent_id`, `resumed_by` | (none here; reserved) |
| `UpdateRefused`        | `invocation` (`check` / `install` / `rollback`), `reason` (`inside_exec` / `vault_format`) | (none here; reserved) |
| `McpCredentialRefreshDiscarded` | `credential`, `reason` (`removed` / `reauthorized` / `unreadable`) | (none here; reserved) |
| `CredentialDestinationRefused` | `credential`, `destination_kind` (`host` / `mcp_server` / `provider` / `adapter` / `plan`), `destination`, `named_by` | (none here; reserved) |
| `CredentialDestinationGranted` | `credential`, `destination_kind`, `destination`, `granted_by` | (none here; reserved) |
| `CredentialDestinationRevoked` | `credential`, `destination_kind`, `destination`, `revoked_by` | (none here; reserved) |
| `CredentialHandedOut`  | `credential`, `destination_kind`, `destination` | (none here; reserved) |
| `VaultMigrated`        | `rows`, `from_format`, `to_format`, `backup` | (none here; reserved) |
| `ReadSensitivityObserved` | `sensitivity` (`workspace` / `channel_memory` / `cross_channel_memory` / `imported_archive` / `aggregated_external` / `exec_output` / `mcp_output` / `credentialed_response`), `tool` | (none here; reserved) |
| `ReadSensitivityExempted` | `exempted[]` (`exec_output` / `mcp_output`), `still_escalated` | (none here; reserved) |
| `OperatorCommand`      | `command`, `target`, `detail?`, `run_by` | (none here; reserved) |
| `AuthorityReloaded`    | `subject_kind` (`credential` / `adapter` / `hook`), `subject`, `change` (`rotated` / `rebound` / `removed` / `added` / `rekeyed`), `reloaded[]` | (none here; reserved) |

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
and `PermissionApproved`, which is not. `ExecLocationDisagreement` is
forwarded by default for that reason: it carries the approval's `told`
and the result's `ran` on one row, so detection 11 needs no approval
rows. It is written by `wirken sessions verify` to the `gateway-verify`
lane, so its `session_id` is that lane and `verified_session_id` is
the session the pair is on; it appears only once verify has been run. Its `mode` is the sandbox mode
the prompt described; the `mode` and `runtime` on the paired
`ToolResult.sandbox` are where the command ran. A row pair where the
prompt said a container and the result says `runtime: host` is the
mismatch `wirken sessions verify` reports as an `exec_location`
divergence.

Of the variants added in 2.0.0, the typed forwarder sends
`LeakRefused`, the five MCP server events, `McpCredentialRefetched` and
the four adapter events by default; `LlmRequestFailed` is outside the
default set, like `LlmRequest` and `LlmResponse`, because a provider's
error text can quote the request it refused. The MCP server events are
written on the `gateway-mcp` lane and `McpCredentialRefetched` on
`gateway-mcp-credentials`; `LeakRefused` names the credential, never
its value, on the session the content belonged to. `LlmRequestFailed`
carries the `request_id` of the `LlmRequest` it ends.

`LlmRequest.purpose` marks model calls made alongside the conversation.
Compaction summary calls happened before 2.2.0 but were not recorded;
from 2.2.0 each is an `llm_request` with `purpose: compaction_summary`
and an `llm_response` priced and charged to the agent's budget like a
turn. `tool_call_probe` is Lyrik's preflight call. `LlmRequest` is
outside the default forwarded set, so a SIEM tells these calls apart
from turns only when `llm_request` is listed in
`typed_include_variants`.

`BinaryInstalled` is forwarded by default. It is written on the
`gateway-install` lane, outside any session, with no agent, adapter or
sender. `rollback` is true for `wirken update --rollback`;
`verifying_key` is the fingerprint of the release key whose signed
manifest the installed binary's sha256 was checked against, and on a
rollback the one recorded when the restored binary was set aside,
absent when none was. A row records that the operator ran the command;
it does not prove the binary on disk was not changed by other means.

`ChainHead` is forwarded by default. Its `build` names the binary that
opened the session, so a chain segment can be attributed to a build
however that build was installed. The `gateway.start` legacy row
carries the same `{version, commit, dirty}` in its detail from 2.3.0;
before, its detail was null. `commit` is a short hash or `unknown`;
`dirty` is `clean`, `dirty` or `unknown`.

Every variant added in 3.0.0 is forwarded by default, with no agent,
adapter or sender column except `InboundSenderRefused`, which carries
the adapter and the refused sender. They are written outside any
session, on `gateway-inbound` (`InboundSenderRefused`),
`gateway-senders`, `gateway-approvers` (the allowlist changes and
`OperatorCommandRefused`), `gateway-install` (`UpdateRefused`),
`gateway-mcp-credentials` (`McpCredentialRefreshDiscarded`) and
`gateway-credentials` (the credential destination rows and
`VaultMigrated`). `CredentialDestinationRefused` is `error`;
`InboundSenderRefused`, `OperatorCommandRefused` and
`McpCredentialRefreshDiscarded` are `warn`. A credential row names the
credential and never its value.

Every variant added in 3.1.0 is forwarded by default at `info`, with no
agent, adapter or sender column. `ReadSensitivityObserved` is written on
the session that read: once per label, the first time, so a session's
rows list what escalates its later `http_request` calls.
`ReadSensitivityExempted` is on the same session, once per turn where an
agent's `exempt_exec_mcp_output` setting left `exec_output` or
`mcp_output` out of that escalation; `still_escalated` is whether other
labels sent the call to the operator anyway. `OperatorCommand` is on
`gateway-operator`, one row per `wirken` command that changed what the
gateway trusts or runs, sealed by a chain head; `detail` never holds a
secret. `AuthorityReloaded` is on `gateway-reloads`, one row per change
the running gateway took up without a restart. An `AdapterRestart` or
`McpServerRestart` with cause `credential_changed` is `info`, with no
delay: it was asked for, not a failure.

On Wirken main after 3.1.0, not yet released: `SessionLivenessUnavailable`
is on `gateway-permissions`, sealed by a chain head, forwarded by default
at `warn`, with `error` and no agent, adapter or sender column.
`OperatorCommandRefused` is also written on `gateway-operator`, sealed by
a chain head, for each refused subcommand of `permissions`, `skills`,
`mcp`, `credentials`, `vault`, `audit`, `agents`, `channel`, `cron`,
`hooks`, `persona`, `preset`, `webchat` and `zirkel`, and for `setup` and
`import`, whose `invocation` is empty. No detection keys on `command`, so
detections 1-13 fire unmodified on both.

Also on main after 3.1.0: `AgentStopped` and `AgentResumed` are on
`gateway-operator`, one row per `wirken agents stop` or `resume`, sealed by
a chain head, forwarded by default, `AgentStopped` at `warn` and
`AgentResumed` at `info`, with the agent column set and no adapter or
sender. A pending approval a stop denies is a `PermissionDenied` with
`denial_reason` `agent stopped`. A message to a stopped agent is a
`message.refused` legacy row, and a cron firing for one a `cron.skipped`
legacy row targeting the job id, each with detail `{reason:
"agent_stopped", agent_id}`. Detections 1-13 fire unmodified.

A query that matched a CLI actor field against a login name, such as
`added_by="davi"`, matches nothing from 3.1.0 on: the field holds
`uid:1000 (davi)`. Match the uid, or the name in parentheses.

`connection.panic` (2.0.0) is a legacy row for a connection task that
panicked: target the adapter id, or the connection kind when there is
none, and detail `{kind, adapter_id, location, payload_len,
payload_sha256}`. Datadog sends it with `status: error`; the other
targets carry no level on legacy rows.

Row metadata on every typed event: `session_id`, `seq`, `ts`,
`trust`, `kind`, and from 2.0.0 `level`. The forwarder wraps each row
in a per-target envelope; see the platform READMEs for the exact field
names per target. `level` is `event.level` on Splunk, `level` on the
webhook, `Level` on Sentinel and `status` on Datadog, where it was
always `info` before. It is `info` for most variants; the adapter and
MCP server lifecycle events take it from their reason or cause,
`LeakRefused` is `error` and `LlmRequestFailed` is `warn`.

From 2.0.0 a sequence number is never reused: a rewind's marker takes
the number after the highest the session issued, so `(session_id,
seq)` names one row for the life of the session and deleted rows leave
a gap. Through 1.28.x, rows written after a rewind reused the deleted
rows' numbers, so a SIEM that kept rows from before the rewind can hold
two different rows under one `(session_id, seq)`.

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
| 11 | Exec prompt disagreed with the run | `ExecLocationDisagreement`     | high              |
| 12 | Binary changed outside `wirken update` | `AuditLegacy` (`gateway.start`) + `BinaryInstalled` | high; informational with no install record |
| 13 | Downgrade or rollback              | `BinaryInstalled`              | medium            |

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
  detections 1-8, 12 and 13 in-process; detections 9 to 11 are not
  ported to the webhook consumer.

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
