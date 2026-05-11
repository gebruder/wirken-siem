# wirken-siem

Detection content for the Wirken audit schema. The repo ships
saved searches, monitors, analytics rules, and a reference
webhook consumer that SOC teams can wire up without reading the
upstream code. Versions track the audit schema, not the wirken
binary.

## Compatibility

| wirken-siem | Wirken audit schema |
|-------------|---------------------|
| 0.1         | 1.3.x               |

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
| `AuditLegacy`          | `actor_kind`, `actor_id`, `action`, `target`, `detail`                  | 6                 |

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
| 6  | Chain tamper correlation           | `AuditLegacy` (`audit.chain_broken`) | high; critical when alarm log missing |

Detection 5 is intentionally absent: it corresponds to a code gap
(`Action::SkillInstall` is declared as a Tier 3 action but the
`wirken skills install` CLI path does not route through the agent
tier gate). That gap is closed in wirken, not in detection content.

## Layout

- `splunk/` saved searches, macros, eventtypes; ingestion via
  HEC `sourcetype=wirken:audit` (legacy) and `sourcetype=wirken:session`
  (typed).
- `datadog/` monitor JSON and dashboard JSON; ingestion via
  Datadog Log Intake under `@ddsource:wirken`.
- `sentinel/` analytics rule YAML and workbook JSON; ingestion via
  DCR streams `Custom-WirkenAudit_CL` and `Custom-WirkenSession_CL`.
- `webhook/` reference Python consumer that verifies the
  `X-Wirken-Signature` HMAC over the raw POST body, then runs the
  five rules in-process.

## What this repo is not

- Not a Splunk app, a Datadog terraform module, or a Sentinel
  solution package. Bare content first; packaging if and when an
  operator adopts the content at scale.
- Not a documentation site. The field index above is the only
  prose; everything else is rules.
- Not the audit-schema reference. That lives in
  `wirken/docs/audit-schema.md` (forthcoming).
