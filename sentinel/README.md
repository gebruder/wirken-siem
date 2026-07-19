# sentinel/

Analytics rule YAML and a workbook for Microsoft Sentinel against
the Wirken 1.3.x DCR streams.

## Ingestion

The detections read from two Data Collection Rules (DCRs):

- `Custom-WirkenAudit_CL`: legacy AuditEvent rows from the
  primary wirken `siem.json` `endpoint`. Column-pinned to the
  legacy shape.
- `Custom-WirkenSession_CL`: typed SessionEvent rows from the
  wirken `sentinel_typed.endpoint`. Column-pinned to the typed
  shape: `TimeGenerated`, `SessionId`, `Seq`, `Kind`, `Trust`,
  `AgentId`, `AdapterId`, `SenderId`, `Event`, `Hostname`.

Configure both DCRs in your Sentinel workspace before deploying
the rules. The wirken side ships the row shapes; the DCR
transforms are operator-side.

## Deploy

Via the Sentinel content hub (preferred), or via Azure CLI:

```
for f in rules/*.yaml; do
  az sentinel alert-rule create \
    --resource-group <rg> \
    --workspace-name <ws> \
    --rule-id "$(uuidgen)" \
    --kind Scheduled \
    --etag '*' \
    @"$f"
done
```

## Watchlist: `wirken_skill_dirs`

Detection 4 reads from a Sentinel watchlist named
`wirken_skill_dirs`. Schema: one column `prefix` (string).
Populate with operator-supplied prefixes via the Sentinel
watchlist admin or `az sentinel watchlist-item create`.

An empty watchlist makes the rule return zero rows; document the
gap on first deploy.

## Alarm log (Detection 5)

The audit-alarms log is a separate ingest path. Wire it into a
Custom Log DCR named `Custom_WirkenAlarms_CL` with the same
`SessionId` and `detail.seq` fields the legacy chain-broken row
carries. The Detection 5 rule joins on
`(SessionId, Seq)` with a 60s window and promotes severity to
Critical when no matching alarm row is found.

## Detection summary

| Rule file                       | Severity baseline | Source DCR                  |
|---------------------------------|-------------------|-----------------------------|
| `shell_outbound_fetch.yaml`     | Medium            | Custom_WirkenSession_CL     |
| `exec_fork_pairing.yaml`        | Medium (>30s)     | Custom_WirkenSession_CL     |
| `binary_write.yaml`             | High              | Custom_WirkenSession_CL     |
| `skill_dir_exec.yaml`           | High              | Custom_WirkenSession_CL     |
| `chain_tamper.yaml`             | High / Critical   | Custom_WirkenAudit_CL + Alarms |
| `agent_cost_anomaly.yaml`       | Medium            | Custom_WirkenSession_CL     |
