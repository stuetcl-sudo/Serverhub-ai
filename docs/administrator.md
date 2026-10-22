# Administrator guide

## Initial onboarding

Install into a disposable Ubuntu 24.04 VM using the installation guide. Configure a trusted HTTPS origin and then sign in using the bootstrap owner credentials. Store the credentials privately and remove the temporary bootstrap file. Create personal accounts rather than sharing the owner's session.

The console has no seeded hosts or healthy sample services. Empty states mean no real data has been reported. Use **Managed hosts → Enroll node** to issue a short-lived token. Place that token in the root-owned node configuration, enable the unprivileged node service and remove the consumed enrollment token from the configuration. Each agent retains its own identity. Revoking a host immediately rejects its identity; re-enrollment creates a new identity rather than restoring an old secret.

## Roles and capabilities

| Role | Effective behavior |
| --- | --- |
| Owner | Manages users/policies/model metadata/enrollment/emergency stop. Infrastructure writes still need an explicit active policy. |
| Administrator | Uses policy-granted host/project operations. Cannot administer owner-only control-plane settings. |
| Adult | Uses policy-granted household diagnostics and predefined repair capabilities within the role ceiling. |
| User | Uses narrower policy-granted diagnostics/reporting capabilities. |
| Read-only | Can use explicitly granted read capabilities and cannot submit write jobs. |

A role is not a global permission grant. Non-owner infrastructure reads require a host grant. A changed role, disabled account, revoked host or revoked/expired policy is checked again during execution. Prompt wording and specialist selection cannot change authenticated identity.

A policy targets a subject or role, an optional host/project, an exact operation list or explicit prefix grant, an expiry, and argument constraints. Prefer exact operations and targets over broad prefixes. For example, a grant for `systemd.restart` can contain `{"service_names":["example.service"]}` and expire after two hours. This must also match the node broker's separately configured service allowlist. A broad owner prompt never populates that broker allowlist automatically.

Production policies require explicit constraints and the production flag. There is currently no generic development production-deploy adapter; a production policy cannot create a missing capability. The same applies to firewall, SSH, credential changes and arbitrary database commands.

## Models and integrations

Copy examples from `docs/examples` into protected `/etc/serverhub` files after reviewing them. The installed defaults are empty. Endpoint URLs, model names, route choices, per-token prices, entity/site/repository allowlists and integration operation allowlists are operator configuration. Provider credentials come from named environment variables in the worker's protected environment, not from prompts or browser configuration. Restart the worker after changes to its environment.

Use a local Ollama provider or a configured OpenAI-compatible API. API cost estimates rely on configured prices and returned token accounting; failed uncertain responses are conservatively charged. A zero or exhausted job budget stops work. External prices and model identifiers are not hard-coded assumptions.

## Jobs, chat and schedules

Select a target host for node diagnostics and repairs; controller context alone does not grant cross-host execution. Chat submits an `autonomous` job. Its specialist tool loop records progress and checks policy for every tool. The browser can disconnect. Inspect job events and the result for measured outcomes and remaining work; a prose completion is not independent proof that an external service improved.

`operation` executes one registered tool; `workflow` executes ordered checkpointed steps. `inventory` reads the last report, while the `inventory.refresh` node operation requests a fresh measurement. `monitoring` requests new inventory and can execute explicitly authorized registered restarts with `{"repair":true}`. It verifies a service's active state or a container's healthy state after a second fresh report. It does not infer that all application functions work.

Owner-only recurring jobs use `/api/schedules` (also shown in the jobs UI when available). For example:

```json
{"name":"Host diagnostics","kind":"monitoring","host_id":"REPLACE_WITH_ENROLLED_HOST_ID","interval_seconds":300,"spec":{"repair":false}}
```

Creating a schedule submits its first job immediately. Missing intervals coalesce, unfinished jobs never overlap, and a schedule cannot extend expired policies. Toggle `enabled` using `PATCH /api/schedules/{id}`. There is no cron-expression/time-zone parser; intervals are UTC-based elapsed periods.

Pause, resume and cancel affect persistent execution state. Cancelling a worker cannot undo a side effect already sent to a remote service; inspect its adapter checkpoint and node journal. Emergency stop pauses active work and prevents further claims/delivery. It is not a network circuit breaker that retracts an already executing broker operation.

## Security and recovery

Treat findings as evidence to investigate. `not_observed` means a finding was not observed in a later snapshot, which can include a collection gap; it is not a verified repair. In particular, host networking, missing healthchecks and privileged containers may have legitimate requirements. Never remove unknown services solely based on a finding.

Native backups run independently from the AI and publish read-only status to the dashboard. Verify checksums and perform restore drills to a generated disposable database. Archive copies and disaster recovery media remain the operator's responsibility. Review `docs/recovery.md` before upgrades.

The installed update path requires the owner's trusted signing key, exact artifact hashes, validation metadata and unchanged trust-boundary digest. AI-generated changes can be proposed and tested but cannot silently replace the installed policy, audit, OAuth or recovery implementation.
