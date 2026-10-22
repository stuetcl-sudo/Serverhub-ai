# Troubleshooting

| Symptom | Check |
| --- | --- |
| Health503 | Database connection, migration identity and exact Alembic head. A reachable but outdated schema is unhealthy. |
| Empty dashboard | Enroll a node, confirm its first report, check the signed-in user's host read policy. No synthetic hosts are seeded. |
| Node offline | TLS certificate trust, public URL, unique identity, revocation and `journalctl -u serverhub-node`. Never disable certificate validation. |
| Broker denied | Configured peer UID/group, root-owned config ancestors, exact service/container/project/diagnostic target allowlist. Agent and worker must not join the Docker group. |
| Job waiting_approval | Check actor, role ceiling, host/project, target arguments, expiry and production flag. After a concrete policy is added, explicitly resume. |
| Job paused | Pause request or emergency stop. Review whether an external operation was already dispatched before resuming. |
| Interrupted integration write | Inspect its saved before-change checkpoint and external state; automatic blind replay is intentionally refused. |
| Inventory partially unavailable | Inspect inventory.errors. netlink, systemd, sensors, firewall, Docker or process attribution can require OS capabilities or the broker. A collection failure is not evidence that the facility does not exist. |
| OpenAI/Ollama job fails | Protected model YAML, environment secret reference, endpoint/model/tool support, configured prices and remaining budget. No paid provider is configured automatically. |
| Development sandbox unavailable | Bubblewrap/user namespace and cgroup support. Tests fail closed; do not enable an unsandboxed shell fallback. |
| OAuth invalid_target | Exact public `/mcp` resource must match in every OAuth request. |
| OAuth invalid_client | Use the same pre-registered client/secret and exact callback. Disabled clients must be reauthorized through the owner. |
| MCP401 | Normal REST/agent tokens are not accepted as MCP tokens. Inspect the protected-resource challenge and OAuth flow. |
| Backup list empty | Independent backup timer/status export may not have run. Review native status separately from SQL backup records. |
| Update rejected | Signature, exact file set/hashes, trusted signing key, validation metadata, installed schema revision and trust-boundary digest. Trust-boundary changes require an owner-reviewed maintenance release. |

Collect bounded, redacted logs. Do not paste secrets, full environment variables or production database dumps into chat. No claim is made that all secret-like text in arbitrary application output can be recognized automatically.


## Installation/autonomy overhaul diagnostics

| Symptom | Check and action |
| --- | --- |
| Interrupted installer | Rerun the same reviewed-source command; keep `/var/lib/serverhub-install/state.json` and environment files. |
| Inaccessible migration cwd | New installer runs migrations from the installed absolute release with source import paths removed. Legacy installs use the backed-up repair workflow. |
| Worker exits before Python | Inspect `journalctl -u serverhub-worker`; new units mask optional absent sockets with `-` and preserve strict filesystem isolation. |
| Assets 403 on loopback | Use the same localhost origin/port through the tunnel. Foreign Origins remain rejected; verify assets and directory traversal in diagnostics. |
| Empty model routes | Setup → AI provider → discover/test/save `default`. A file merely existing no longer means a model is configured. |
| Permission denied reading models | Inspect leaf and ancestors with `namei -l`; worker must read non-secret root-owned fallback config. Prefer owner-managed DB routes; never expose secret environment files. |
| Private Ollama HTTP rejected | Use a literal RFC1918/ULA IP and explicit endpoint consent, or HTTPS. DNS/public/metadata HTTP endpoints are deliberately refused. |
| Approval-blocked job | Inspect exact denial fields, grant only the intended subject/host/arguments/environment until expiry, then resume its saved job. |
| Controller grant but node failure | Broker allowlists and protected-service checks are independent. Controller policy cannot bypass an offline/misconfigured broker. |
| Partial AI result | Inspect completed tool evidence and verification checks. A fluent model summary without successful measurable verification is not success. |
| Stale model-readiness timestamp | Run the live model connection/tool test again; diagnostics does not silently generate paid model requests. |
