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
