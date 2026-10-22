# AI providers and service integrations

The controller uses ordinary HTTP APIs and an explicit fixed tool registry. It does
not require Codex, a ChatGPT browser session, unrestricted SSH or a Docker socket.
Provision the example YAML under `/etc/serverhub`, owned by root, without group/world
write permission. Configuration ancestors must also be protected. Secret values are
read from named environment variables in protected worker configuration; YAML contains
references, not keys. The API exposes sanitized descriptors, never credential values.

## Models and durable autonomy

See [models.yaml](examples/models.yaml). `openai` routes call `/chat/completions` under
the configured base URL; `ollama` routes call `/api/chat` with `stream:false` and native
structured tool calls. `max_tokens_parameter` supports `max_tokens` and
`max_completion_tokens` for providers with different compatible APIs. Cloud providers
need explicit configured input/output prices; there are no guessed prices. Loopback
Ollama can use HTTP; remote endpoints require HTTPS unless an owner explicitly opts
into insecure HTTP. Redirects are not followed and environment proxy configuration is
not inherited. Private CA files are supported by service integrations.

Eight specialist configurations share the same persisted job state and authenticated
identity: infrastructure, Linux, Docker, security, network, development, monitoring,
and verification. A specialist can select a configured model route; it cannot widen
its permissions. This implementation provides sequential specialist delegation and a
common tool loop, not eight independently running peer processes.

An autonomous job accepts `prompt`, optional `model_route`, `specialist`, and
`max_steps` (1–100). Job limits independently cap duration, retries, token use and API
cost. Larger multi-step investigations typically need a token budget above the default
20,000 because tool schemas and conversation history are counted on each request.
Before a provider request, UTF-8 byte counts conservatively bound tokens, including tool
schemas. Reported usage is charged; missing usage or uncertain transport failure is
charged at the reserved upper bound. Local model CPU/GPU costs are not monetary API
charges. Prices are operator inputs, not verified billing guarantees.

Model responses and pending tool calls are checkpointed in PostgreSQL before execution.
Completed tool results are reused after restart. A Linux-node command carries a stable
call-specific idempotency key, permitting a fresh later probe without replaying an old
measurement. An interrupted remote API mutation stops for owner reconciliation using
the stored prechange checkpoint; it is never silently repeated. Configured read failures
can retry within bounds. Authorization denial stops execution rather than asking a new
specialist to bypass it. Provider errors are sanitized; response content is not echoed
as an error containing credentials.

`inventory.read` gives a compact, explicitly truncated snapshot. `inventory.query` reads
bounded sections when more package, service, port, container or address details are
needed. Historical memory is scoped to the job host/project and returned with its
verification status. AI prose is stored as unverified memory even if a tool succeeded;
only independent measured evidence can establish a verified fix.

## Installed adapters

All adapters below have automated protocol-contract tests where listed; **none have
been tested against Dennis's production services or a paid model account**.

| Adapter | Implemented operations | Limits / verification |
|---|---|---|
| Home Assistant | API health; allowlisted entity states; allowlisted light/switch/input_boolean on/off | Write checkpoints previous state, verifies API state, restores on failure. API state does not prove physical actuation. Mock HTTP tests. |
| AdGuard Home | Health/stats, filters, refresh, simple domain rules, replacement with an owner-vetted HTTPS source | Rule/replacement writes require both allowed and blocked canaries, snapshot and readback; attempted rollback is reported. No arbitrary rewrite rules or guessed replacement URL. Mock rollback tests. |
| UniFi Network | Official integration API sites/devices/clients | Owner-configured site IDs and API key; first 100 records with pagination limitation explicit. No firewall or device writes. Mock site/header/path tests. |
| UISP | Network API v2.1 devices/sites | Read-only adapter; API contract must be checked against the deployed version. No invented radio control. |
| PostgreSQL | Version, database size and recovery state | DSN from environment; read-only transaction and statement timeout. No SQL input or database changes. |
| Prometheus | Named preconfigured instant PromQL query | Prompt cannot choose arbitrary query text. |
| Grafana | API health and dashboard index | Read-only; no alert or dashboard mutation adapter. |
| GitHub | Allowlisted repository metadata and last five commits | Read-only service API adapter. Development Git workspaces are a separate tool path. |
| Existing ServerHub MCP | Initialize, initialized notification, tools/list metadata | JSON Streamable HTTP only, negotiated 2025 protocol versions; supports session header. No arbitrary tools/call passthrough or automatic OAuth refresh. Mock handshake tests. |
| Docker/Systemd/Linux | Inventory, named status/restart, configured network diagnostics/scanners, registered Compose deployment | Through the separately configured node broker; worker never receives root or Docker-group membership. Exact local broker limits apply. |

Read-only operations on platforms supporting writes reflect the **current implementation
coverage**, not a claim that those APIs cannot support writes. Further mutation adapters
need a reviewed operation schema, narrow authorization, durable reconciliation and
operation-specific verification before enabling them.

API-level AdGuard rollback runs in the active operation process. It is not an independent
network watchdog. Crash recovery retains its snapshot and halts for reconciliation.
Critical route/firewall/SSH changes are outside these tools; the platform does not claim
to automatically close all ports or eliminate all vulnerabilities.

## Service catalog

The catalog contains Stirling PDF for interactive PDF tooling and Paperless-ngx for a
searchable archive. It explains the selection and returns reviewable plans. Stirling
plans require an owner-verified immutable digest, loopback binding, resource limits,
authentication, backup registration and a registered broker manifest. Paperless plans
report their unconfigured Redis/database/secret dependencies. **The catalog does not
yet provide unattended arbitrary application installation or reverse-proxy registration.**

## API sources

These are the primary API contracts used by the adapters:

- [OpenAI-compatible chat completion reference](https://platform.openai.com/docs/api-reference/chat/create)
- [Ollama chat API](https://docs.ollama.com/api/chat)
- [Home Assistant REST API](https://contributors.home-assistant.io/core/internals/rest-api/)
- [AdGuard Home OpenAPI](https://github.com/AdguardTeam/AdGuardHome/blob/master/openapi/openapi.yaml)
- [UniFi Network Integration API](https://developer.ui.com/network)
- UISP local generated Swagger: `https://YOUR_UISP_INSTANCE/nms/api-docs/` (validate against the installed instance before enabling). No current instance schema was available during this build.
- [Prometheus HTTP API](https://prometheus.io/docs/prometheus/latest/querying/api/)
- [Grafana HTTP API](https://grafana.com/docs/grafana/latest/developers/http_api/)
- [GitHub REST repository API](https://docs.github.com/en/rest/repos/repos)
- [MCP 2025-11-25 transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)

Validate vendor version-specific behavior before granting production write policies.
