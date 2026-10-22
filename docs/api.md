# API reference

The running controller publishes an OpenAPI schema at `/openapi.json` and interactive reference at `/docs` when enabled. `docs/openapi.json` captures the delivered schema. REST uses an HttpOnly SameSite session cookie or opaque bearer token. Cookie-authenticated writes require the configured same Origin. Authentication failures return401 and authorization failures403. Opaque tokens are stored hashed.

| Area | Routes |
| --- | --- |
| Authentication | POST `/api/auth/login`, GET `/api/auth/me`, POST `/api/auth/logout` |
| Inventory | GET `/api/overview`, `/api/hosts`, `/api/hosts/{id}`, `/api/hosts/{id}/inventory`, `/api/hosts/{id}/inventory/history`, `/api/hosts/{id}/metrics`, `/api/topology` |
| Node control | POST `/api/nodes/enrollment`, `/api/nodes/enroll`, `/api/nodes/report`, `/api/nodes/heartbeat`, GET `/api/nodes/commands`, POST `/api/nodes/commands/{id}/result`, `/api/hosts/{id}/revoke` |
| Persistent work | GET/POST `/api/jobs`, GET `/api/jobs/{id}`, `/api/jobs/{id}/events`, POST `/api/jobs/{id}/pause`, `/resume`, `/cancel`, GET `/api/events` SSE |
| Recurring work | GET/POST `/api/schedules`, PATCH `/api/schedules/{id}` |
| Conversation | POST `/api/chat` |
| Policies | GET/POST `/api/policies`, PATCH `/api/policies/{id}` |
| Accounts | GET/POST `/api/users`, PATCH `/api/users/{id}` |
| Operations | GET `/api/findings`, GET/POST `/api/incidents`, GET `/api/memory`, `/api/backups`, `/api/recovery/status`, `/api/integrations`, `/api/catalog`, `/api/projects`, `/api/settings/models` |
| Audit/safety | GET `/api/audit`, `/api/audit/verify`, GET/POST `/api/emergency-stop` |
| MCP | POST `/mcp`, owner GET/POST `/api/mcp/clients`, DELETE `/api/mcp/clients/{id}`, OAuth metadata and `/oauth/*` |

Only agent-specific tokens can report inventory or consume node commands. Users cannot submit arbitrary node result payloads. Node commands are durable, expire and are reauthorized at delivery. Controller URLs, model config and integration endpoints are owner-installed configuration; they are not arbitrary tool arguments.

A workflow example:

```json
{"kind":"workflow","host_id":"REPLACE_WITH_HOST_ID","spec":{"steps":[{"operation":"inventory.refresh","arguments":{}},{"operation":"systemd.restart","arguments":{"service":"example.service"}},{"operation":"inventory.refresh","arguments":{}}]},"time_limit":300,"max_attempts":2,"token_budget":0,"cost_budget":0}
```

Submission and execution both require active policies for concrete operations. The example service must also be separately allowlisted by its node broker. No documented example grants a real server permission by itself.


## Setup and diagnostics additions

All setup/configuration routes below require an authenticated owner.

| Method | Route | Behavior |
| --- | --- | --- |
| GET | `/api/settings/models` | Effective validated routes and timestamped readiness; empty routes mean unconfigured. |
| POST | `/api/settings/models/discover` | Bounded provider model discovery from a validated fixed endpoint. |
| POST | `/api/settings/models/test` | Capability/readiness and harmless structured tool-call probe; no infrastructure tool execution. |
| PUT | `/api/settings/models/{name}` | Test then persist a route, audit the change; no inline secret values. |
| GET | `/api/policies/profiles` | Read-only, maintenance and development profile descriptions. |
| POST | `/api/policies/profiles` | Grant named identity/host/argument/environment scope with expiration; never a universal root grant. |
| GET | `/api/diagnostics` | Actionable configuration/schema/worker/asset/node findings; no repair side effects. |

Permission failures return `403 {detail, denial}`. Policy-blocked jobs persist the
same denial under `result.denial` with operation, host, project, arguments,
environment, missing permission and remediation. `partial` is a terminal job state
for explicit unfinished or unverified AI outcomes. Existing successful dependency
checks continue to require `succeeded`, so partial work does not unlock dependents.
