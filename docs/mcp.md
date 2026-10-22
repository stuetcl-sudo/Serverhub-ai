# MCP and ChatGPT connection

## Implemented server

The endpoint is `https://YOUR_CONTROLLER_ORIGIN/mcp`. It implements stateless JSON responses for MCP revisions 2025-03-26, 2025-06-18 and 2025-11-25; it does not claim 2026 protocol compatibility, MCP task extensions, sampling or the optional GET/SSE stream. GET/DELETE return 405. JSON-RPC notifications return 202. Origin validation, authentication, method/argument validation and persisted authorization apply.

Tools list/read hosts and inventory, security findings, incidents, recorded backup status, own job progress/results, submit persistent jobs, request remediation, list policies, list predefined policy templates and activate a bounded predefined nonproduction approval. No unrestricted execution tool exists.

## OAuth

The server publishes protected-resource metadata, authorization-server metadata and an authorization-code flow with S256 PKCE. Clients are **pre-registered by an authenticated owner**; public dynamic client registration and CIMD document fetching are not implemented. Exact HTTPS redirect URIs must be supplied by the connecting client. Access tokens are one-hour, opaque, audience-bound MCP tokens; they cannot access REST or agent endpoints. Refresh tokens rotate, and replay revokes their grant family. OAuth database tables are inaccessible to the AI worker.

Register using `POST /api/mcp/clients` with a normal owner REST bearer/session, for example:

```json
{"name":"My ChatGPT connection","redirect_uris":["REPLACE_WITH_EXACT_HTTPS_CALLBACK_FROM_CLIENT"],"confidential":true}
```

The response contains `client_id` and the one-time client secret. Store them privately in the connecting client's OAuth configuration; never commit them. The token authentication method for this client is `client_secret_post`; public clients use `none`. Both require PKCE. The `resource` parameter must equal the exact public `/mcp` URI in authorization, exchange, refresh and revocation requests.

Requested scopes are `serverhub:read`, `serverhub:jobs` and, for owner approval controls, `serverhub:policies`. The browser must first sign into ServerHub; the authorization page then asks for explicit consent. A newly connected client cannot bypass existing role, host or operation policy.

Revoke a connection using owner-only `DELETE /api/mcp/clients/{client_id}`. This disables it and revokes its issued tokens. It does not revoke unrelated browser sessions.

## Connect from ChatGPT

Current official OpenAI documentation describes connecting a custom MCP server, selecting OAuth and using predefined OAuth clients where supported. Configure this installation as a predefined client, supply the exact callback shown by your connection management screen, and use the registered ID/secret. Set the MCP URL to your HTTPS `/mcp` endpoint. Sign in to ServerHub and approve the requested scopes. If your particular client surface only supports DCR or CIMD, this implementation needs that extension before it can connect; do not enable unauthenticated tools to bypass it.

The deployment must be reachable by the selected client transport with valid TLS. No tunnel or public ingress is automatically installed. A real connection from the owner's ChatGPT account has **not** been tested in this delivery, and account-specific availability is not assumed.

Official references, checked 22 October 2026:

- https://developers.openai.com/plugins/build/auth
- https://developers.openai.com/plugins/deploy/connect-chatgpt
- https://developers.openai.com/api/docs/guides/custom-mcp-server
- https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- https://modelcontextprotocol.io/specification/2025-11-25/basic/transports

## Predefined policy approvals

Create root-owned `/etc/serverhub/mcp-policies.yaml` if this capability is wanted. It is empty/absent by default. For example:

```yaml
templates:
  household-restart:
    name: Restart one household service
    role: adult
    allowed_hosts: [REPLACE_WITH_ENROLLED_HOST_ID]
    maximum_seconds: 1800
    operations: [systemd.restart]
    constraints:
      service_names: [example.service]
```

Only an owner token with `serverhub:policies` may activate this template. The caller can select only an explicitly listed host and a bounded duration. Operations, constraints and the target role come from the protected template. Production approval cannot be activated by this tool. The broker's independent allowlist still applies.

## Existing ServerHub Control MCP

Its credentials/OAuth/configuration are not modified. The optional legacy adapter can perform the documented initialize/tools-list handshake and return metadata. It does not fabricate names for unknown existing tools or forward unrestricted commands. Existing tool compatibility requires the actual external server's schema and an explicitly implemented adapter; it is not implied by both products using MCP.
