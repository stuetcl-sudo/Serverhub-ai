# ServerHub administration console

Node 22.12+ or 24+ is required for development and test tooling.

React 19 + TypeScript, built to static assets with Vite. Production pages consume
same-origin `/api` endpoints and use an HttpOnly controller session cookie. The
console does not save bearer tokens or credentials in browser storage. All access
and operation authorization remains enforced by the backend.

```bash
npm ci
npm run test
npm run build
npm run dev
```

The development proxy expects the native API on `127.0.0.1:9080`. The production
native installer serves `dist/` through the FastAPI controller behind trusted TLS.
No Node runtime is required to serve the production bundle. Use `npm run format`
when editing source.

Included views: infrastructure overview; interactive topology and evidence;
host inventory and individual enrollment; Docker; network/ports; integration
metadata and application catalog; configured project workflows; chat and persisted
jobs; findings; resource gauges and recorded memory history; incidents; operational
memory; policy grants; protected backup status; model provider descriptors; user
administration; and audit records. Resource history is never synthesized. Linux
load per core is labeled separately from CPU utilization.

Model and integration trust settings are intentionally inspected through the UI
and configured using the protected native administrator procedure. The worker and
web console cannot edit those trust files. Backup creation and restore run in the
independent protected maintenance service; the UI shows its published status.

The Vitest suite mocks API boundaries only in test files. It exercises real UI
forms, authorization rejection, cookie request options, exact job payloads, policy
revocation, emergency-stop reasons, one-time enrollment, event-session expiry,
recorded monitoring, and native backup publication. Browser layout/visual QA still
requires a real Chromium/Firefox installation; no browser binary is bundled.
