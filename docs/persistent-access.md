# Persistent authenticated access

The default remains loopback HTTP behind an explicitly configured HTTPS reverse
proxy; see `packaging/config/nginx.conf.example`. This is a native systemd API;
there is no requirement for a terminal-held SSH tunnel. Existing proxy/firewall/
SSH configuration is never changed by installation.

A controller may instead serve HTTPS directly. Provision a certificate from your
trusted public or private PKI with the exact DNS/IP Subject Alternative Name.
Install the certificate chain and private key in a root-owned directory searchable
by `serverhub-api`, with the key root:serverhub-api 0640 and directory 0750.
Copy and adapt `packaging/config/access.env.example` to
`/etc/serverhub/access.env`, also root:serverhub-api 0640. Use the **test VM's own
address**, not the production host address. The file selects bind/port, canonical
public origin, TLS files and an independently certificate-verified health URL.
For a private PKI, supply its CA certificate through `SERVERHUB_HEALTH_CA`; never
turn off certificate validation. The example's private addresses are examples,
not endpoints this release has configured.

After explicit operator review, `sudo systemctl restart serverhub-ai-api` loads the
optional access environment. The installer enables this systemd service, so it
survives reboot. Certificate renewal must preserve the group/read permissions and
restart the API; private-PKI enrollment/renewal is operator-managed. No HTTP
redirect listener or public Ollama listener is created. A non-loopback production
HTTP listener is rejected at startup. Reverse-proxy deployments keep loopback
binding; untrusted forwarded headers remain disabled. Authenticated APIs still
require user/node identities, and cookie writes still require an allowed Origin.
Only the UI assets and normal authentication/discovery endpoints are public.

Run the certificate-aware health command with the API environment loaded, or
`serverhub health --url https://CONTROLLER:9080 --ca-file /path/to/ca.pem`.
Native upgrade and release activation use the protected health URL/CA from the
API/access environment, rather than assuming loopback plaintext.

The canonical public origin is always allowed for assets and cookie requests,
even if a legacy explicit origins list retains the old domain. Foreign Origins
remain rejected. Missing assets and API routes return 404 rather than SPA HTML.
Filesystem asset validation and installed-service health checks remain mandatory.
