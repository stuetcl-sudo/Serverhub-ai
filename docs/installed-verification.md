# Verify an existing installation

The destructive fresh-runner integration scripts are **not** an acceptance command
for an existing VM. Use the installed verifier below after a reviewed upgrade.
It needs no root privileges, service environment files or database password.

```sh
/opt/serverhub/current/venv/bin/python -m serverhub.ops.verify_install \
  --url http://127.0.0.1:9080 --username dennis
```

The owner password is prompted without echo. It is never a command-line argument,
environment variable or report field. A newly created login session is revoked at
the end. Existing sessions supplied with `--token-file` are retained; that file
must be an owned regular file with private permissions (0600). Symlinks and
group/world-readable token files are rejected.

If the API uses TLS, supply its exact canonical origin and a trusted private CA:

```sh
/opt/serverhub/current/venv/bin/python -m serverhub.ops.verify_install \
  --url https://YOUR-CONTROLLER:9080 --ca-file /path/to/public-ca.pem \
  --username dennis --probe-model default --host ENROLLED_HOST_ID
```

Remote HTTP, credentials in URLs, redirects and disabling certificate verification
are not supported. Use the existing [persistent TLS access](persistent-access.md)
configuration. Do not expose an administrative endpoint merely to make a test
environment reachable.

The default command checks controller health, anonymous inventory denial (401),
public HTML and referenced JS/CSS, authenticated owner access, and the controller's
database/migration/worker/model/file/sandbox/policy/node diagnostics. It never
prints bearer tokens, raw API error bodies, provider configuration or inventory.
Diagnostic failures include a next step; no permissions are broadened or repaired.

`--probe-model ROUTE` explicitly invokes the existing harmless structured-tool
probe against that configured provider. The existing 16,000-token/$0.10 probe
budget and 60-second provider timeout still apply. Paid providers may incur that
bounded charge. The probe does not save or change the model configuration, and
passing it is not proof that a complex AI task will complete.

`--host ID` explicitly submits one durable `operation` job whose only action is
`inventory.refresh`, with no model token/API budget and one execution attempt.
The worker, enrolled agent and normal authorization still execute the job. It
cannot restart a service or run a model-selected operation. An unavailable agent,
approval block, collection gap or failed result is reported without claiming
verified success. A local wait timeout retains the job ID; it does not cancel or
hide its persistent receipt. Inspect it in Active jobs. `--timeout` controls the
wait and task time limit, 1–3600 seconds, default 180.

Login/logout, model requests, job/audit records and inventory updates are expected
side effects of the explicit options. Managed service/configuration changes,
installation, rollback, backups and policy changes are never performed.

JSON report and exit codes:

- `0`: all requested checks passed.
- `1`: a failed or invalid response, unavailable endpoint, unauthorized access or
  timeout; use the named check and its remediation.
- `2`: checks ran but diagnostics or inventory collectors have warnings/gaps.
  This is partial evidence, not a clean installation acceptance.

This is an installed-system check, not a production-readiness certification or a
database restore drill. Backups, application-specific acceptance, real reboot,
intended storage mounts and off-host audit retention require separate validation.

## Current private-VM blocker

The development environment tested direct TCP to `192.168.122.10:22` and `:9080`
on 2026-10-23; both failed with OS error 101, **Network is unreachable**.
No private test VM upgrade or verification is claimed. Its earlier installed
version cannot be inferred from the current repository. GitHub access and
disposable Ubuntu CI remain available; production was not changed.

For an old checkout, first fetch/check out the reviewed PR commit, then use
`./scripts/install-ubuntu.sh --build-only` and `sudo ./scripts/repair-install.sh`
as described in [the upgrade guide](upgrade.md). The reviewed repair backs up
configuration/database and arms independent recovery. Run the verifier after it;
never run `scripts/test-native-ubuntu.py` on that existing VM.
