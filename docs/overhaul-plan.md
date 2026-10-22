# Stability and autonomy overhaul

Priority order: reproduce native installation failures; preserve the privilege boundary while adding owner-managed model settings; make denials and durable execution actionable; expose setup and diagnostics; run regressions and isolated release validation.

Confirmed causes in baseline 69de5c1:

- `Installer.apply` refuses any existing API/node configuration and generates new credentials on every new attempt. No persistent install journal exists.
- `runuser` inherits the invoking directory. Alembic looks at `Path.cwd()` before the absolute release path, and source-relative Python paths remain dependent on that directory.
- Worker `InaccessiblePaths` lists optional Docker/broker paths as mandatory. Mount namespace setup can fail before Python runs.
- All requests with an Origin differing from the configured public URL are rejected, including same-origin loopback asset requests. This is an origin check, separate from filesystem readability.
- Empty `routes` is reported as configured whenever the YAML file exists. The shipped commented provider example uses a routing shape unsupported by the loader. The UI cannot write or test settings.
- The installer ships models.yaml mode 0644; the reported unreadable file is not explained by that mode alone. Ancestors, actual ownership/mode, manual edits and sandbox visibility require diagnostics rather than an invented diagnosis.
- Private HTTP is a broad boolean with no private-address restriction. No discovery/readiness workflow exists.
- `diagnostics.network` and `inventory.refresh` are omitted from the read classifier although the node identifies them as reads.
- Policy errors contain no operation, target or candidate mismatch. AI jobs with `completed=false` are still marked succeeded; no durable idle-worker heartbeat exists.

Implementation and verification details are recorded in `overhaul-report.md` after the changes. Fresh Ubuntu VM acceptance remains separate from simulated filesystem staging and unit tests.
