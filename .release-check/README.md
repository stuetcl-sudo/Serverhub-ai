# Disposable Linux validation

Run from the repository root:

```sh
docker compose -f .release-check/compose.yaml build tests
docker compose -f .release-check/compose.yaml up --abort-on-container-exit --exit-code-from tests
docker compose -f .release-check/compose.yaml down
```

This is a test environment, not a production deployment. It has no host mounts,
Docker socket, published ports or privileged containers. Its network is internal.
PostgreSQL data is temporary. The test container shares only the disposable
PostgreSQL container's network namespace, allowing the restore drill's explicit
loopback check. PostgreSQL 16 client tools are copied from the official 16 image
so backup/restore is not tested using a newer incompatible major-version client.
Browser tests use local HTTPS and intercepted external callback fixtures.
The fixed password belongs only to this disposable test database.

The container is root only inside its own default Docker isolation, to exercise
root-owned fixture checks. It cannot prove real systemd sandboxing or native host
release/watchdog integration. Those checks require a disposable Ubuntu VM.
