# ServerHub AI OS self-development — owner enrollment (not applied)

This procedure registers **ServerHub AI OS as a development project** so its
autonomous worker can propose and test changes to its own *Git repository*.
It does **not** grant the worker access to installed binaries, policy files,
root configuration, production databases, credentials, or production deployment.

## Prerequisites

1. Review and validate the isolated Python virtualenv bootstrap in draft PR #18,
   including its native Ubuntu CI. The project example requires that behavior.
2. Review the independent acceptance check and **copy it outside the repository**
   to root-owned `/etc/serverhub/project-checks/serverhub-ai/serverhub-ai-check.py`.
   Ensure the directory and all ancestors are root-owned and not group/world writable.
3. Review `docs/examples/serverhub-ai-project.yaml`. Its `base_ref` is an
   owner-selected development candidate branch, not an immutable signed release.
   Verify the branch and package dependency trust before enrollment.
4. Preserve the current `jarvis-os` registration. Back up the protected
   `/etc/serverhub/projects.yaml` and **append the single project entry** from
   the example's `projects` array. Do not replace the whole file with the
   example, and do not accept project definitions from chat or generated patches.
5. Use the installed interpreter to validate the final file via
   `serverhub.development.config.load_projects()`. Confirm the project list
   contains both `jarvis-os` and `serverhub-ai`. A malformed or unsafe
   configuration must fail closed. Do not alter Control services.
6. Grant the authenticated owner identity a bounded controller-only
   `serverhub-ai` development profile (for example 2 hours). Enable dependency
   network only for the pinned PyPI hosts when required. Leave publication,
   staging, host administration, and production release **disabled**.
7. Through MCP `list_projects`, confirm `serverhub-ai` appears. Submit a
   **no-patch** validation job first, monitor its complete command results, then
   submit a small autonomous source-edit job and inspect its verified candidate.
   Revoke the temporary grant after testing.

The example runs a deliberately **bounded subset** of development tests plus
independent static safety checks. It is **not** a production-ready CI substitute.
Before allowing automated draft PR publication, add comprehensive external
acceptance checks, configure a separately protected fine-grained GitHub credential,
restrict publication paths, and explicitly approve the publication policy.

Production deployment, schema migrations on the installed database, merges,
updates to trust anchors, SSH/firewall changes and direct host commands are never
part of this development registration. Those remain separate reviewed releases.
