# Inventory/development routing regression

`dependencies` is not a host inventory section and is intentionally not added as
an alias. Inventory queries inspect authenticated node reports, not repository
files. The previous regex-only schema, infrastructure instruction mentioning
"dependencies", and inventory schemas shared with the development specialist
made the invalid category plausible to a small model. The reported model's exact
reason cannot be proved without its saved request/response.

Inventory section is now a JSON-schema enum. A project-scoped autonomous job
defaults to the development specialist unless an explicit specialist is selected.
That specialist advertises development discovery/submission and verification,
not host inventory. Existing Development UI jobs already route to
`development_autonomous` (or deterministic `development` without a prompt);
that dedicated workspace engine is retained. Generic host chat is not silently
converted based on guessed prompt wording. Instructions direct repository work
through development.list and development.submit and their existing scoped grants.

Before execution, invalid arguments produce a durable tool observation containing
field paths, error codes and the expected schema. Rejected values are not echoed
in the correction response. The model can correct the next call within existing
step/token budgets. Identical-failure suppression remains bounded. Validation does
not execute a tool, authorize it, or prove task completion. Policy denials and
ambiguous interrupted mutations retain their existing behavior; downstream runtime
validation errors are not mislabeled as safe pre-execution failures.

Regression coverage checks the original invalid section, subsequent model
continuation, enum schema, project routing, development tool selection and invalid
mutation arguments without dispatch. Existing policy-denial and restart tests
remain applicable. Real Ollama behavior requires separate integration verification;
mocked provider responses demonstrate control flow, not model reliability.
