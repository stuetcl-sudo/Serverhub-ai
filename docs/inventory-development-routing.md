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

## Follow-up: validation precedes journaling

Argument validation now runs before `in_flight`/`mutating` journaling, before the
"AI tool request" job event and before any authorization or dispatch. An invalid
call therefore writes no in-flight marker, logs only operation, specialist and
error field paths (never rejected values) and cannot trigger "interrupted external
mutation needs owner reconciliation" after a crash. A stale in-flight marker for a
call whose arguments are invalid is discarded only when it exactly matches the
operation, arguments and call ID and contains no checkpoint, failure or other
dispatch evidence. A mismatched or enriched marker remains blocked for owner
reconciliation. This legacy recovery assumes the unchanged argument schemas from
PR #9; schema migrations must not treat newly invalid former writes as unexecuted.
Valid calls still journal before dispatch, authorize before execution, and retain
durable checkpoints, idempotency keys and interrupted-mutation reconciliation.

Repeated identical invalid calls remain subject to job step and token budgets: the second sets
`requires_changed_strategy` and omits the schema to save tokens. An invalid call is
never dispatched, so it never aborts the job even for a mutating tool.

The development specialist now states its tool coverage (development.list,
development.submit, task.verify, agent.specialize) and tells the model to call
`agent.specialize` for host work instead of declaring it unsupported. Delegation
never changes permissions; the same `job.submit` check and principal apply.

Follow-up validation (2026-10-24): 59 targeted orchestrator/provider tests passed;
full local suite: 409 passed, 15 skipped, one Starlette deprecation warning.
Ruff on the changed Python files and git diff whitespace checks passed.
Skipped tests require disposable PostgreSQL, Unix sockets denied by this local
sandbox, or a configured real Ollama endpoint. These results are not a real-model
or native Ubuntu installation verification. Additional negative cases cover
mismatched/enriched recovery markers, denied specialization, denied valid writes,
and a crash after an authorized write checkpoint without duplicate dispatch.
The attached finish patch applied cleanly to f9fb248; recovery guards and tests
were strengthened during review. No production configuration is changed.

## Native Jarvis follow-up

Validation run 40099244567 failed in the real qwen2.5:3b Jarvis pilot:
the model successfully read and committed the requested version change, but after
the intentional worker restart it attempted the same malformed patch three times
instead of checking its already committed work. The stall guard correctly returned
partial, not success. Backend, frontend, dependency scans, migrations, installation,
Docker backup/restore and network isolation checks in that run passed.

The development loop now durably schedules the existing run_checks tool for each
changed source HEAD before requesting another model decision. It recovers from the
Git HEAD plus existing inspection/checkpoint state, including older checkpoints.
A failed check is recorded once per HEAD so this does not create an automatic
retry loop; changed source permits fresh verification. All configured commands
still use project authorization and the sandbox. Permission denial is propagated,
never converted into a successful receipt. Completion and staging gates remain
unchanged; a successful check does not itself mark the whole job complete.
Tool availability for further authorized multi-file work is preserved.

Regression coverage includes interruption after the committed edit receipt,
verification before the next provider request, and revocation of test permission
while the worker is interrupted. The latter must wait for approval without running
a new command. Local provider/sandbox fixtures are not real-model evidence.
