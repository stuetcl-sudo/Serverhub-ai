# AI token budgeting and execution fix

This update to PR #4 targets `overhaul/stability-autonomy`. It does not deploy,
merge or expand authorization. The earlier byte-estimator correction is retained
and completed with provider formatting, retry reservation, durable request debit
and attempt-safe preflight handling.

## Measured reproduction

The original private user prompt is not present in this repository/session, so
its exact original wire payload cannot be reconstructed. A reproduction with the
shipped 34-tool schema, actual infrastructure specialist instructions and a short
CPU/memory/disk diagnostic prompt produces:

| Measurement | Count |
| --- | ---: |
| Legacy double-serialized input bytes counted as tokens | 18,003 |
| Legacy fixed output reservation | 2,048 |
| Legacy admission total, against a 20,000-token job | **20,051 — rejected before HTTP** |
| Normalized input JSON UTF-8 bytes, counted once | 15,179 |
| New token estimate including framing and uncertainty margin | 6,128 |
| New output reservation | 2,048 |
| New admission total | **8,176 — admitted** |
| Actual serialized native HTTP request body bytes | 15,262 |
| Separately configured context in reproduction | 16,384 |

The byte-based count plus output reserve explains a failure with zero usage and
no tool calls. Changing policy grants or silently enlarging the job's budget
would not fix its cause. Actual sizes vary with prompt, history and tool versions;
job events now expose numeric input/request byte sizes without prompt content.

The estimator uses ASCII characters/3, non-ASCII UTF-8 bytes, a **20% uncertainty
margin**, and 12 framing units/message plus 32. This is a conservative heuristic
for ordinary BPE text/code/JSON, not Qwen's exact tokenizer or a universal upper
bound. High-entropy text, different model templates and tokenizer behavior can
exceed it. Provider-reported usage replaces it. Provider-side limits remain
necessary for a hard upstream billing guarantee. No tokenizer/model download or
new runtime dependency is required.

## Behavior

- Ollama history is converted to its actual native format before estimation;
  OpenAI-compatible history retains its own representation. Schemas are counted
  once. JSON request byte diagnostics remain distinct from estimated tokens.
- Context applies to one request; remaining job budget covers cumulative requests;
  output reserve is separately bounded by both. Even rejected small budgets never
  reserve more than remains. At least 32 output tokens must fit before any HTTP.
- Every retry recalculates its output cap. Ollama uses `num_predict`/`num_ctx` and
  compatible providers use their configured completion-limit parameter.
- Valid reported counts are charged; missing/invalid counts, transport ambiguity,
  HTTP rejections and malformed responses retain input/output reserves. Invalid
  values cannot be coerced to smaller integers or overflow persistent counters.
- A request reservation/debit commits **before** network dispatch. Usage settlement
  and clearing commit together. Restart retains unknown request charges exactly
  once; cancellation records known usage; stale workers cannot refund newer work.
- Pure local preflight failure pauses the job without using an execution attempt,
  retaining actionable numeric context/output/remaining-budget diagnostics. No
  busy automatic retry loop occurs. Correct configuration and resume the same
  job, or submit a separately authorized larger-budget job. Work already attempted
  and unknown provider charges are not refunded. Cached result replay is not new work.
- Policy checks, broker allowlists, audit chain, job cancellation/lease handling,
  rollback controls and approved budgets remain in force. No unrestricted command
  endpoint or production capability is added.

## Verification

Run with an explicitly disposable PostgreSQL test database, as configured in CI:

```sh
python -m pip install -e '.[test]'
python -m pytest --junitxml=test-results/backend.xml
python -m ruff check src/serverhub tests/test_budget_execution.py scripts/test-native-ubuntu.py
npm --prefix frontend ci
npm --prefix frontend run build
npm --prefix frontend test -- --run
```

Targeted coverage:

```sh
python -m pytest tests/test_ai_providers.py tests/test_ai_orchestrator.py tests/test_budget_execution.py -q
```

The tests exercise native qwen2.5:3b-style tool calls, full real tool schemas,
provider-specific history/JSON byte counts, Unicode, small/exhausted budgets,
context exhaustion, repeated requests, adaptive retry caps, failed HTTP/network
requests, malformed/unreported usage, invalid/overflow counters, pure admission
pause/refund, cached tool replay, actual tool activity, same-job correction/resume,
a verified read-only tool lifecycle, PostgreSQL/forked-worker persistence, request
interruption, cancellation and stale-worker refund rejection.

The native Ubuntu CI scenario now intentionally configures too-small model
context, verifies `paused / attempts=0 / used=0`, corrects context via the owner
API, resumes the same **20,000-token** job, and requires a verified successful
read-only outcome on its Ollama API fixture. It also retains unauthorized SSH
restart rejection and native upgrade/failure rollback checks.

Local final run: **183 passed, 1 skipped** in 15.22 seconds against disposable
PostgreSQL 16.2. The one skip is the unconfigured real Ollama probe. Frontend:
**28 passed** and TypeScript/Vite production build passed. Ruff passed. The actual
API/worker/enrolled-node command lifecycle, audit chain and desktop/mobile browser
smoke passed. Native systemd install/resume/upgrade and the new preflight/resume
scenario are verified separately by GitHub's `native-ubuntu` check; see the updated
PR body and CI artifacts for exact revision/result.
Local verification includes disposable PostgreSQL 16.2, real API/worker/node
startup and persistent command lifecycle, frontend build/tests and browser smoke.
A real Ollama endpoint/model is **not configured in this execution environment**.
The real-provider test remains an explicit skip: neither the fixtures nor the
verified mocked read-only AI lifecycle establish real qwen2.5:3b behavior.

Existing optional live readiness probe:

```sh
SERVERHUB_TEST_OLLAMA_URL=http://192.168.1.50:11434 \
SERVERHUB_TEST_OLLAMA_MODEL=qwen2.5:3b \
SERVERHUB_TEST_OLLAMA_PRIVATE_HTTP=true \
python -m pytest tests/test_overhaul.py -k optional_real -q
```

Use only an explicitly authorized test endpoint. This existing optional probe
checks a harmless nonce tool call, not a complete production job; real-model
end-to-end execution remains unverified here.

## Install/upgrade on a test VM

Review PR #4, check out its approved revision and follow
[installation.md](installation.md) or the root-reviewed [upgrade.md](upgrade.md)
workflow. Protected worker/provider code changes its trust digest, so use the
reviewed maintenance path rather than allowing the worker to change its own trust
anchors. No database migration or automatic grant expansion is required. Configure
a context that fits the actual model and inference-host RAM/VRAM. Do not apply
this update to production without the owner's separate deployment authorization.
