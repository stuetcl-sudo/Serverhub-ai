# Model accounting and 20k-token jobs

Issue #2 exposed a pre-request failure: `UsageBudget.preflight` treated the UTF-8
byte length of JSON as a token count. It also JSON-encoded tool schemas twice and
reserved the entire output maximum even when a smaller answer could fit.
This is independent of permission policy or Ollama network access.

The provider now counts compact messages and tool schemas once. Without a local
model tokenizer it estimates ASCII text/code/JSON at three characters per token,
counts non-ASCII UTF-8 bytes separately, adds 20% headroom and chat framing. This
is an explicitly labelled estimate, **not exact Qwen tokenization or a guaranteed
upper bound**. High-entropy text, unusual tokenizers and model chat templates can
exceed it. No tokenizer or model is downloaded automatically. Qwen documents
byte-level BPE; a UTF-8 byte is not inherently a token.

Preflight requires room for estimated input plus at least 32 output tokens. A
rejection reserves only the remaining allowance (possibly zero), never an
impossible minimum. The output allowance is reduced to the remaining job and configured context bounds when
necessary; input history is never silently removed. The configured context is
sent as Ollama `options.num_ctx`; it must fit the actual model and host memory.
Increasing context increases memory usage. This is not GPU admission control.

The job budget covers **cumulative input and output over all requests**, including
repeated conversation history, rather than the size of just one conversation.
`context_limit` bounds one request. Reaching either limit prevents another request;
it does not grant a larger budget. API cost reserves remain independent.

Ollama's `prompt_eval_count` and `eval_count`, or OpenAI-compatible reported usage,
replace the estimate on a valid response. Missing usage, uncertain transport/5xx
outcomes, all HTTP rejections and malformed responses charge estimated input plus
reserved output.
Retries are rechecked against the remaining budget. If reported usage exceeds
the reserve and job budget, it is charged and execution stops. An estimate cannot
guarantee a hard upstream billing limit; use provider-side limits for that.

Job events show numeric estimated input, generation reserve, measured input/output,
context and job limits, serialized byte size and usage verification status. These
use non-credential field names so the existing secret redactor preserves the
numbers. Preflight errors include numeric limits and remediation, without prompts,
URLs, credentials or tool arguments.

## Reproduce the regression

```sh
python -m pytest tests/test_ai_providers.py tests/test_ai_orchestrator.py -q
```

The Qwen 2.5 3B regression uses the complete real ServerHub tool schema, a prompt
whose legacy byte count plus output reserve exceeded 20,000, and mocked native
Ollama tool-call/usage responses. It verifies admission, tool parsing, `num_ctx`,
actual accounting, output reservation reduction, Unicode headroom, genuine budget
and context rejection, uncertain usage and actual overrun stopping. It does not
claim a real Qwen server was available.

The optional existing live readiness test is explicitly opt-in:

```sh
SERVERHUB_TEST_OLLAMA_URL=http://192.168.1.50:11434 \
SERVERHUB_TEST_OLLAMA_MODEL=qwen2.5:3b \
SERVERHUB_TEST_OLLAMA_PRIVATE_HTTP=true \
python -m pytest tests/test_overhaul.py -k optional_real -q
```

Use an already installed model on an isolated, authorized endpoint; the probe
only tests a harmless nonce tool call and executes no infrastructure tools.

References: [Ollama chat response usage](https://docs.ollama.com/api/chat),
[Ollama context memory](https://docs.ollama.com/context-length),
[Qwen tokenization](https://qwen.readthedocs.io/en/latest/getting_started/concepts.html#tokens-tokenization).


## Provider formatting, durable debit and execution attempts

The current estimator normalizes Ollama tool history before counting: native
argument objects, empty assistant content and `tool_name`, without OpenAI-only
IDs or double-encoded function arguments. OpenAI-compatible history keeps its
own format. Tools occur once in the normalized input. Job accounting events also
record the actual serialized HTTP JSON body byte length separately from estimated
tokens; byte size is a diagnostic, never the token budget.

Every retry recomputes output allowance from the remaining cumulative budget.
Malformed, negative, fractional, boolean, string, null or impossible reported
usage counts cannot be coerced into a smaller charge. Invalid/missing usage and
failed requests retain the conservative reserve. Provider usage counts above the
platform's maximum supported two-million-token request bound are invalid, avoiding
integer overflow in durable job counters.

Before HTTP dispatch, the worker atomically saves a content-free reservation and
debits it from durable job usage. A valid response atomically replaces that debit
with actual counters and clears the reservation. Uncertain failures retain the
reserve; a restarted worker clears its marker without charging twice or refunding
an unknown request. Cancellation can still record a known result. An old lease
owner cannot refund a request after another worker takes ownership. These changes
use existing jobs/checkpoint JSON and require no schema or privilege expansion.

A budget/context/pricing rejection before any request or newly executed tool in
that worker attempt pauses the job with `failure_class=preflight`, structured
numeric diagnostics and no consumed execution attempt. It is not automatically
requeued. Correct model configuration/task scope, then resume; increasing an
immutable job budget requires a separately authorized new job. Previous actual
requests, uncertain debit and previously spent attempts remain charged. Replaying
a cached tool result does not count as a newly executed tool. A preflight rejection
after actual activity in the same attempt remains a normal budget failure.

See [token-budget-fix.md](token-budget-fix.md) for the measured 20k reproduction,
regression commands and current verification limitations.
