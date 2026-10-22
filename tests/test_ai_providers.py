import json

import httpx
import pytest

from serverhub.ai.providers import BudgetExceeded, ChatProvider, ProviderConfig, ProviderError, UsageBudget


def config(**kw):
    return ProviderConfig(kind="openai", base_url="https://model.example/v1", model="test",
                          input_cost_per_million=1, output_cost_per_million=2,
                          max_output_tokens=64, **kw)


def test_openai_tools_and_verified_usage():
    def handle(request):
        assert request.url.path == "/v1/chat/completions"
        body = json.loads(request.content)
        assert body["tools"][0]["function"]["name"] == "status"
        return httpx.Response(200, json={"choices": [{"message": {"content": "", "tool_calls": [
            {"id": "call1", "function": {"name": "status", "arguments": '{"id":1}'}}]}}],
            "usage": {"prompt_tokens": 12, "completion_tokens": 4}})
    budget = UsageBudget(10000, 1)
    result = ChatProvider(config(), transport=httpx.MockTransport(handle)).complete(
        [{"role": "user", "content": "status"}], [{"type": "function", "function": {"name": "status"}}], budget)
    assert result.tool_calls[0].arguments == {"id": 1}
    assert result.usage_verified and budget.tokens_used == 16
    assert budget.cost_used == pytest.approx(.000020)


def test_ollama_native_tool_history_and_unreported_usage():
    def handle(request):
        body = json.loads(request.content)
        assert request.url.path == "/api/chat" and body["stream"] is False
        assert body["messages"][0]["tool_calls"][0]["function"]["arguments"] == {"x": 1}
        return httpx.Response(200, json={"message": {"content": "done"}})
    cfg = ProviderConfig(kind="ollama", base_url="http://127.0.0.1:11434", model="local", max_output_tokens=64)
    result = ChatProvider(cfg, transport=httpx.MockTransport(handle)).complete([
        {"role": "assistant", "content": None, "tool_calls": [{"function": {"name": "status", "arguments": '{"x":1}'}}]}], [], UsageBudget(10000, 0))
    assert not result.usage_verified and result.output_tokens == 64


def test_transport_retries_reserve_and_charge_uncertain_billing():
    attempts = []
    def handle(request):
        attempts.append(1)
        raise httpx.ReadTimeout("request with secret must not escape", request=request)
    budget = UsageBudget(10000, 1)
    with pytest.raises(ProviderError, match="transport failed") as error:
        ChatProvider(config(max_retries=2), transport=httpx.MockTransport(handle), sleep=lambda _: None).complete(
            [{"role": "user", "content": "hi"}], [], budget)
    assert len(attempts) == 3 and budget.tokens_used > 3 * 64
    assert "secret" not in str(error.value)


def test_pricing_and_tool_schema_budget_checked_before_network():
    invoked = []
    transport = httpx.MockTransport(lambda r: invoked.append(r))
    with pytest.raises(BudgetExceeded):
        ChatProvider(config(), transport=transport).complete([], [{"schema": "x" * 5000}], UsageBudget(100, 1))
    with pytest.raises(BudgetExceeded, match="pricing"):
        ChatProvider(ProviderConfig(base_url="https://model.example", model="paid"), transport=transport).complete([], [], UsageBudget(10000, 1))
    assert not invoked


def test_malformed_tools_rejected_and_usage_charged():
    budget = UsageBudget(10000, 1)
    malformed = {"choices": [{"message": {"tool_calls": [{"function": {"name": "bad", "arguments": '[]'}}]}}]}
    with pytest.raises(ProviderError, match="invalid chat response"):
        ChatProvider(config(), transport=httpx.MockTransport(lambda r: httpx.Response(200, json=malformed))).complete([], [], budget)
    assert budget.tokens_used >= 64


def test_no_remote_plain_http_or_inline_credentials():
    with pytest.raises(ValueError):
        ProviderConfig(base_url="http://remote.example", model="x")
    with pytest.raises(ValueError):
        ProviderConfig(base_url="https://username:password@remote.example", model="x")


def test_server_error_after_possible_generation_charged_before_retry():
    attempts = []
    def handle(request):
        attempts.append(1)
        if len(attempts) == 1:
            return httpx.Response(503, json={"error": "unknown billing outcome"})
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}],
                                         "usage": {"prompt_tokens": 2, "completion_tokens": 1}})
    budget = UsageBudget(10000, 1)
    result = ChatProvider(config(), transport=httpx.MockTransport(handle), sleep=lambda _: None).complete([], [], budget)
    assert result.content == "ok" and len(attempts) == 2
    assert budget.tokens_used > 64 + 3


def test_qwen_20k_real_tool_schemas_do_not_count_utf8_bytes_as_tokens():
    from serverhub.ai.orchestrator import tool_schemas
    from serverhub.ai.providers import estimate_prompt
    tools = tool_schemas()
    messages = [{"role": "user", "content": "Inspect Docker, RAM and systemd. " * 130}]
    legacy = len(json.dumps(messages + [{"role": "system", "content": json.dumps(tools, ensure_ascii=False)}], ensure_ascii=False).encode())
    assert legacy + 2048 > 20000
    calls = []
    def handle(request):
        body = json.loads(request.content)
        calls.append(body)
        assert body["model"] == "qwen2.5:3b"
        assert body["options"] == {"num_predict": 2048, "num_ctx": 16384}
        return httpx.Response(200, json={"message": {"content": "", "tool_calls": [
            {"function": {"name": "inventory__query", "arguments": {"section": "containers"}}}]},
            "prompt_eval_count": 4500, "eval_count": 25})
    cfg = ProviderConfig(kind="ollama", model="qwen2.5:3b", base_url="http://127.0.0.1:11434", context_limit=16384)
    budget = UsageBudget(20000, 0)
    result = ChatProvider(cfg, transport=httpx.MockTransport(handle)).complete(messages, tools, budget)
    assert len(calls) == 1 and result.tool_calls[0].name == "inventory__query"
    assert budget.tokens_used == 4525  # reported counts replace the estimate
    assert result.accounting["actual_input_tokens"] == 4500
    assert result.accounting["estimated_input_tokens"] == estimate_prompt(messages, tools)["estimated_input_tokens"]
    assert result.accounting["serialized_utf8_bytes"] < legacy


def test_output_reserve_shrinks_without_dropping_conversation():
    from serverhub.ai.providers import estimate_prompt
    messages = [{"role": "user", "content": "hello"}]
    estimated = estimate_prompt(messages)["estimated_input_tokens"]
    bodies = []
    def handle(request):
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json={"message": {"content": "ok"}, "prompt_eval_count": 10, "eval_count": 2})
    cfg = ProviderConfig(kind="ollama", base_url="http://localhost:11434", model="local")
    ChatProvider(cfg, transport=httpx.MockTransport(handle)).complete(messages, [], UsageBudget(estimated + 100, 0))
    assert bodies[0]["options"]["num_predict"] == 100
    assert bodies[0]["messages"] == messages


@pytest.mark.parametrize("context,budget,match", [(1024, 20000, "context limit"), (32768, 1000, "Job token budget")])
def test_genuine_overbudget_stops_before_request_with_actionable_safe_numbers(context, budget, match):
    cfg = ProviderConfig(kind="ollama", base_url="http://localhost:11434", model="qwen2.5:3b", context_limit=context)
    invoked = []
    with pytest.raises(BudgetExceeded, match=match) as error:
        ChatProvider(cfg, transport=httpx.MockTransport(lambda r: invoked.append(r))).complete(
            [{"role": "user", "content": "PRIVATE-PROMPT " * 1000}], [], UsageBudget(budget, 0))
    assert not invoked and "PRIVATE-PROMPT" not in str(error.value)
    assert error.value.diagnostics["estimated_input_tokens"] > 1000
    assert "output reserve=" in str(error.value)


def test_unicode_estimation_does_not_assume_four_characters_per_token():
    from serverhub.ai.providers import estimate_prompt
    ascii_prompt = estimate_prompt([{"role": "user", "content": "a" * 100}])
    unicode_prompt = estimate_prompt([{"role": "user", "content": "漢😀" * 50}])
    assert unicode_prompt["estimated_input_tokens"] > ascii_prompt["estimated_input_tokens"] * 2
    assert unicode_prompt["is_exact"] is False


def test_missing_usage_charges_estimated_input_and_entire_reserved_output():
    cfg = ProviderConfig(kind="ollama", model="local", base_url="http://localhost:11434", max_output_tokens=64)
    budget = UsageBudget(20000, 0)
    result = ChatProvider(cfg, transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"message": {"content": "ok"}}))).complete([], [], budget)
    assert not result.usage_verified
    assert result.accounting["actual_input_tokens"] is None
    assert budget.tokens_used == result.accounting["estimated_input_tokens"] + 64


def test_provider_underestimate_charged_and_stops_future_requests():
    budget = UsageBudget(20000, 0)
    cfg = ProviderConfig(kind="ollama", base_url="http://localhost:11434", model="local")
    calls = []
    def handle(request):
        calls.append(request)
        return httpx.Response(200, json={"message": {"content": "ok"}, "prompt_eval_count": 19990, "eval_count": 20})
    provider = ChatProvider(cfg, transport=httpx.MockTransport(handle))
    with pytest.raises(BudgetExceeded, match="Provider billed usage"):
        provider.complete([], [], budget)
    assert budget.tokens_used == 20010
    with pytest.raises(BudgetExceeded, match="Job token budget"):
        provider.complete([], [], budget)
    assert len(calls) == 1
