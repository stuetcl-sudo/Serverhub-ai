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
