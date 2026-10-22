"""OpenAI-compatible and Ollama chat APIs with bounded, explicit accounting.

No SDK or provider-specific agent runtime is required. Endpoint/model/pricing
configuration is an operator-owned trust boundary, never model output.
"""
from __future__ import annotations

import json
import os
import stat
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

import httpx
import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ProviderError(RuntimeError):
    """A sanitized, classified provider failure."""
    def __init__(self, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable


class BudgetExceeded(RuntimeError):
    pass


def validate_url(value: str, *, allow_http: bool = False) -> str:
    parsed = urlsplit(value)
    if (parsed.scheme not in ("https", "http") or not parsed.hostname or
            parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("A fixed HTTP(S) URL without credentials, query or fragment is required")
    if parsed.scheme == "http" and not (allow_http or parsed.hostname in ("localhost", "127.0.0.1", "::1")):
        raise ValueError("Non-loopback endpoints require HTTPS or explicit allow_insecure_http")
    return value.rstrip("/")


def read_operator_yaml(path: str | Path) -> dict:
    path = Path(path)
    if not path.is_file():
        return {}
    if path.is_symlink():
        raise ValueError("Operator configuration must not be a symlink")
    if os.environ.get("SERVERHUB_DEV_MODE", "").lower() not in {"true", "1"}:
        for component in (path.absolute(), *path.absolute().parents):
            metadata = component.lstat()
            if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise ValueError("Operator configuration and ancestors must be root-owned and protected")
    mode = path.stat().st_mode
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("Operator configuration must not be group/world writable")
    # Isolated dev mode permits non-root-owned test files; production config
    # and every ancestor must be protected against the unprivileged worker.
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("Operator configuration exceeds 1 MiB")
    data = yaml.safe_load(path.read_text()) or {}
    if not isinstance(data, dict):
        raise ValueError("Operator configuration must be a mapping")
    return data


class ProviderConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str = "openai"
    base_url: str
    model: str = Field(min_length=1, max_length=128)
    api_key_env: str | None = None
    allow_insecure_http: bool = False
    timeout_seconds: float = Field(default=90, ge=1, le=300)
    max_retries: int = Field(default=2, ge=0, le=4)
    max_output_tokens: int = Field(default=2048, ge=32, le=32768)
    max_tokens_parameter: str = "max_completion_tokens"
    input_cost_per_million: float | None = Field(default=None, ge=0, le=10000)
    output_cost_per_million: float | None = Field(default=None, ge=0, le=10000)
    context_limit: int = Field(default=32768, ge=1024, le=2000000)

    @field_validator("kind")
    @classmethod
    def kind_known(cls, value):
        if value not in ("openai", "ollama"):
            raise ValueError("kind must be openai or ollama")
        return value

    @model_validator(mode="after")
    def endpoint(self):
        self.base_url = validate_url(self.base_url, allow_http=self.allow_insecure_http)
        if self.max_tokens_parameter not in {"max_tokens", "max_completion_tokens"}:
            raise ValueError("max_tokens_parameter must be max_tokens or max_completion_tokens")
        if self.api_key_env and not __import__("re").fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", self.api_key_env):
            raise ValueError("api_key_env must name an environment variable")
        if self.kind == "ollama":
            self.input_cost_per_million = 0 if self.input_cost_per_million is None else self.input_cost_per_million
            self.output_cost_per_million = 0 if self.output_cost_per_million is None else self.output_cost_per_million
        return self


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class Completion:
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    cost: float = 0
    usage_verified: bool = True

    def assistant_message(self) -> dict:
        message: dict[str, Any] = {"role": "assistant", "content": self.content or None}
        if self.tool_calls:
            message["tool_calls"] = [
                {"id": c.id, "type": "function", "function": {"name": c.name, "arguments": json.dumps(c.arguments)}}
                for c in self.tool_calls
            ]
        return message


@dataclass
class UsageBudget:
    token_limit: int
    cost_limit: float
    tokens_used: int = 0
    cost_used: float = 0

    def preflight(self, config: ProviderConfig, messages: list[dict], output_tokens: int) -> int:
        # UTF-8 byte count is deliberately conservative; provider tokenizers
        # differ. Billed usage, if supplied, replaces this reserve after a call.
        estimated_input = len(json.dumps(messages, ensure_ascii=False).encode("utf-8"))
        if estimated_input + output_tokens > config.context_limit:
            raise BudgetExceeded("Conversation exceeds configured conservative context bound")
        if self.tokens_used + estimated_input + output_tokens > self.token_limit:
            raise BudgetExceeded("Job token budget would be exceeded")
        if config.input_cost_per_million is None or config.output_cost_per_million is None:
            raise BudgetExceeded("API pricing must be configured before paid model use")
        reserve = (estimated_input * config.input_cost_per_million + output_tokens * config.output_cost_per_million) / 1_000_000
        if self.cost_used + reserve > self.cost_limit:
            raise BudgetExceeded("Job API cost budget would be exceeded")
        return estimated_input

    def charge(self, completion: Completion) -> None:
        self.tokens_used += completion.input_tokens + completion.output_tokens
        self.cost_used += completion.cost
        if self.tokens_used > self.token_limit or self.cost_used > self.cost_limit:
            raise BudgetExceeded("Provider billed usage exceeded the reserved budget; further requests stopped")


def load_routes(path: str | Path | None = None) -> dict[str, ProviderConfig]:
    if path is None:
        try:
            from serverhub.settings import get_settings
            path = getattr(get_settings(), "model_config_path", "/etc/serverhub/models.yaml")
        except ImportError:
            path = "/etc/serverhub/models.yaml"
    data = read_operator_yaml(path)
    routes = data.get("routes", {})
    if not isinstance(routes, dict):
        raise ValueError("routes must be a mapping")
    if any(not isinstance(name, str) or not __import__("re").fullmatch(r"[A-Za-z0-9_-]{1,64}", name) for name in routes):
        raise ValueError("Invalid model route name")
    return {name: ProviderConfig.model_validate(config) for name, config in routes.items()}


class ChatProvider:
    def __init__(self, config: ProviderConfig, *, transport: httpx.BaseTransport | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.config = config
        self.transport = transport
        self.sleep = sleep

    def complete(self, messages: list[dict], tools: list[dict], budget: UsageBudget,
                 before_request: Callable[[], None] | None = None) -> Completion:
        cfg = self.config
        output_limit = min(cfg.max_output_tokens, max(32, budget.token_limit - budget.tokens_used))
        # Reserve before every HTTP request, including retries. Timed-out calls
        # may still be billed. Such attempts are charged conservatively.
        budget_messages = messages + [{"role": "system", "content": json.dumps(tools, ensure_ascii=False)}]
        estimated_input = budget.preflight(cfg, budget_messages, output_limit)
        headers = {"Content-Type": "application/json"}
        if cfg.api_key_env:
            key = os.environ.get(cfg.api_key_env)
            if not key:
                raise ProviderError("Configured provider credential is unavailable")
            headers["Authorization"] = f"Bearer {key}"
        if cfg.kind == "ollama":
            body = {"model": cfg.model, "messages": self._ollama_messages(messages), "stream": False,
                    "options": {"num_predict": output_limit}}
            endpoint = "/api/chat"
        else:
            body = {"model": cfg.model, "messages": messages, "stream": False, cfg.max_tokens_parameter: output_limit}
            endpoint = "/chat/completions"
        if tools:
            body["tools"] = tools
        with httpx.Client(timeout=cfg.timeout_seconds, transport=self.transport, follow_redirects=False, trust_env=False) as client:
            for attempt in range(cfg.max_retries + 1):
                budget.preflight(cfg, budget_messages, output_limit)
                if before_request:
                    before_request()
                try:
                    with client.stream("POST", cfg.base_url + endpoint, headers=headers, json=body) as response:
                        raw = b""
                        for chunk in response.iter_bytes():
                            raw += chunk
                            if len(raw) > 4 * 1024 * 1024:
                                raise ProviderError("Provider response exceeded 4 MiB")
                        status = response.status_code
                    if status == 429 or status >= 500:
                        raise ProviderError(f"Provider temporarily unavailable (HTTP {status})", retryable=True)
                    if status >= 300:
                        raise ProviderError(f"Provider rejected request (HTTP {status})")
                    try:
                        completion = self._parse(json.loads(raw), estimated_input, output_limit)
                    except (ValueError, KeyError, IndexError, TypeError) as exc:
                        # Invalid replies still incur provider cost.
                        self._charge_unknown(budget, estimated_input, output_limit)
                        raise ProviderError("Provider returned an invalid chat response") from exc
                    budget.charge(completion)
                    return completion
                except httpx.HTTPError as exc:
                    self._charge_unknown(budget, estimated_input, output_limit)
                    if attempt == cfg.max_retries:
                        raise ProviderError("Provider transport failed", retryable=True) from exc
                except ProviderError as exc:
                    if not exc.retryable or attempt == cfg.max_retries:
                        raise
                self.sleep(min(2 ** attempt, 8))
        raise ProviderError("Provider exhausted retries", retryable=True)

    def _charge_unknown(self, budget: UsageBudget, inp: int, out: int):
        cfg = self.config
        budget.charge(Completion("", input_tokens=inp, output_tokens=out,
                                cost=(inp * (cfg.input_cost_per_million or 0) + out * (cfg.output_cost_per_million or 0)) / 1_000_000,
                                usage_verified=False))

    @staticmethod
    def _ollama_messages(messages):
        converted = []
        for source in messages:
            message = dict(source)
            if message.get("content") is None:
                message["content"] = ""
            if message.get("tool_calls"):
                message["tool_calls"] = [{"function": {"name": call["function"]["name"],
                    "arguments": json.loads(call["function"]["arguments"]) if isinstance(call["function"]["arguments"], str) else call["function"]["arguments"]}}
                    for call in message["tool_calls"]]
            if message.get("role") == "tool":
                message.pop("tool_call_id", None)
            converted.append(message)
        return converted

    def _parse(self, data: dict, fallback_input: int, output_limit: int) -> Completion:
        cfg = self.config
        if cfg.kind == "ollama":
            message = data["message"]
            verified = "prompt_eval_count" in data and "eval_count" in data
            inp = int(data.get("prompt_eval_count", fallback_input))
            out = int(data.get("eval_count", output_limit))
        else:
            message = data["choices"][0]["message"]
            usage = data.get("usage") or {}
            verified = "prompt_tokens" in usage and "completion_tokens" in usage
            inp = int(usage.get("prompt_tokens", fallback_input))
            out = int(usage.get("completion_tokens", output_limit))
        if inp < 0 or out < 0 or len(message.get("tool_calls") or []) > 16:
            raise ValueError("Invalid usage/tool count")
        calls = []
        for call in message.get("tool_calls") or []:
            function = call["function"]
            arguments = function["arguments"]
            if isinstance(arguments, str):
                arguments = json.loads(arguments)
            if not isinstance(arguments, dict):
                raise ValueError("Tool arguments must be an object")
            calls.append(ToolCall(str(call.get("id") or uuid.uuid4()), function["name"], arguments))
        content = message.get("content") or ""
        if not isinstance(content, str):
            raise ValueError("Text chat completion required")
        return Completion(content=content, tool_calls=calls, input_tokens=inp, output_tokens=out,
                          cost=(inp * (cfg.input_cost_per_million or 0) + out * (cfg.output_cost_per_million or 0)) / 1_000_000,
                          usage_verified=verified)
