"""OpenAI-compatible and Ollama chat APIs with bounded, explicit accounting.

No SDK or provider-specific agent runtime is required. Endpoint/model/pricing
configuration is an operator-owned trust boundary, never model output.
"""
from __future__ import annotations

import json
import math
import ipaddress
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
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator


class ProviderError(RuntimeError):
    """A sanitized, classified provider failure."""
    def __init__(self, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable


class BudgetExceeded(RuntimeError):
    def __init__(self, message: str, *, diagnostics: dict | None = None):
        super().__init__(message)
        self.diagnostics = diagnostics or {}


class PreflightRejected(BudgetExceeded):
    """Request admission failed; unlike actual usage overrun this made no call."""


def format_messages(messages: list[dict], kind: str) -> list[dict]:
    if kind == "openai":
        return messages
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
            if "name" in message:
                message["tool_name"] = message.pop("name")
        converted.append(message)
    return converted


def estimate_prompt(messages: list[dict], tools: list[dict] | None = None, *, kind: str = "openai") -> dict:
    """Portable *estimate*, not a tokenizer or a guaranteed upper bound.

    ASCII BPE text/code/JSON: 3 characters/token plus 20% headroom. Non-ASCII
    uses UTF-8 bytes as a deliberately cautious allowance (covers CJK/emoji).
    Count tool schemas once, without double-encoding them into message content.
    Include chat framing separately; never infer a Qwen tokenizer from its name.
    Provider usage replaces this estimate after a response, never added to it.
    """
    messages = format_messages(messages, kind)
    text = json.dumps({"messages": messages, "tools": tools or []}, ensure_ascii=False, separators=(",", ":"))
    ascii_chars = sum(ord(char) < 128 for char in text)
    byte_count = len(text.encode("utf-8"))
    estimate = math.ceil((ascii_chars / 3 + byte_count - ascii_chars) * 1.2)
    return {"method": "mixed_utf8_bpe_estimate_v1", "estimated_input_tokens": estimate + 12 * len(messages) + 32,
            "serialized_utf8_bytes": byte_count, "is_exact": False,
            "provider_format": kind, "ascii_characters_per_token": 3, "uncertainty_margin": 0.2,
            "framing_reserve_tokens": 12 * len(messages) + 32}


def validate_url(value: str, *, allow_http: bool = False) -> str:
    parsed = urlsplit(value)
    if (parsed.scheme not in ("https", "http") or not parsed.hostname or
            parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("A fixed HTTP(S) URL without credentials, query or fragment is required")
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        try:
            address = ipaddress.ip_address(parsed.hostname)
            private = any(address in ipaddress.ip_network(network) for network in
                          ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
                          if address.version == ipaddress.ip_network(network).version)
        except ValueError:
            private = False
        if not allow_http or not private:
            raise ValueError("Private HTTP requires explicit allow_insecure_http and a literal RFC1918/ULA address; use HTTPS for public endpoints or DNS names")
    return value.rstrip("/")


def read_operator_yaml(path: str | Path) -> dict:
    path = Path(path)
    try:
        if not path.is_file():
            return {}
    except PermissionError as exc:
        raise ValueError("Model configuration cannot be read; run Setup diagnostics to inspect file and ancestor permissions") from exc
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
    default_job_token_budget: int = Field(default=20000, ge=0, le=2_000_000)
    default_job_cost_budget: float = Field(default=1.0, ge=0, le=1000, allow_inf_nan=False)

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
    accounting: dict = field(default_factory=dict)

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

    last_preflight: dict = field(default_factory=dict)

    def preflight(self, config: ProviderConfig, messages: list[dict], output_tokens: int | None = None,
                  tools: list[dict] | None = None) -> int:
        estimate = estimate_prompt(messages, tools, kind=config.kind)
        estimated_input = estimate["estimated_input_tokens"]
        requested = config.max_output_tokens if output_tokens is None else output_tokens
        if isinstance(requested, bool) or not isinstance(requested, int) or requested < 0:
            raise ValueError("Output reservation must be a non-negative integer")
        # Never reserve more than the *actual* remaining request/job allowance,
        # even in a rejection diagnostic. No request is sent with <32 output.
        output_tokens = max(0, min(requested, config.max_output_tokens,
                                  config.context_limit - estimated_input,
                                  self.token_limit - self.tokens_used - estimated_input))
        self.last_preflight = {**estimate, "output_reserve_tokens": output_tokens,
                               "tokens_used": self.tokens_used, "token_limit": self.token_limit,
                               "remaining_tokens": max(0, self.token_limit - self.tokens_used),
                               "minimum_output_tokens": 32,
                               "context_limit": config.context_limit}
        details = (f"input estimate={estimated_input}, output reserve={output_tokens}, "
                   f"used={self.tokens_used}, remaining job budget={max(0, self.token_limit - self.tokens_used)}, "
                   f"job limit={self.token_limit}, context limit={config.context_limit}, minimum output=32; "
                   f"estimator={estimate['method']}, serialized bytes={estimate['serialized_utf8_bytes']}")
        if estimated_input + 32 > config.context_limit:
            raise PreflightRejected("Conversation exceeds configured context limit: " + details +
                                 ". Reduce history/tool results or configure a supported larger context.", diagnostics=self.last_preflight)
        if self.tokens_used + estimated_input + 32 > self.token_limit or output_tokens < 32:
            raise PreflightRejected("Job token budget would be exceeded: " + details +
                                 ". Reduce task scope/history or increase the authorized job budget.", diagnostics=self.last_preflight)
        if config.input_cost_per_million is None or config.output_cost_per_million is None:
            raise PreflightRejected("API pricing must be configured before paid model use: " + details, diagnostics=self.last_preflight)
        reserve = (estimated_input * config.input_cost_per_million + output_tokens * config.output_cost_per_million) / 1_000_000
        self.last_preflight.update({"cost_reserve": reserve, "cost_used": self.cost_used, "cost_limit": self.cost_limit})
        if self.cost_used + reserve > self.cost_limit:
            raise PreflightRejected(f"Job API cost budget would be exceeded: reserve={reserve:.6f}, used={self.cost_used:.6f}, limit={self.cost_limit:.6f}; {details}", diagnostics=self.last_preflight)
        return estimated_input

    def charge(self, completion: Completion) -> None:
        self.tokens_used += completion.input_tokens + completion.output_tokens
        self.cost_used += completion.cost
        if self.tokens_used > self.token_limit or self.cost_used > self.cost_limit:
            raise BudgetExceeded(f"Provider billed usage exceeded the reserved budget; further requests stopped: "
                                 f"actual input={completion.input_tokens}, actual output={completion.output_tokens}, "
                                 f"used={self.tokens_used}, job limit={self.token_limit}, remaining job budget={max(0, self.token_limit-self.tokens_used)}, "
                                 f"context limit={self.last_preflight.get('context_limit', 'unknown')}, cost used={self.cost_used:.6f}, cost limit={self.cost_limit:.6f}")


def load_routes(path: str | Path | None = None) -> dict[str, ProviderConfig]:
    if path is None:
        from serverhub.database import SessionLocal
        from serverhub.models import ModelRoute
        from sqlalchemy import select
        # DB errors are not swallowed: a missing migration must be actionable.
        with SessionLocal() as db:
            saved = db.scalars(select(ModelRoute)).all()
            if saved:
                return validate_routes({row.name: row.config for row in saved if row.enabled})
    if path is None:
        try:
            from serverhub.settings import get_settings
            path = getattr(get_settings(), "model_config_path", "/etc/serverhub/models.yaml")
        except ImportError:
            path = "/etc/serverhub/models.yaml"
    try:
        data = read_operator_yaml(path)
    except yaml.YAMLError as exc:
        raise ValueError("Invalid model YAML. Use owner Setup or validate the root-owned fallback file; source contents are not returned") from exc
    if set(data) - {"routes", "providers"} or data.get("providers"):
        raise ValueError("Unsupported model configuration shape. Use inline route configurations or owner Setup; legacy provider documents remain private")
    routes = data.get("routes", {})
    if not isinstance(routes, dict):
        raise ValueError("routes must be a mapping")
    if any(not isinstance(name, str) or not __import__("re").fullmatch(r"[A-Za-z0-9_-]{1,64}", name) for name in routes):
        raise ValueError("Invalid model route name")
    return validate_routes(routes)


def validate_routes(routes):
    result = {}
    for name, config in routes.items():
        try:
            result[name] = ProviderConfig.model_validate(config)
        except ValidationError as exc:
            fields = sorted({".".join(str(part) for part in error["loc"]) or "endpoint" for error in exc.errors()})
            raise ValueError("Invalid model route " + str(name) + ": check " + ", ".join(fields) + " in owner Setup. Configuration values are withheld") from None
    return result


class ChatProvider:
    def __init__(self, config: ProviderConfig, *, transport: httpx.BaseTransport | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.config = config
        self.transport = transport
        self.sleep = sleep

    def complete(self, messages: list[dict], tools: list[dict], budget: UsageBudget,
                 before_request: Callable[[], None] | None = None) -> Completion:
        cfg = self.config
        estimated_input = budget.preflight(cfg, messages, tools=tools)
        output_limit = budget.last_preflight["output_reserve_tokens"]
        headers = {"Content-Type": "application/json"}
        if cfg.api_key_env:
            key = os.environ.get(cfg.api_key_env)
            if not key:
                raise ProviderError("Configured provider credential is unavailable")
            headers["Authorization"] = f"Bearer {key}"
        if cfg.kind == "ollama":
            body = {"model": cfg.model, "messages": self._ollama_messages(messages), "stream": False,
                    "options": {"num_predict": output_limit, "num_ctx": cfg.context_limit}}
            endpoint = "/api/chat"
        else:
            body = {"model": cfg.model, "messages": messages, "stream": False, cfg.max_tokens_parameter: output_limit}
            endpoint = "/chat/completions"
        if tools:
            body["tools"] = tools
        with httpx.Client(timeout=cfg.timeout_seconds, transport=self.transport, follow_redirects=False, trust_env=False) as client:
            for attempt in range(cfg.max_retries + 1):
                estimated_input = budget.preflight(cfg, messages, tools=tools)
                output_limit = budget.last_preflight["output_reserve_tokens"]
                if cfg.kind == "ollama":
                    body["options"]["num_predict"] = output_limit
                else:
                    body[cfg.max_tokens_parameter] = output_limit
                budget.last_preflight["request_utf8_bytes"] = len(json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
                if before_request:
                    before_request()
                try:
                    with client.stream("POST", cfg.base_url + endpoint, headers=headers, json=body) as response:
                        raw = b""
                        for chunk in response.iter_bytes():
                            raw += chunk
                            if len(raw) > 4 * 1024 * 1024:
                                self._charge_unknown(budget, estimated_input, output_limit)
                                raise ProviderError("Provider response exceeded 4 MiB")
                        status = response.status_code
                    if status >= 300:
                        # A provider rejection does not prove zero upstream
                        # work/billing. Charge its reserve before any retry.
                        self._charge_unknown(budget, estimated_input, output_limit)
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
                    completion.accounting = {**budget.last_preflight, "actual_input_tokens": completion.input_tokens if completion.usage_verified else None,
                                             "actual_output_tokens": completion.output_tokens if completion.usage_verified else None,
                                             "usage_verified": completion.usage_verified}
                    budget.charge(completion)
                    return completion
                except httpx.HTTPError as exc:
                    self._charge_unknown(budget, estimated_input, output_limit)
                    if attempt == cfg.max_retries:
                        raise ProviderError("Provider transport failed: model endpoint is unreachable or timed out; check Settings → AI providers and the controller-to-Ollama network path", retryable=True) from exc
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
        return format_messages(messages, "ollama")

    def _parse(self, data: dict, fallback_input: int, output_limit: int) -> Completion:
        cfg = self.config
        def counter(values, name, fallback):
            value = values.get(name, fallback)
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2_000_000:
                raise ValueError("Provider usage counts must be bounded non-negative integers")
            return value
        if cfg.kind == "ollama":
            message = data["message"]
            verified = "prompt_eval_count" in data and "eval_count" in data
            inp = counter(data, "prompt_eval_count", fallback_input)
            out = counter(data, "eval_count", output_limit)
        else:
            message = data["choices"][0]["message"]
            usage = data.get("usage") or {}
            verified = "prompt_tokens" in usage and "completion_tokens" in usage
            inp = counter(usage, "prompt_tokens", fallback_input)
            out = counter(usage, "completion_tokens", output_limit)
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
