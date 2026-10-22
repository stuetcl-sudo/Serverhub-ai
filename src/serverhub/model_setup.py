"""Bounded provider setup probes. No response can become an infrastructure action."""

import json
import os
import secrets

import httpx

from .ai.providers import ChatProvider, ProviderConfig, ProviderError, UsageBudget


def provider_json(config: ProviderConfig, path: str, body=None, *, transport=None):
    headers = {}
    if config.api_key_env:
        value = os.environ.get(config.api_key_env)
        if not value:
            raise ProviderError("Credential environment reference is unavailable in the API service")
        headers["Authorization"] = "Bearer " + value
    try:
        with httpx.Client(
            timeout=min(config.timeout_seconds, 15),
            transport=transport,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            with client.stream(
                "POST" if body is not None else "GET", config.base_url + path, json=body, headers=headers
            ) as response:
                raw = bytearray()
                for chunk in response.iter_bytes():
                    raw.extend(chunk)
                    if len(raw) > 1024 * 1024:
                        raise ProviderError("Provider setup response exceeds 1 MiB")
                if response.status_code >= 300:
                    raise ProviderError(
                        f"Model discovery/readiness rejected (HTTP {response.status_code}); check endpoint and installed model"
                    )
                data = json.loads(raw)
                if not isinstance(data, dict):
                    raise ValueError()
                return data
    except httpx.HTTPError as exc:
        raise ProviderError(
            "Cannot reach model endpoint within 15 seconds. Check private host/IP, port, bind address and controller access; keep Ollama restricted to your trusted network"
        ) from exc
    except (ValueError, TypeError) as exc:
        raise ProviderError("Model endpoint returned invalid JSON") from exc


def discover_models(config, *, transport=None):
    data = provider_json(config, "/api/tags" if config.kind == "ollama" else "/models", transport=transport)
    items = data.get("models" if config.kind == "ollama" else "data", [])
    if not isinstance(items, list):
        raise ProviderError("Model discovery response has no model list")
    return [
        {
            "name": str(item.get("name") or item.get("id"))[:128],
            "size": item.get("size"),
            "modified_at": item.get("modified_at"),
        }
        for item in items[:200]
        if isinstance(item, dict) and (item.get("name") or item.get("id"))
    ]


def test_model(config, *, transport=None):
    capabilities = []
    if config.kind == "ollama":
        data = provider_json(config, "/api/show", {"model": config.model}, transport=transport)
        capabilities = data.get("capabilities", [])
        if "tools" not in capabilities:
            return {
                "ready": False,
                "tool_calling": False,
                "capabilities": capabilities,
                "message": "This Ollama model does not advertise tool support. Select a tool-capable model; no model is downloaded automatically.",
            }
    nonce = secrets.token_hex(8)
    tools = [
        {
            "type": "function",
            "function": {
                "name": "serverhub_probe",
                "description": "Harmless connection test. Call with the exact provided nonce.",
                "parameters": {
                    "type": "object",
                    "properties": {"nonce": {"type": "string", "enum": [nonce]}},
                    "required": ["nonce"],
                    "additionalProperties": False,
                },
            },
        }
    ]
    budget = UsageBudget(16000, 0.1)
    probe = config.model_copy(
        update={
            "max_output_tokens": 128,
            "max_retries": 0,
            "timeout_seconds": min(config.timeout_seconds, 60),
        }
    )
    completion = ChatProvider(probe, transport=transport).complete(
        [
            {
                "role": "user",
                "content": "Call serverhub_probe once with nonce " + nonce + ". Do not answer in text.",
            }
        ],
        tools,
        budget,
    )
    valid = (
        len(completion.tool_calls) == 1
        and completion.tool_calls[0].name == "serverhub_probe"
        and completion.tool_calls[0].arguments == {"nonce": nonce}
    )
    return {
        "ready": valid,
        "tool_calling": valid,
        "capabilities": capabilities,
        "tokens_used": budget.tokens_used,
        "cost_used": budget.cost_used,
        "message": "Connection and a harmless structured tool call verified"
        if valid
        else "Connection succeeded, but the model did not produce the required structured tool call. Select another model or inspect its template.",
    }
