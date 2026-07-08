import json
import re

import httpx

from src.agents.config import LLMConfig


def extract_json(raw: str) -> str:
    """Strip markdown fences and extract the first valid JSON object.
    Handles truncated output by searching for the last complete }."""

    # Strip markdown fences
    cleaned = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    cleaned = cleaned.strip()

    # Try direct parse first
    try:
        json.loads(cleaned)
        return cleaned
    except json.JSONDecodeError:
        pass

    # Find the first { and try progressively shorter suffixes
    start = cleaned.find("{")
    if start == -1:
        return cleaned

    from_end = cleaned.rfind("}")
    while from_end > start:
        candidate = cleaned[start:from_end + 1]
        try:
            json.loads(candidate)
            return candidate
        except json.JSONDecodeError:
            from_end = cleaned.rfind("}", 0, from_end)

    # Last resort: return the full thing for the error message
    return cleaned[start:] if start >= 0 else cleaned


def chat(
    system: str,
    user: str,
    config: LLMConfig | None = None,
) -> str:
    if config is None:
        config = LLMConfig()

    if not config.configured:
        raise RuntimeError(
            "LLM not configured: set AEGIS_LLM_API_KEY (and optionally "
            "AEGIS_LLM_ENDPOINT / AEGIS_LLM_MODEL)"
        )

    url = f"{config.endpoint.rstrip('/')}/chat/completions"
    headers = {
        "Authorization": f"Bearer {config.api_key}",
        "Content-Type": "application/json",
    }
    body = {
        "model": config.model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.1,
    }

    last_exc: str | None = None
    for attempt in range(config.max_retries + 1):
        try:
            with httpx.Client(timeout=config.timeout) as client:
                resp = client.post(url, headers=headers, json=body)
            if resp.status_code == 200:
                data = resp.json()
                return data["choices"][0]["message"]["content"]
            elif resp.status_code >= 500 and attempt < config.max_retries:
                last_exc = f"HTTP {resp.status_code}: {resp.text[:200]}"
                continue
            else:
                resp.raise_for_status()
        except Exception as e:
            last_exc = str(e)
            if attempt < config.max_retries:
                continue
            raise RuntimeError(
                f"LLM call failed after {config.max_retries} retries: {last_exc}"
            )

    raise RuntimeError(f"LLM call failed: {last_exc}")
