from __future__ import annotations

import json
import os
import re
import urllib.request
from urllib.error import HTTPError, URLError
from pathlib import Path
from typing import Any, Dict, List


def load_project_env() -> None:
    candidates = [Path.cwd() / '.env', Path(__file__).resolve().parent / '.env']
    for env_path in candidates:
        if not env_path.exists() or not env_path.is_file():
            continue
        for raw_line in env_path.read_text(encoding='utf-8').splitlines():
            line = raw_line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
        break


load_project_env()


class BaseLLMClient:
    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.2) -> str:
        raise NotImplementedError


class OpenAICompatibleClient(BaseLLMClient):
    def __init__(self, env_prefix: str | None = None) -> None:
        self.env_prefix = (env_prefix or '').strip().upper()
        self.api_key = _get_llm_env(self.env_prefix, 'OPENAI_API_KEY', '')
        self.base_url = _get_llm_env(self.env_prefix, 'OPENAI_BASE_URL', 'https://api.openai.com/v1').rstrip('/')
        self.model = _get_llm_env(self.env_prefix, 'LLM_MODEL', 'gpt-4o-mini')
        self.timeout = max(1, int(_get_llm_env(self.env_prefix, 'LLM_REQUEST_TIMEOUT', '180')))
        if not self.api_key:
            raise RuntimeError('OPENAI_API_KEY is required for the OpenAI-compatible client.')

    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.2) -> str:
        url = f'{self.base_url}/chat/completions'
        payload = {
            'model': self.model,
            'messages': messages,
            'response_format': {'type': 'json_object'},
        }
        if self.model != 'deepseek-reasoner':
            payload['temperature'] = temperature
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {self.api_key}'},
            method='POST',
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode('utf-8'))
        except HTTPError as exc:
            error_body = exc.read().decode('utf-8', errors='replace')
            raise RuntimeError(f'LLM API HTTP {exc.code}: {error_body}') from exc
        except URLError as exc:
            raise RuntimeError(f'LLM API request failed: {exc}') from exc
        return body['choices'][0]['message']['content']


def _get_llm_env(prefix: str, key: str, default: str = '') -> str:
    normalized_prefix = prefix.strip().upper()
    if normalized_prefix:
        prefixed_key = f'{normalized_prefix}_{key}'
        if prefixed_key in os.environ and str(os.environ[prefixed_key]).strip():
            return str(os.environ[prefixed_key]).strip()
    return str(os.environ.get(key, default)).strip()


def make_llm_client(env_prefix: str | None = None) -> BaseLLMClient:
    normalized_prefix = (env_prefix or '').strip().upper()
    provider = _get_llm_env(normalized_prefix, 'LLM_PROVIDER', '').lower()
    if provider not in {'openai', 'deepseek', 'openai_compatible'}:
        provider_label = f'{normalized_prefix}_LLM_PROVIDER' if normalized_prefix else 'LLM_PROVIDER'
        raise RuntimeError(
            f'{provider_label} must be one of: openai, deepseek, openai_compatible. '
            'Mock mode has been removed.'
        )
    return OpenAICompatibleClient(env_prefix=normalized_prefix)


def extract_json(text: str) -> Dict[str, Any]:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r'\{.*\}', text, flags=re.DOTALL)
    if not match:
        preview = text[:300].replace('\n', '\\n')
        raise ValueError(f'No JSON object found in model output. Raw preview: {preview}')
    return json.loads(match.group())


def chat_and_extract_json(
    llm: BaseLLMClient,
    messages: List[Dict[str, str]],
    temperature: float = 0.2,
) -> Dict[str, Any]:
    raw = llm.chat(messages, temperature=temperature)
    try:
        return extract_json(raw)
    except Exception:
        retry_messages = list(messages) + [
            {
                'role': 'assistant',
                'content': raw or '',
            },
            {
                'role': 'user',
                'content': (
                    'Your previous reply was not valid JSON. '
                    'Return exactly one JSON object that matches the required_output_schema. '
                    'Do not include markdown, explanation, or code fences.'
                ),
            },
        ]
        retry_raw = llm.chat(retry_messages, temperature=temperature)
        try:
            return extract_json(retry_raw)
        except Exception as exc:
            preview = retry_raw[:300].replace('\n', '\\n')
            raise ValueError(f'Failed to parse model output as JSON after one retry. Raw preview: {preview}') from exc
