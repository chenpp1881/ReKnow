from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from llm_client import BaseLLMClient, chat_and_extract_json, make_llm_client
from prompts.router_prompts import build_router_messages


@dataclass
class RouterResult:
    parsed: Dict[str, Any]


class RouterAgent:
    def __init__(self, llm_client: Optional[BaseLLMClient] = None) -> None:
        self.llm = llm_client or make_llm_client()

    def route(self, contract_code: str, max_candidates: int = 6, temperature: float = 0.1) -> RouterResult:
        messages = build_router_messages(contract_code, max_candidates=max_candidates)
        parsed = chat_and_extract_json(self.llm, messages, temperature=temperature)
        return RouterResult(parsed=parsed)
