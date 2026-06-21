from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from llm_client import BaseLLMClient, chat_and_extract_json, make_llm_client
from prompts.snippet_extraction_prompts import build_snippet_messages


@dataclass
class SnippetResult:
    vuln_type: str
    parsed: Dict[str, Any]


class SnippetAgent:
    def __init__(self, llm_client: Optional[BaseLLMClient] = None) -> None:
        self.llm = llm_client or make_llm_client()

    def extract(
        self,
        vulnerability_type: str,
        routing_info: Dict[str, Any],
        contract_code: str,
        knowledge_profile: Dict[str, Any] | None = None,
        temperature: float = 0.1,
    ) -> SnippetResult:
        messages = build_snippet_messages(vulnerability_type, routing_info, contract_code, knowledge_profile)
        parsed = chat_and_extract_json(self.llm, messages, temperature=temperature)
        return SnippetResult(vuln_type=vulnerability_type, parsed=parsed)
