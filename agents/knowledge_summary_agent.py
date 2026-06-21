from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from llm_client import BaseLLMClient, chat_and_extract_json, make_llm_client
from prompts.knowledge_summary_prompts import build_knowledge_summary_messages


@dataclass
class KnowledgeSummaryResult:
    vuln_type: str
    parsed: Dict[str, Any]


class KnowledgeSummaryAgent:
    def __init__(self, llm_client: Optional[BaseLLMClient] = None) -> None:
        self.llm = llm_client or make_llm_client()

    def summarize(
        self,
        vulnerability_type: str,
        reflection_result: Dict[str, Any],
        knowledge_profile: Dict[str, Any],
        existing_lessons: List[Dict[str, Any]],
        temperature: float = 0.1,
    ) -> KnowledgeSummaryResult:
        messages = build_knowledge_summary_messages(vulnerability_type, reflection_result, knowledge_profile, existing_lessons)
        parsed = chat_and_extract_json(self.llm, messages, temperature=temperature)
        return KnowledgeSummaryResult(vuln_type=vulnerability_type, parsed=parsed)
