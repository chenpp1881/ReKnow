from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from llm_client import BaseLLMClient, chat_and_extract_json, make_llm_client
from prompts.reflection_prompts import build_reflection_messages


@dataclass
class ReflectionResult:
    vuln_type: str
    parsed: Dict[str, Any]


class ReflectionAgent:
    def __init__(self, llm_client: Optional[BaseLLMClient] = None) -> None:
        self.llm = llm_client or make_llm_client('REFLECTION')

    def reflect(
        self,
        vulnerability_type: str,
        predicted_label: int,
        true_label: int,
        explanation_package: Dict[str, Any],
        knowledge_profile: Dict[str, Any] | None = None,
        temperature: float = 0.2,
    ) -> ReflectionResult:
        messages = build_reflection_messages(vulnerability_type, predicted_label, true_label, explanation_package, knowledge_profile)
        parsed = chat_and_extract_json(self.llm, messages, temperature=temperature)
        return ReflectionResult(vuln_type=vulnerability_type, parsed=parsed)
