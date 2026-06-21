from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from llm_client import BaseLLMClient, chat_and_extract_json, make_llm_client
from prompts.judge_prompts import build_judge_messages


@dataclass
class JudgeResult:
    vuln_type: str
    parsed: Dict[str, Any]


class JudgeAgent:
    def __init__(self, llm_client: Optional[BaseLLMClient] = None) -> None:
        self.llm = llm_client or make_llm_client('JUDGE')

    def decide(
        self,
        vulnerability_type: str,
        code_subset_package: Dict[str, Any],
        routing_info: Dict[str, Any],
        vulnerability_knowledge: Dict[str, Any] | None = None,
        temperature: float = 0.1,
    ) -> JudgeResult:
        messages = build_judge_messages(
            vulnerability_type,
            code_subset_package,
            routing_info,
            vulnerability_knowledge=vulnerability_knowledge,
        )
        parsed = chat_and_extract_json(self.llm, messages, temperature=temperature)
        return JudgeResult(vuln_type=vulnerability_type, parsed=parsed)
