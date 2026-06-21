from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from llm_client import BaseLLMClient, chat_and_extract_json, make_llm_client
from prompts.knowledge_maintenance_prompts import build_knowledge_maintenance_messages


@dataclass
class KnowledgeMaintenanceResult:
    vuln_type: str
    parsed: Dict[str, Any]


class KnowledgeMaintenanceAgent:
    def __init__(self, llm_client: Optional[BaseLLMClient] = None) -> None:
        self.llm = llm_client or make_llm_client()

    def maintain(
        self,
        vulnerability_type: str,
        existing_lessons: List[Dict[str, Any]],
        recently_added_lessons: List[Dict[str, Any]],
        temperature: float = 0.1,
    ) -> KnowledgeMaintenanceResult:
        messages = build_knowledge_maintenance_messages(
            vulnerability_type=vulnerability_type,
            existing_lessons=existing_lessons,
            recently_added_lessons=recently_added_lessons,
        )
        parsed = chat_and_extract_json(self.llm, messages, temperature=temperature)
        return KnowledgeMaintenanceResult(vuln_type=vulnerability_type, parsed=parsed)
