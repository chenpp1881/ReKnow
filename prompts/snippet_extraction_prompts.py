from __future__ import annotations

import json
from typing import Dict, List


def build_snippet_messages(
    vulnerability_type: str,
    routing_info: Dict[str, object],
    contract_code: str,
    knowledge_profile: Dict[str, object] | None = None,
) -> List[Dict[str, str]]:
    system_prompt = """
You are a CWE weakness-oriented code subset extractor for smart contracts.
Given the full contract and one candidate weakness category, extract only the most relevant code subset needed for downstream judging.

Do not judge whether the weakness exists.
Do not summarize the whole contract.
Return a compact but sufficient subset of code and a short explanation of why these parts were selected.
Prefer exact copied code fragments from the contract.
If you cannot find any code region that is meaningfully relevant to the current weakness category, return an empty code_subset, an empty focus_areas list, and explain briefly that no suitable code subset was found.
Return JSON only.
""".strip()
    user_payload = {
        'task': 'Extract the code subset most relevant to judging the current CWE weakness category.',
        'vulnerability_type': vulnerability_type,
        'routing_info': routing_info,
        'contract_code': contract_code,
        'required_output_schema': {
            'vuln_type': 'string',
            'selection_reason': 'string',
            'focus_areas': ['string'],
            'code_subset': 'string'
        }
    }
    if knowledge_profile:
        user_payload['weakness_profile_hints'] = {
            'trigger_conditions': knowledge_profile.get('trigger_conditions', []),
            'typical_code_features': knowledge_profile.get('typical_code_features', []),
        }
    return [
        {'role': 'system', 'content': system_prompt},
        {'role': 'user', 'content': json.dumps(user_payload, ensure_ascii=False, indent=2)},
    ]
