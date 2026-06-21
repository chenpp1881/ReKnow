from __future__ import annotations

import json
from typing import Dict, List


def build_knowledge_maintenance_messages(
    vulnerability_type: str,
    existing_lessons: List[Dict[str, object]],
    recently_added_lessons: List[Dict[str, object]],
) -> List[Dict[str, str]]:
    system_prompt = """
You are a knowledge-base maintenance agent for smart-contract CWE weakness auditing.
Your job is to consolidate the learned lessons for one weakness category without losing important signal.

You must:
- remove exact duplicates and near-duplicates,
- merge highly similar lessons when one cleaner lesson can represent them,
- keep multiple lessons only when they capture meaningfully different situations or decision boundaries,
- resolve obvious conflicts by preferring the lesson that is more precise, better conditioned, and less likely to cause systematic misjudgment,
- preserve useful aspect labels and applies_when conditions whenever possible.
- preserve provenance metadata such as source_sample_id whenever possible.

Do not invent broad new theory. Work only from the provided lessons.
Return JSON only.
""".strip()
    user_payload = {
        'task': 'Consolidate, deduplicate, and clean the learned lessons for one weakness category.',
        'vulnerability_type': vulnerability_type,
        'existing_lessons': existing_lessons,
        'recently_added_lessons': recently_added_lessons,
        'required_output_schema': {
            'vuln_type': 'string',
            'final_lessons': [
                {
                    'aspect': 'cause | trigger_conditions | typical_code_features | common_scenarios | attack_path | false_positive_boundaries',
                    'lesson': 'string',
                    'applies_when': 'string',
                    'rule_type': 'calibration | insufficiency_rule | weighing_rule | boundary_condition',
                    'source_sample_id': 'string'
                }
            ],
            'removed_or_merged_count': 0,
            'maintenance_summary': 'string'
        }
    }
    return [
        {'role': 'system', 'content': system_prompt},
        {'role': 'user', 'content': json.dumps(user_payload, ensure_ascii=False, indent=2)},
    ]
