from __future__ import annotations

import json
from typing import Dict, List


def build_knowledge_summary_messages(
    vulnerability_type: str,
    reflection_result: Dict[str, object],
    knowledge_profile: Dict[str, object],
    existing_lessons: List[Dict[str, object]],
) -> List[Dict[str, str]]:
    error_type = str(reflection_result.get('error_type', '')).strip().lower()
    if error_type == 'false_positive':
        lesson_focus = (
            'Prefer lessons that sharpen false_positive_boundaries or trigger_conditions '
            'to prevent future over-flagging caused by weak or non-decisive evidence.'
        )
    elif error_type == 'false_negative':
        lesson_focus = (
            'Prefer lessons that sharpen trigger_conditions, typical_code_features, or attack_path '
            'to prevent future under-detection of exploit-enabling patterns.'
        )
    else:
        lesson_focus = 'Prefer lessons that directly reduce the failure type identified in the reflection.'

    system_prompt = """
You are a knowledge-base curator for smart-contract CWE weakness auditing.

A reflection agent has diagnosed a classification failure for a specific CWE type.
Your task is to independently reason about what narrow, reusable decision boundary would prevent
the same error. You may extract 0, 1, or 2 new lessons from that reasoning.

Output zero lessons if the reflection is generic, sample-specific, redundant with the existing
profile, or does not identify a reproducible failure pattern. One precise lesson is always better
than two vague ones.

High-value lessons have ALL of these properties:
- they identify a specific, statically observable code pattern,
- they explain how that pattern should move the verdict boundary,
- they are narrower than the CWE definition,
- they remain useful across future contracts of the same CWE type.

Low-value lessons must be rejected. Examples:
- broad slogans such as "missing authorization checks are dangerous"
- profile restatements such as "unchecked external calls may fail"
- generic wording like "critical state", "sensitive operation", or "unsafe logic"
  without saying exactly what code evidence makes the rule fire
- lessons that would trigger on most contracts in the category

Aspect assignment rules:
- lessons that argue FOR flagging belong to:
  trigger_conditions | typical_code_features | common_scenarios | attack_path
- lessons that argue AGAINST flagging belong to:
  false_positive_boundaries
- reject lessons whose aspect does not match the direction of the rule

Calibration rules:
- false_negative: the lesson may lower the threshold only for a narrow, concrete code pattern
- false_positive: the lesson may raise the threshold only for a narrow, concrete code pattern
- reject anything that shifts the boundary too broadly or in the wrong direction

applies_when rules:
- must be statically observable in source code
- must describe code already present, not hypothetical future behavior
- must be specific enough that a reviewer could tell when the lesson fires
- reject wording grounded mainly in "could", "may", "might", "potential for", or "risk of"

Profile and duplication rules:
- identify the exact profile entry this lesson refines
- reject the lesson if it only paraphrases an existing profile entry
- reject the lesson if it duplicates an existing lesson
- reject the lesson if it depends on project-specific names, addresses, or one-off facts

Return JSON only.
""".strip()

    user_payload = {
        'task': 'Using the reflection as diagnostic input, independently reason about the narrow, reusable decision boundary that would prevent the same error, then extract 0-2 lessons from that reasoning.',
        'vulnerability_type': vulnerability_type,
        'error_type': error_type,
        'lesson_focus': lesson_focus,
        'knowledge_profile': knowledge_profile,
        'existing_lessons': existing_lessons,
        'reflection_result': reflection_result,
        'required_output_schema': {
            'vuln_type': 'string',
            'accepted_lessons': [
                {
                    'aspect': 'cause | trigger_conditions | typical_code_features | common_scenarios | attack_path | false_positive_boundaries',
                    'lesson': 'string',
                    'applies_when': 'string - specific, checkable evidence condition',
                    'rule_type': 'calibration | insufficiency_rule | weighing_rule | boundary_condition',
                    'decision_boundary_change': 'string - explain exactly how this lesson changes vulnerable vs not_vulnerable judgment on a narrow code pattern',
                    'gap_filled': 'string - quote the specific profile entry (aspect + text) this lesson refines, then state in one sentence what it adds that the quoted entry does not cover',
                }
            ],
            'rejected_candidates': [
                {
                    'candidate': 'string',
                    'rejection_reason': 'string',
                }
            ],
        }
    }
    return [
        {'role': 'system', 'content': system_prompt},
        {'role': 'user', 'content': json.dumps(user_payload, ensure_ascii=False, indent=2)},
    ]
