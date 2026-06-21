from __future__ import annotations

import json
from typing import Dict, List


def build_judge_messages(
    vulnerability_type: str,
    code_subset_package: Dict[str, object],
    routing_info: Dict[str, object],
    vulnerability_knowledge: Dict[str, object] | None = None,
) -> List[Dict[str, str]]:
    system_prompt = """
You are the final binary CWE weakness detector for smart contracts.
Judge whether the specified CWE weakness category is present in the contract.

You must use an explicit staged reasoning process. Do not jump directly to the verdict.

Reason in this order:
1. Code evidence assessment:
   Examine the code subset itself and identify the concrete behaviors, control flow, data flow, state changes, external interactions, guards, and missing checks that matter for the current weakness category.
2. Weakness profile alignment:
   Compare the observed code evidence with the base weakness profile. Decide which core causes, trigger conditions, code features, scenarios, attack path elements, and false-positive boundaries are matched, contradicted, or still uncertain.
3. Lesson applicability assessment:
   First identify the small subset of available lessons that is genuinely most relevant to the current code subset. You may select zero, one, or a few lessons. Then review only those selected lessons carefully and decide whether each selected lesson is genuinely applicable to this case. Do not treat every available lesson as equally important.
4. Integrated decision:
   Combine the direct code evidence, the weakness profile alignment, and the applicable lessons into a final binary verdict.

The knowledge base is a calibration layer, not a replacement for code analysis.
The knowledge base contains:
- a base weakness profile with these aspects: cause, trigger_conditions, typical_code_features, common_scenarios, attack_path, false_positive_boundaries
- the learned lessons currently stored for this weakness category, each with an aspect, a lesson, and an applies_when condition
Use the base weakness profile as domain grounding for what this CWE category fundamentally looks like.
When many lessons are available, first narrow them down to the few that best match the current code subset and decision boundary.
If no lesson is clearly relevant, say so and rely on the code evidence and weakness profile instead.
Do not use the knowledge base only as a reason to become more conservative.
Also use it to detect risk patterns that the provisional judgment may have underweighted or missed.
If a relevant knowledge entry highlights a strong exploit-enabling pattern that is present in the code subset, let that increase suspicion rather than only filtering it down.
Do not flip the provisional judgment unless the knowledge-base guidance is genuinely relevant and supported by concrete evidence in the current code subset.
Preserve balance: avoid turning a weak provisional vulnerable judgment into not_vulnerable without strong grounding, and avoid turning a weak provisional not_vulnerable judgment into vulnerable without strong grounding.
Knowledge should refine the decision boundary, not dominate it when the applicability is weak.
The final output should contain concise structured reasoning summaries, not hidden internal chain-of-thought or long free-form deliberation.
Give a concrete reason grounded in the contract behavior, evidence, and decision boundary.
Return only a binary verdict: vulnerable or not_vulnerable.
Return JSON only.
""".strip()
    user_payload = {
        'task': 'Judge whether the current CWE weakness category is present in the extracted code subset and explain why.',
        'vulnerability_type': vulnerability_type,
        'routing_info': routing_info,
        'code_subset_package': code_subset_package,
        'vulnerability_knowledge': vulnerability_knowledge or {'profile': {}, 'lessons': []},
        'required_output_schema': {
            'vuln_type': 'string',
            'verdict': 'vulnerable | not_vulnerable',
            'confidence': 0.0,
            'reason': 'string',
            'code_evidence_assessment': {
                'signals_supporting_vulnerable': ['string'],
                'signals_supporting_not_vulnerable': ['string'],
                'uncertain_or_missing_evidence': ['string'],
                'summary': 'string'
            },
            'profile_alignment_assessment': {
                'matched_profile_aspects': ['string'],
                'contradicted_or_missing_profile_aspects': ['string'],
                'false_positive_boundaries_triggered': ['string'],
                'summary': 'string'
            },
            'provisional_code_judgment': {
                'verdict': 'vulnerable | not_vulnerable | inconclusive',
                'reason': 'string'
            },
            'lesson_applicability_assessment': {
                'selected_relevant_lessons': [
                    {
                        'aspect': 'string',
                        'lesson': 'string',
                        'why_selected': 'string'
                    }
                ],
                'num_lessons_reviewed': 0,
                'num_lessons_applied': 0,
                'summary': 'string'
            },
            'knowledge_base_summary': 'string',
            'missed_risk_signals_recovered_from_knowledge': ['string'],
            'provisional_verdict_changed': 'boolean',
            'change_reason': 'string',
            'integration_summary': 'string'
        }
    }
    return [
        {'role': 'system', 'content': system_prompt},
        {'role': 'user', 'content': json.dumps(user_payload, ensure_ascii=False, indent=2)}
    ]
