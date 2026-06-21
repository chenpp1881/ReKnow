from __future__ import annotations

import json
from typing import Dict, List


def _infer_error_type(predicted_label: int, true_label: int) -> str:
    return 'false_positive' if predicted_label == 1 and true_label == 0 else 'false_negative'


def build_reflection_messages(
    vulnerability_type: str,
    predicted_label: int,
    true_label: int,
    explanation_package: Dict[str, object],
    knowledge_profile: Dict[str, object] | None = None,
) -> List[Dict[str, str]]:
    error_type = _infer_error_type(predicted_label, true_label)
    system_prompt = """
You are a post-hoc audit reflection agent for smart-contract CWE weakness detection.

A binary classifier judged a contract and was wrong.
Your task is not to restate the CWE definition. Your task is to reconstruct the precise
failure mechanism so a future classifier can avoid the same error.

You will receive:
- The CWE weakness type and its base knowledge profile
- The code subset and routing context that was analyzed
- The classifier's predicted label, true label, and stated reason

Analysis steps - perform them in order:
1. Quote the decisive claim(s): identify the specific sentence(s) in the stated reason
   that most directly drove the wrong verdict.
2. Answer the counterfactual:
   - False positive: what guard, constraint, ownership relation, authorization scope,
     or mitigating condition was already present in the code and should have blocked
     the vulnerable verdict?
   - False negative: what concrete exploit-enabling path, missing guard, authority gap,
     or stale-state interaction was present in the code but was dismissed or missed?
3. Classify the primary failure type using exactly one label from this fixed set:
   insufficient_evidence_threshold | ignored_mitigating_condition |
   missed_trigger_pattern | overgeneralized_code_pattern |
   incorrect_boundary_assumption | benign_context_dismissed_risk
4. Identify which aspect of the CWE knowledge profile the failure belongs to:
   cause | trigger_conditions | typical_code_features |
   common_scenarios | attack_path | false_positive_boundaries
5. Decide whether this error supports a reusable lesson at all.
   Set reusable_insight = no when the reflection would only:
   - restate the general CWE definition,
   - say a broad slogan like "missing authorization check" or "unsafe external call,"
   - depend on contract-specific facts that would not transfer,
   - or fail to identify a narrow code-level decision boundary.
   Reusable insight requires BOTH:
   - a concrete, statically observable evidence condition in source code, and
   - a clear decision-boundary correction that would change future judgments on similar code.
6. If reusable_insight = yes, state the corrected decision rule as a single imperative sentence:
   "When [specific evidence condition], judge [verdict] because [reason]."
   The rule must be narrower than the failure: it should close the specific gap that caused
   this error without overcorrecting into the opposite error type.
   - Do not write a rule that would flag all superficially similar code.
   - Do not write a rule that would suppress an entire class of signals.
   - The evidence condition must be observable in the contract source code alone; no reference
     to maintenance practices, developer intent, or deployment context.
   - Prefer rules with explicit boundaries: who can modify which state, which guard is missing
     or present, which path enables exploitation, or which risky-looking pattern is actually made safe.
   - Bad rule example: "Flag functions without authorization checks."
   - Better rule example: "When a function can modify another user's balance, role assignment,
     or approval mapping using caller-controlled parameters and does not verify that the caller
     owns or is authorized for the targeted resource, judge vulnerable because the operation
     permits unauthorized state changes."

If reusable_insight = no, corrected_decision_rule must be an empty string and non_reusable_reason
must explain why this error does not support a reusable lesson.

Every claim must be grounded in the stated reason text and the code subset.
Do not produce generic security advice that is not tied to this specific failure.
Return JSON only.
""".strip()

    user_payload = {
        'task': 'Reconstruct the failure mechanism for this wrong judgment and state the corrected decision rule only if the error supports a reusable lesson.',
        'vulnerability_type': vulnerability_type,
        'predicted_label': predicted_label,
        'true_label': true_label,
        'error_type': error_type,
        'knowledge_profile': knowledge_profile or {},
        'explanation_package': explanation_package,
        'required_output_schema': {
            'vuln_type': 'string',
            'error_type': 'false_positive | false_negative',
            'decisive_claims_in_stated_reason': ['string - direct quotes from the stated reason'],
            'counterfactual': 'string - minimum code/context change that would have produced the correct verdict',
            'failure_type': 'insufficient_evidence_threshold | ignored_mitigating_condition | missed_trigger_pattern | overgeneralized_code_pattern | incorrect_boundary_assumption | benign_context_dismissed_risk',
            'affected_profile_aspect': 'cause | trigger_conditions | typical_code_features | common_scenarios | attack_path | false_positive_boundaries',
            'failure_mechanism': 'string - causal explanation, 2-4 sentences, grounded in the stated reason and code',
            'reusable_insight': 'yes | no',
            'non_reusable_reason': 'string - required when reusable_insight=no, else empty string',
            'corrected_decision_rule': 'string - single imperative: When [statically observable condition], judge [verdict] because [reason]; must close this specific gap without overcorrecting, or empty string if reusable_insight=no',
        }
    }
    return [
        {'role': 'system', 'content': system_prompt},
        {'role': 'user', 'content': json.dumps(user_payload, ensure_ascii=False, indent=2)},
    ]
