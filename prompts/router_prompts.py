from __future__ import annotations

import json
from typing import Dict, List


def build_router_messages(contract_code: str, max_candidates: int) -> List[Dict[str, str]]:
    system_prompt = """
You are a smart-contract CWE weakness-category router.
Read the full contract and identify possible weakness categories worth sending to downstream experts.
Do not make final weakness claims. Only produce candidate categories, reasons, suspicious functions, and dangerous signals.
If the contract does not contain credible clues for any allowed weakness category, return an empty candidate_vulnerabilities list.
Return JSON only.
""".strip()
    user_payload = {
        'task': 'Route potential CWE weakness categories from the full contract.',
        'contract_code': contract_code,
        'required_output_schema': {
            'contract_summary': 'string',
            'candidate_vulnerabilities': [
                {
                    'vuln_type': 'string',
                    'risk_score': 0.0,
                    'routing_reason': 'string',
                    'suspicious_functions': ['string'],
                    'dangerous_signals': ['string']
                }
            ]
        },
        'max_candidates': max_candidates,
        'allowed_vulnerability_types': [
            'CWE-20: Improper Input Validation',
            'CWE-266: Incorrect Privilege Assignment',
            'CWE-269: Improper Privilege Management',
            'CWE-284: Improper Access Control',
            'CWE-285: Improper Authorization',
            'CWE-664: Improper Control of a Resource Through its Lifetime',
            'CWE-682: Incorrect Calculation',
            'CWE-691: Insufficient Control Flow Management',
            'CWE-693: Protection Mechanism Failure',
            'CWE-703: Improper Check or Handling of Exceptional Conditions',
            'CWE-710: Improper Adherence to Coding Standards',
            'CWE-754: Improper Check for Unusual or Exceptional Conditions',
            'CWE-755: Improper Handling of Exceptional Conditions',
            'CWE-1041: Use of Redundant Code',
            'CWE-1068: Inconsistency Between Implementation and Documented Design',
            'CWE-1076: Insufficient Adherence to Expected Conventions',
            'CWE-1164: Irrelevant Code',
        ]
    }
    return [
        {'role': 'system', 'content': system_prompt},
        {'role': 'user', 'content': json.dumps(user_payload, ensure_ascii=False, indent=2)}
    ]
