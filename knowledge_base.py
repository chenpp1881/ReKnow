from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

from vulnerability_catalog import VULNERABILITY_ABBREVIATIONS
from vulnerability_knowledge_profiles import VULNERABILITY_KNOWLEDGE_PROFILES


KNOWLEDGE_ASPECTS = [
    'cause',
    'trigger_conditions',
    'typical_code_features',
    'common_scenarios',
    'attack_path',
    'false_positive_boundaries',
]

CODE_ANCHOR_PATTERNS = [
    r'\bmsg\.sender\b',
    r'\btx\.origin\b',
    r'\bonlyowner\b',
    r'\bonlyrole\b',
    r'\brequire\s*\(',
    r'\bmodifier\b',
    r'\bmapping\b',
    r'\bowner\b',
    r'\brole\b',
    r'\bapprove\b',
    r'\ballowance\b',
    r'\btransfer\b',
    r'\bcall\b',
    r'\bdelegatecall\b',
    r'\bsend\b',
    r'\bblock\.',
    r'\btimestamp\b',
    r'\bbalance\b',
    r'\bindex\b',
    r'\barray\b',
    r'\bstorage\b',
    r'\bfunction\b',
    r'\bparameter\b',
    r'\bstate\b',
]

GENERIC_LESSON_PHRASES = [
    'flag as vulnerable when',
    'judge vulnerable when',
    'missing authorization check',
    'missing access control',
    'critical contract state',
    'authorization-related state',
    'sensitive operation',
    'unsafe logic',
    'external call may fail',
    'unchecked external call',
]


def _default_profile(vulnerability_type: str) -> Dict[str, Any]:
    raw = VULNERABILITY_KNOWLEDGE_PROFILES.get(vulnerability_type, {})
    return {
        'overview': str(raw.get('overview', vulnerability_type)).strip() or vulnerability_type,
        'cause': [str(x).strip() for x in raw.get('cause', []) if str(x).strip()],
        'trigger_conditions': [str(x).strip() for x in raw.get('trigger_conditions', []) if str(x).strip()],
        'typical_code_features': [str(x).strip() for x in raw.get('typical_code_features', []) if str(x).strip()],
        'common_scenarios': [str(x).strip() for x in raw.get('common_scenarios', []) if str(x).strip()],
        'attack_path': [str(x).strip() for x in raw.get('attack_path', []) if str(x).strip()],
        'false_positive_boundaries': [str(x).strip() for x in raw.get('false_positive_boundaries', []) if str(x).strip()],
    }


def _empty_bucket(vulnerability_type: str) -> Dict[str, Any]:
    return {
        'profile': _default_profile(vulnerability_type),
        'lessons': [],
    }


def _empty_knowledge_base() -> Dict[str, Any]:
    return {
        'vulnerabilities': {
            vulnerability_type: _empty_bucket(vulnerability_type)
            for vulnerability_type in VULNERABILITY_ABBREVIATIONS
        }
    }


def _normalize_entry(entry: Any) -> Dict[str, str] | None:
    if isinstance(entry, str):
        text = entry.strip()
        if not text:
            return None
        return {
            'lesson': text,
            'aspect': '',
            'applies_when': '',
            'source_sample_id': '',
        }
    if not isinstance(entry, dict):
        return None
    lesson = str(entry.get('lesson', '')).strip()
    if not lesson:
        return None
    aspect = str(entry.get('aspect', '')).strip()
    if aspect and aspect not in KNOWLEDGE_ASPECTS:
        aspect = ''
    applies_when = str(entry.get('applies_when', '')).strip()
    source_sample_id = str(entry.get('source_sample_id', '')).strip()
    return {
        'lesson': lesson,
        'aspect': aspect,
        'applies_when': applies_when,
        'source_sample_id': source_sample_id,
    }


def load_knowledge_base(path: str | Path) -> Dict[str, Any]:
    kb_path = Path(path)
    if not kb_path.exists():
        return _empty_knowledge_base()
    try:
        data = json.loads(kb_path.read_text(encoding='utf-8'))
    except Exception:
        return _empty_knowledge_base()
    if not isinstance(data, dict):
        return _empty_knowledge_base()
    if not isinstance(data.get('vulnerabilities'), dict):
        data['vulnerabilities'] = {}
    return data


def save_knowledge_base(path: str | Path, data: Dict[str, Any]) -> None:
    kb_path = Path(path)
    kb_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')


def ensure_knowledge_base(path: str | Path, reset: bool = False) -> Dict[str, Any]:
    kb_path = Path(path)
    if reset or not kb_path.exists():
        data = _empty_knowledge_base()
        save_knowledge_base(kb_path, data)
        return data
    data = load_knowledge_base(kb_path)
    for vulnerability_type in VULNERABILITY_ABBREVIATIONS:
        bucket = data.setdefault('vulnerabilities', {}).setdefault(vulnerability_type, _empty_bucket(vulnerability_type))
        if not isinstance(bucket, dict):
            data['vulnerabilities'][vulnerability_type] = _empty_bucket(vulnerability_type)
            continue
        bucket.setdefault('profile', _default_profile(vulnerability_type))
        bucket.setdefault('lessons', [])
    save_knowledge_base(kb_path, data)
    return data


def get_vulnerability_knowledge_entries(data: Dict[str, Any], vulnerability_type: str) -> List[Dict[str, str]]:
    vulnerabilities = data.setdefault('vulnerabilities', {})
    bucket = vulnerabilities.setdefault(vulnerability_type, _empty_bucket(vulnerability_type))
    bucket.setdefault('profile', _default_profile(vulnerability_type))
    lessons = bucket.setdefault('lessons', [])
    normalized_entries: List[Dict[str, str]] = []
    seen: set[str] = set()
    for item in lessons:
        entry = _normalize_entry(item)
        if not entry:
            continue
        key = normalize_lesson_key(entry)
        if key in seen:
            continue
        seen.add(key)
        normalized_entries.append(entry)
    bucket['lessons'] = normalized_entries
    return normalized_entries


def get_vulnerability_lessons(data: Dict[str, Any], vulnerability_type: str) -> List[str]:
    return [entry['lesson'] for entry in get_vulnerability_knowledge_entries(data, vulnerability_type)]


def get_vulnerability_lesson_texts(data: Dict[str, Any], vulnerability_type: str) -> List[str]:
    return list(get_vulnerability_lessons(data, vulnerability_type))


def normalize_lesson_text(text: str) -> str:
    return ' '.join(str(text).strip().lower().split())


def normalize_lesson_key(entry: Dict[str, str]) -> str:
    lesson = normalize_lesson_text(entry.get('lesson', ''))
    aspect = normalize_lesson_text(entry.get('aspect', ''))
    applies_when = normalize_lesson_text(entry.get('applies_when', ''))
    return f'{lesson}||{aspect}||{applies_when}'


def _tokenize_for_similarity(text: str) -> set[str]:
    return {
        token
        for token in re.findall(r'[a-z0-9_.]+', normalize_lesson_text(text))
        if len(token) > 2
    }


def _jaccard_similarity(left: str, right: str) -> float:
    left_tokens = _tokenize_for_similarity(left)
    right_tokens = _tokenize_for_similarity(right)
    if not left_tokens or not right_tokens:
        return 0.0
    return len(left_tokens & right_tokens) / len(left_tokens | right_tokens)


def _has_code_anchor(text: str) -> bool:
    normalized = normalize_lesson_text(text)
    return any(re.search(pattern, normalized) for pattern in CODE_ANCHOR_PATTERNS)


def _looks_overly_generic(text: str) -> bool:
    normalized = normalize_lesson_text(text)
    return any(phrase in normalized for phrase in GENERIC_LESSON_PHRASES)


def _profile_entries_for_aspect(profile: Dict[str, Any], aspect: str) -> List[str]:
    if aspect not in KNOWLEDGE_ASPECTS:
        return []
    values = profile.get(aspect, [])
    if not isinstance(values, list):
        return []
    return [str(item).strip() for item in values if str(item).strip()]


def is_high_value_lesson(
    entry: Dict[str, str],
    profile: Dict[str, Any] | None = None,
    existing_lessons: List[Dict[str, str]] | None = None,
) -> bool:
    lesson = str(entry.get('lesson', '')).strip()
    aspect = str(entry.get('aspect', '')).strip()
    applies_when = str(entry.get('applies_when', '')).strip()
    if not lesson or not aspect or not applies_when:
        return False

    combined = f'{lesson} {applies_when}'
    if not _has_code_anchor(combined) and _looks_overly_generic(combined):
        return False

    if len(_tokenize_for_similarity(applies_when)) < 6:
        return False

    profile = profile or {}
    for profile_entry in _profile_entries_for_aspect(profile, aspect):
        if _jaccard_similarity(combined, profile_entry) >= 0.72:
            return False

    for existing in existing_lessons or []:
        existing_combined = f"{existing.get('lesson', '')} {existing.get('applies_when', '')}"
        if _jaccard_similarity(combined, existing_combined) >= 0.88:
            return False

    return True


def get_vulnerability_knowledge_context(data: Dict[str, Any], vulnerability_type: str) -> Dict[str, Any]:
    vulnerabilities = data.setdefault('vulnerabilities', {})
    bucket = vulnerabilities.setdefault(vulnerability_type, _empty_bucket(vulnerability_type))
    profile = bucket.setdefault('profile', _default_profile(vulnerability_type))
    return {
        'profile': profile,
        'lessons': get_vulnerability_knowledge_entries(data, vulnerability_type),
    }


def add_lessons(
    data: Dict[str, Any],
    vulnerability_type: str,
    lessons: List[Dict[str, Any] | str],
) -> List[Dict[str, str]]:
    bucket = data.setdefault('vulnerabilities', {}).setdefault(vulnerability_type, _empty_bucket(vulnerability_type))
    bucket.setdefault('profile', _default_profile(vulnerability_type))
    normalized_existing = get_vulnerability_knowledge_entries(data, vulnerability_type)
    bucket['lessons'] = list(normalized_existing)
    stored_lessons = bucket['lessons']
    existing_keys = {normalize_lesson_key(entry) for entry in stored_lessons}
    added: List[Dict[str, str]] = []
    for lesson in lessons:
        entry = _normalize_entry(lesson)
        if not entry:
            continue
        key = normalize_lesson_key(entry)
        if key in existing_keys:
            continue
        stored_lessons.append(entry)
        existing_keys.add(key)
        added.append(entry)
    bucket['lessons'] = get_vulnerability_knowledge_entries(data, vulnerability_type)
    return added


def replace_lessons(
    data: Dict[str, Any],
    vulnerability_type: str,
    lessons: List[Dict[str, Any] | str],
) -> List[Dict[str, str]]:
    bucket = data.setdefault('vulnerabilities', {}).setdefault(vulnerability_type, _empty_bucket(vulnerability_type))
    bucket.setdefault('profile', _default_profile(vulnerability_type))
    normalized: List[Dict[str, str]] = []
    seen: set[str] = set()
    for lesson in lessons:
        entry = _normalize_entry(lesson)
        if not entry:
            continue
        key = normalize_lesson_key(entry)
        if key in seen:
            continue
        seen.add(key)
        normalized.append(entry)
    bucket['lessons'] = normalized
    return bucket['lessons']
