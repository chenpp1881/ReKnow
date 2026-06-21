from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from vulnerability_catalog import resolve_dataset_vulnerability


@dataclass
class DatasetSample:
    sample_id: str
    source_code: str
    original_label: Any
    source_file: str
    target_vulnerability: str
    index_in_file: int


def _normalize_records(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ['data', 'items', 'contracts', 'samples', 'records']:
            value = data.get(key)
            if isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]
        if 'code' in data and 'label' in data:
            return [data]
    return []


def _extract_code(record: Dict[str, Any]) -> str:
    for key in ["source_code", "code", "contract_code"]:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _extract_label(record: Dict[str, Any]) -> Any:
    for key in ["label", "original_label", "target_label"]:
        if key in record:
            return record[key]
    return 1


def _extract_target_vulnerability(record: Dict[str, Any], json_path: Path) -> str:
    for key in ["target_vulnerability", "vulnerability_type", "cwe_id"]:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            try:
                return resolve_dataset_vulnerability(value.strip())
            except KeyError:
                return value.strip()
    return resolve_dataset_vulnerability(json_path.stem)


def _load_json_records(path: Path) -> List[Dict[str, Any]]:
    text = path.read_text(encoding='utf-8').strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        return _normalize_records(data)
    except json.JSONDecodeError:
        pass
    records: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            records.append(obj)
    return records


def load_dataset(dataset_dir: str) -> List[DatasetSample]:
    root = Path(dataset_dir)
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f'Dataset directory not found: {dataset_dir}')
    samples: List[DatasetSample] = []
    for json_path in sorted(root.glob('*.json')):
        try:
            default_target_vulnerability = resolve_dataset_vulnerability(json_path.stem)
        except KeyError:
            continue
        records = _load_json_records(json_path)
        for idx, record in enumerate(records):
            code = _extract_code(record)
            if not code:
                continue
            target_vulnerability = _extract_target_vulnerability(record, json_path)
            if target_vulnerability != default_target_vulnerability:
                target_vulnerability = default_target_vulnerability
            sample_id = str(
                record.get(
                    'sample_id',
                    record.get('id', f'{json_path.stem}_{idx:05d}')
                )
            ).replace('/', '_').replace('\\', '_').replace(' ', '_')
            samples.append(
                DatasetSample(
                    sample_id=sample_id,
                    source_code=code,
                    original_label=_extract_label(record),
                    source_file=json_path.name,
                    target_vulnerability=target_vulnerability,
                    index_in_file=idx,
                )
            )
    return samples
