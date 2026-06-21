from __future__ import annotations

from typing import Any, Dict, List


def _safe_div(n: float, d: float) -> float:
    return n / d if d else 0.0


def _normalize_binary_label(label: Any) -> int:
    if isinstance(label, bool):
        return int(label)
    if isinstance(label, (int, float)):
        return 1 if int(label) != 0 else 0
    text = str(label).strip().lower()
    return 1 if text in {'1', 'true', 'vulnerable', 'yes'} else 0


def _compute_binary_metrics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    y_true = [_normalize_binary_label(x['original_label']) for x in results]
    y_pred = [_normalize_binary_label(x['predicted_label']) for x in results]
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    accuracy = _safe_div(tp + tn, len(results))
    return {
        'num_samples': len(results),
        'tp': tp,
        'fp': fp,
        'fn': fn,
        'tn': tn,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'accuracy': accuracy,
    }


def compute_metrics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for item in results:
        vulnerability_type = str(item.get('target_vulnerability', 'UNKNOWN')).strip() or 'UNKNOWN'
        grouped.setdefault(vulnerability_type, []).append(item)

    per_vulnerability = {
        vulnerability_type: _compute_binary_metrics(items)
        for vulnerability_type, items in sorted(grouped.items())
    }

    return {
        'num_vulnerability_types': len(per_vulnerability),
        'per_vulnerability': per_vulnerability,
    }
