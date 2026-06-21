from __future__ import annotations

import argparse
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List

try:
    from tqdm import tqdm
except Exception:
    tqdm = None

from agents.judge_agent import JudgeAgent
from agents.knowledge_maintenance_agent import KnowledgeMaintenanceAgent
from agents.knowledge_summary_agent import KnowledgeSummaryAgent
from agents.reflection_agent import ReflectionAgent
from agents.router_agent import RouterAgent
from agents.snippet_agent import SnippetAgent
from dataset_loader import DatasetSample, load_dataset
from knowledge_base import add_lessons, ensure_knowledge_base, get_vulnerability_knowledge_context, get_vulnerability_knowledge_entries, is_high_value_lesson, load_knowledge_base, replace_lessons, save_knowledge_base
from llm_client import load_project_env
from metrics import compute_metrics
from vulnerability_catalog import normalize_vulnerability_name

load_project_env()


def _maintenance_threshold() -> int:
    return max(1, int(os.environ.get('KNOWLEDGE_MAINTENANCE_EVERY', '20')))


def _predict_any_vulnerability(findings: List[Dict[str, Any]]) -> int:
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        judge_payload = finding.get('judge', {})
        verdict = str(judge_payload.get('verdict', '')).strip().lower()
        if verdict == 'vulnerable':
            return 1
    return 0


def _has_meaningful_candidate_clues(candidate: Dict[str, Any]) -> bool:
    if not isinstance(candidate, dict):
        return False
    vuln_type = str(candidate.get('vuln_type', '')).strip()
    if not vuln_type:
        return False
    risk_score = candidate.get('risk_score')
    routing_reason = str(candidate.get('routing_reason', '')).strip()
    suspicious_functions = candidate.get('suspicious_functions', [])
    dangerous_signals = candidate.get('dangerous_signals', [])
    if isinstance(risk_score, (int, float)) and float(risk_score) > 0:
        return True
    if routing_reason:
        return True
    if isinstance(suspicious_functions, list) and any(str(item).strip() for item in suspicious_functions):
        return True
    if isinstance(dangerous_signals, list) and any(str(item).strip() for item in dangerous_signals):
        return True
    return False


def _has_meaningful_code_subset(snippet_package: Dict[str, Any]) -> bool:
    if not isinstance(snippet_package, dict):
        return False
    code_subset = str(snippet_package.get('code_subset', '')).strip()
    return bool(code_subset)


def _build_reflection_context(report: Dict[str, Any], target_vulnerability: str) -> Dict[str, Any]:
    target_key = normalize_vulnerability_name(target_vulnerability)
    target_finding: Dict[str, Any] | None = None
    for finding in report.get('findings', []):
        judge_payload = finding.get('judge', {}) if isinstance(finding, dict) else {}
        vuln_type = str(judge_payload.get('vuln_type') or finding.get('vuln_type') or '').strip()
        if normalize_vulnerability_name(vuln_type) == target_key:
            target_finding = finding
            break
    target_judge = target_finding.get('judge', {}) if isinstance(target_finding, dict) else {}
    return {
        'router_output': report.get('router_output', {}),
        'target_finding': target_finding or {},
        'target_prediction': {
            'vuln_type': str(target_judge.get('vuln_type', '')).strip(),
            'verdict': str(target_judge.get('verdict', '')).strip(),
            'reason': str(target_judge.get('reason', '')).strip(),
            'confidence': target_judge.get('confidence'),
        },
    }


def _attach_lesson_metadata(
    lessons: List[Dict[str, Any]],
    sample_id: str,
) -> List[Dict[str, Any]]:
    enriched: List[Dict[str, Any]] = []
    for lesson in lessons:
        if not isinstance(lesson, dict):
            continue
        enriched.append({
            **lesson,
            'source_sample_id': str(lesson.get('source_sample_id', '')).strip() or sample_id,
        })
    return enriched


def _filter_high_value_lessons(
    lessons: List[Dict[str, Any]],
    knowledge_profile: Dict[str, Any],
    existing_lessons: List[Dict[str, str]],
) -> List[Dict[str, Any]]:
    filtered: List[Dict[str, Any]] = []
    for lesson in lessons:
        if not isinstance(lesson, dict):
            continue
        if not str(lesson.get('lesson', '')).strip():
            continue
        if is_high_value_lesson(lesson, profile=knowledge_profile, existing_lessons=existing_lessons + filtered):
            filtered.append(lesson)
    return filtered


def _maybe_reflect_and_update_knowledge_base(
    sample_result: Dict[str, Any],
    report: Dict[str, Any],
    knowledge_base: Dict[str, Any],
    knowledge_base_path: Path,
    maintenance_counters: Dict[str, int],
) -> List[Dict[str, str]]:
    sample_id = str(sample_result.get('sample_id', 'unknown'))
    predicted_label = int(sample_result['predicted_label'])
    true_label = 1 if str(sample_result['original_label']).strip().lower() in {'1', 'true', 'vulnerable', 'yes'} else 0
    if predicted_label == true_label:
        return []

    target_vulnerability = str(sample_result['target_vulnerability'])
    reflection_context = _build_reflection_context(report, target_vulnerability)
    knowledge_context = get_vulnerability_knowledge_context(knowledge_base, target_vulnerability)
    existing_lessons = knowledge_context['lessons']

    reflection_agent = ReflectionAgent()
    reflection = reflection_agent.reflect(
        vulnerability_type=target_vulnerability,
        predicted_label=predicted_label,
        true_label=true_label,
        explanation_package=reflection_context,
        knowledge_profile=knowledge_context['profile'],
    ).parsed

    summary_agent = KnowledgeSummaryAgent()
    summary = summary_agent.summarize(
        vulnerability_type=target_vulnerability,
        reflection_result=reflection,
        knowledge_profile=knowledge_context['profile'],
        existing_lessons=existing_lessons,
    ).parsed

    accepted = summary.get('accepted_lessons', [])
    filtered = _filter_high_value_lessons(
        [lesson for lesson in accepted if isinstance(lesson, dict)],
        knowledge_profile=knowledge_context['profile'],
        existing_lessons=existing_lessons,
    )
    filtered = _attach_lesson_metadata(
        filtered,
        sample_id=sample_id,
    )
    added = add_lessons(
        knowledge_base,
        vulnerability_type=target_vulnerability,
        lessons=filtered,
    )
    if added:
        maintenance_counters[target_vulnerability] = maintenance_counters.get(target_vulnerability, 0) + len(added)
        threshold = _maintenance_threshold()
        if maintenance_counters[target_vulnerability] >= threshold:
            maintenance_agent = KnowledgeMaintenanceAgent()
            current_lessons = get_vulnerability_knowledge_entries(knowledge_base, target_vulnerability)
            maintenance = maintenance_agent.maintain(
                vulnerability_type=target_vulnerability,
                existing_lessons=current_lessons,
                recently_added_lessons=added,
            ).parsed
            final_lessons = maintenance.get('final_lessons', [])
            if isinstance(final_lessons, list):
                replace_lessons(
                    knowledge_base,
                    vulnerability_type=target_vulnerability,
                    lessons=[item for item in final_lessons if isinstance(item, dict)],
                )
            maintenance_counters[target_vulnerability] = 0
        save_knowledge_base(knowledge_base_path, knowledge_base)
    return added


def _build_direct_candidate(vulnerability_type: str) -> Dict[str, Any]:
    return {
        'vuln_type': vulnerability_type,
        'risk_score': None,
        'routing_reason': 'Router skipped; using the current target CWE weakness category directly.',
        'suspicious_functions': [],
        'dangerous_signals': [],
    }


def run_pipeline_from_code(
    code: str,
    knowledge_base: Dict[str, Any] | None = None,
    forced_vulnerability_type: str | None = None,
    use_knowledge_base: bool = True,
) -> Dict[str, Any]:
    kb = knowledge_base or {'vulnerabilities': {}}
    snippet_agent = SnippetAgent()
    if forced_vulnerability_type:
        routed = {
            'contract_summary': 'Router skipped; target CWE weakness category supplied externally.',
            'candidate_vulnerabilities': [_build_direct_candidate(forced_vulnerability_type)],
            'router_skipped': True,
        }
        candidates = routed['candidate_vulnerabilities']
    else:
        router = RouterAgent()
        max_candidates = max(1, int(os.environ.get('ROUTER_MAX_CANDIDATES', '6')))
        routed = router.route(code, max_candidates=max_candidates).parsed
        raw_candidates = routed.get('candidate_vulnerabilities', [])
        candidates = [
            candidate for candidate in raw_candidates
            if _has_meaningful_candidate_clues(candidate)
        ]
        routed['candidate_vulnerabilities'] = candidates
    findings: List[Dict[str, Any]] = [None] * len(candidates)
    expert_workers = max(1, int(os.environ.get('EXPERT_MAX_WORKERS', '4')))
    judge_agent = JudgeAgent()

    def _process_candidate(index: int, candidate: Dict[str, Any]) -> tuple[int, Dict[str, Any]]:
        vuln_type = candidate['vuln_type']
        vulnerability_knowledge = get_vulnerability_knowledge_context(kb, vuln_type) if use_knowledge_base else {'profile': {}, 'lessons': []}
        snippet_package = snippet_agent.extract(vuln_type, candidate, code, knowledge_profile=vulnerability_knowledge.get('profile')).parsed
        if not _has_meaningful_code_subset(snippet_package):
            return index, {
                'vuln_type': vuln_type,
                'routing': candidate,
                'code_subset_package': snippet_package,
                'judge': {},
            }
        judgment = judge_agent.decide(
            vuln_type,
            snippet_package,
            candidate,
            vulnerability_knowledge=vulnerability_knowledge,
        ).parsed
        return index, {
            'vuln_type': vuln_type,
            'routing': candidate,
            'code_subset_package': snippet_package,
            'judge': judgment,
        }

    if candidates:
        with ThreadPoolExecutor(max_workers=min(expert_workers, len(candidates))) as executor:
            futures = [executor.submit(_process_candidate, i, cand) for i, cand in enumerate(candidates)]
            for future in as_completed(futures):
                idx, item = future.result()
                findings[idx] = item

    findings = [
        x for x in findings
        if x is not None and _has_meaningful_code_subset(x.get('code_subset_package', {}))
    ]
    return {'router_output': routed, 'findings': findings}


def run_pipeline_for_sample(
    sample: DatasetSample,
    knowledge_base: Dict[str, Any] | None = None,
    skip_router_for_target: bool = False,
    use_knowledge_base: bool = True,
) -> Dict[str, Any]:
    if skip_router_for_target:
        report = run_pipeline_from_code(
            sample.source_code,
            knowledge_base=knowledge_base,
            forced_vulnerability_type=sample.target_vulnerability,
            use_knowledge_base=use_knowledge_base,
        )
    else:
        report = run_pipeline_from_code(
            sample.source_code,
            knowledge_base=knowledge_base,
            use_knowledge_base=use_knowledge_base,
        )
    findings = report.get('findings', [])
    router_candidates = report.get('router_output', {}).get('candidate_vulnerabilities', [])
    if not router_candidates or not findings:
        predicted_label = 0
        prediction_source = 'no_findings'
    else:
        predicted_label = _predict_any_vulnerability(findings)
        prediction_source = 'judge'
    return {
        'result': {
            'sample_id': sample.sample_id,
            'source_code': sample.source_code,
            'original_label': sample.original_label,
            'target_vulnerability': sample.target_vulnerability,
            'predicted_label': predicted_label,
            'prediction_source': prediction_source,
            'judge_vulnerability_types': _collect_judge_vulnerability_types(report.get('findings', [])),
        },
        'report': report,
    }


def _load_existing_output(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {'results': [], 'failed_samples': [], 'metrics': {}}
    try:
        payload = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(payload, dict):
            return {'results': [], 'failed_samples': [], 'metrics': {}}
        payload.setdefault('results', [])
        payload.setdefault('failed_samples', [])
        payload.setdefault('metrics', {})
        return payload
    except Exception:
        return {'results': [], 'failed_samples': [], 'metrics': {}}


def _write_checkpoint(
    output_file: Path,
    results: List[Dict[str, Any]],
    processed_ids: set[str],
    failed_samples: List[Dict[str, Any]],
) -> None:
    payload = {
        'results': results,
        'failed_samples': failed_samples,
        'metrics': compute_metrics(results),
    }
    temp_path = output_file.with_suffix(output_file.suffix + '.tmp')
    temp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
    temp_path.replace(output_file)


def _collect_judge_vulnerability_types(findings: List[Dict[str, Any]]) -> List[str]:
    vuln_types: List[str] = []
    for finding in findings:
        judge_payload = finding.get('judge', {}) if isinstance(finding, dict) else {}
        vuln_type = str(judge_payload.get('vuln_type') or finding.get('vuln_type') or '').strip()
        if vuln_type and vuln_type not in vuln_types:
            vuln_types.append(vuln_type)
    return vuln_types


def _process_sample_with_context(
    sample: DatasetSample,
    knowledge_base: Dict[str, Any],
    skip_router_for_target: bool,
    use_knowledge_base: bool,
) -> Dict[str, Any]:
    return run_pipeline_for_sample(
        sample,
        knowledge_base=knowledge_base,
        skip_router_for_target=skip_router_for_target,
        use_knowledge_base=use_knowledge_base,
    )


def _run_sample_batch(
    batch_samples: List[DatasetSample],
    sample_workers: int,
    knowledge_base_path: Path,
    use_knowledge_base: bool,
    skip_router_for_target: bool,
    knowledge_learning_limit_per_file: int | None,
    knowledge_base: Dict[str, Any],
    maintenance_counters: Dict[str, int],
    results: List[Dict[str, Any]],
    processed_ids: set[str],
    failed_samples: List[Dict[str, Any]],
    output_file: Path,
    progress: Any = None,
) -> List[Dict[str, Any]]:
    if not batch_samples:
        return failed_samples
    with ThreadPoolExecutor(max_workers=min(sample_workers, len(batch_samples))) as executor:
        knowledge_snapshot = load_knowledge_base(knowledge_base_path) if use_knowledge_base else {'vulnerabilities': {}}
        future_to_sample = {
            executor.submit(_process_sample_with_context, sample, knowledge_snapshot, skip_router_for_target, use_knowledge_base): sample
            for sample in batch_samples
        }
        for future in as_completed(future_to_sample):
            sample = future_to_sample[future]
            try:
                payload = future.result()
                item = payload['result']
                report = payload['report']
                added_lessons: List[Dict[str, str]] = []
                should_learn_knowledge = (
                    use_knowledge_base
                    and (
                        knowledge_learning_limit_per_file is None
                        or sample.index_in_file < knowledge_learning_limit_per_file
                    )
                )
                if should_learn_knowledge:
                    added_lessons = _maybe_reflect_and_update_knowledge_base(
                        item,
                        report,
                        knowledge_base,
                        knowledge_base_path,
                        maintenance_counters,
                    )
                if added_lessons:
                    item['knowledge_base_updates'] = added_lessons
                results.append(item)
                processed_ids.add(sample.sample_id)
                failed_samples = [
                    x for x in failed_samples
                    if str(x.get('sample_id', '')) != sample.sample_id
                ]
            except Exception as exc:
                error_text = str(exc).strip() or exc.__class__.__name__
                failed_samples = [
                    x for x in failed_samples
                    if str(x.get('sample_id', '')) != sample.sample_id
                ]
                failed_samples.append({
                    'sample_id': sample.sample_id,
                    'source_file': sample.source_file,
                    'target_vulnerability': sample.target_vulnerability,
                    'error': error_text,
                })
            if progress is not None:
                progress.update(1)
            _write_checkpoint(output_file, results, processed_ids, failed_samples)
    return failed_samples


def run_dataset(
    dataset_dir: str,
    output_path: str,
    force: bool = False,
    limit_per_file: int | None = None,
    skip_first_per_file: int = 0,
    knowledge_learning_limit_per_file: int | None = None,
    reset_knowledge_base: bool = False,
    skip_router_for_target: bool = False,
    dataset_files: List[str] | None = None,
    use_knowledge_base: bool = True,
) -> Dict[str, Any]:
    samples = load_dataset(dataset_dir)
    if limit_per_file is not None and limit_per_file <= 0:
        limit_per_file = None
    output_file = Path(output_path)
    knowledge_base_path = Path(os.environ.get('KNOWLEDGE_BASE_PATH', 'knowledge_base.json'))
    knowledge_base = ensure_knowledge_base(knowledge_base_path, reset=reset_knowledge_base) if use_knowledge_base else {'vulnerabilities': {}}
    existing = _load_existing_output(output_file)
    results = existing.get('results', []) if not force else []
    processed_ids = (
        {
            str(item.get('sample_id', '')).strip()
            for item in results
            if isinstance(item, dict) and str(item.get('sample_id', '')).strip()
        }
        if not force else set()
    )
    failed_samples = existing.get('failed_samples', []) if not force else []

    grouped: Dict[str, List[DatasetSample]] = {}
    for sample in samples:
        grouped.setdefault(sample.source_file, []).append(sample)

    if dataset_files:
        selected_names = {
            name if name.endswith('.json') else f'{name}.json'
            for name in dataset_files
            if str(name).strip()
        }
        grouped = {name: grouped[name] for name in sorted(grouped) if name in selected_names}
        if not grouped:
            raise SystemExit(f'No dataset JSON files matched: {sorted(selected_names)}')

    sample_workers = max(1, int(os.environ.get('SAMPLE_MAX_WORKERS', '4')))
    progress_print_every = max(1, int(os.environ.get('PROGRESS_PRINT_EVERY', '10')))
    maintenance_counters: Dict[str, int] = {}
    for source_file in sorted(grouped):
        group_samples = grouped[source_file]
        if skip_first_per_file > 0:
            group_samples = group_samples[skip_first_per_file:]
        if limit_per_file is not None:
            group_samples = group_samples[:limit_per_file]
        pending = [s for s in group_samples if force or s.sample_id not in processed_ids]
        progress = tqdm(total=len(group_samples), desc=f'Evaluating {source_file}', unit='sample') if tqdm is not None else None
        skipped = len(group_samples) - len(pending)
        if progress is not None and skipped:
            progress.update(skipped)
        if progress is None:
            print(f'Evaluating {source_file} ({len(group_samples)} samples)...')
        if pending:
            failed_samples = _run_sample_batch(
                batch_samples=pending,
                sample_workers=sample_workers,
                knowledge_base_path=knowledge_base_path,
                use_knowledge_base=use_knowledge_base,
                skip_router_for_target=skip_router_for_target,
                knowledge_learning_limit_per_file=knowledge_learning_limit_per_file,
                knowledge_base=knowledge_base,
                maintenance_counters=maintenance_counters,
                results=results,
                processed_ids=processed_ids,
                failed_samples=failed_samples,
                output_file=output_file,
                progress=progress,
            )
        retry_pending = [
            sample for sample in group_samples
            if sample.sample_id not in processed_ids
            and any(
                str(item.get('sample_id', '')) == sample.sample_id and str(item.get('source_file', '')) == source_file
                for item in failed_samples
            )
        ]
        if progress is not None:
            progress.close()
        if retry_pending:
            retry_progress = tqdm(total=len(retry_pending), desc=f'Retrying {source_file}', unit='sample') if tqdm is not None else None
            failed_samples = _run_sample_batch(
                batch_samples=retry_pending,
                sample_workers=sample_workers,
                knowledge_base_path=knowledge_base_path,
                use_knowledge_base=use_knowledge_base,
                skip_router_for_target=skip_router_for_target,
                knowledge_learning_limit_per_file=knowledge_learning_limit_per_file,
                knowledge_base=knowledge_base,
                maintenance_counters=maintenance_counters,
                results=results,
                processed_ids=processed_ids,
                failed_samples=failed_samples,
                output_file=output_file,
                progress=retry_progress,
            )
            if retry_progress is not None:
                retry_progress.close()

    final_output = {
        'results': results,
        'failed_samples': failed_samples,
        'metrics': compute_metrics(results),
    }
    _write_checkpoint(output_file, results, processed_ids, failed_samples)
    return final_output


def run_single(
    input_path: str,
    output_path: str,
    pretty: bool,
    target_vulnerability: str | None = None,
    skip_router_for_target: bool = False,
    use_knowledge_base: bool = True,
) -> Dict[str, Any]:
    code = Path(input_path).read_text(encoding='utf-8')
    knowledge_base_path = Path(os.environ.get('KNOWLEDGE_BASE_PATH', 'knowledge_base.json'))
    forced_vulnerability_type = target_vulnerability if skip_router_for_target else None
    report = run_pipeline_from_code(
        code,
        knowledge_base=ensure_knowledge_base(knowledge_base_path) if use_knowledge_base else {'vulnerabilities': {}},
        forced_vulnerability_type=forced_vulnerability_type,
        use_knowledge_base=use_knowledge_base,
    )
    Path(output_path).write_text(json.dumps(report, ensure_ascii=False, indent=2 if pretty else None), encoding='utf-8')
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description='Pure-LLM smart contract CWE weakness audit pipeline')
    parser.add_argument('-i', '--input', help='Path to a single Solidity contract file')
    parser.add_argument('-d', '--dataset', default='dataset', help='Path to dataset directory containing JSON files with code and label fields')
    parser.add_argument('-o', '--output', default='res.json', help='Output JSON path')
    parser.add_argument('-p', '--pretty', action='store_true', help='Pretty print JSON')
    parser.add_argument('-f', '--force', action='store_true', help='Ignore saved processed ids and rerun dataset samples')
    parser.add_argument('-n', '--limit-per-file', default=0, type=int, help='Only evaluate the first N samples from each dataset file; use 0 for no limit')
    parser.add_argument('--skip-first-per-file', default=0, type=int, help='Skip the first N samples from each dataset file before evaluation')
    parser.add_argument('--knowledge-learning-limit-per-file', default=100, type=int, help='Only allow reflection and knowledge-base writing on the first N samples of each dataset file; later samples skip reflection (default: 100)')
    parser.add_argument('-r', '--reset-knowledge-base', action='store_true', help='Reset the external knowledge base before running')
    parser.add_argument('-s', '--skip-router-for-target', action='store_true', help='Skip routing and directly analyze the current target CWE weakness category')
    parser.add_argument('-t', '--target-vulnerability', help='Target CWE weakness category name for single-file runs when router is skipped')
    parser.add_argument('-j', '--dataset-json', action='append', help='Only run the specified dataset JSON file(s), e.g. -j CWE-710.json or -j CWE-284 -j CWE-703')
    parser.add_argument('--use-knowledge-base', dest='use_knowledge_base', action=argparse.BooleanOptionalAction, default=True, help='Whether to read from and connect the external knowledge base during judging (default: enabled)')
    args = parser.parse_args()
    if bool(args.input) == bool(args.dataset):
        raise SystemExit('Please provide exactly one of --input or --dataset.')
    if args.skip_router_for_target and args.input and not args.target_vulnerability:
        raise SystemExit('When using --skip-router-for-target with --input, you must also provide --target-vulnerability.')
    if args.input:
        run_single(
            args.input,
            args.output,
            args.pretty,
            target_vulnerability=args.target_vulnerability,
            skip_router_for_target=args.skip_router_for_target,
            use_knowledge_base=args.use_knowledge_base,
        )
    else:
        run_dataset(
            args.dataset,
            args.output,
            force=args.force,
            limit_per_file=args.limit_per_file,
            skip_first_per_file=args.skip_first_per_file,
            knowledge_learning_limit_per_file=args.knowledge_learning_limit_per_file,
            reset_knowledge_base=args.reset_knowledge_base,
            skip_router_for_target=args.skip_router_for_target,
            dataset_files=args.dataset_json,
            use_knowledge_base=args.use_knowledge_base,
        )
    print(f'Report written to {args.output}')


if __name__ == '__main__':
    main()
