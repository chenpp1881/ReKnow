## LLM configuration
This project now requires a real API-backed OpenAI-compatible endpoint.
Set `LLM_PROVIDER` to one of `openai`, `deepseek`, or `openai_compatible`, and configure:

The default LLM configuration is used by router, snippet extraction, knowledge summary, and knowledge maintenance.
You can optionally give the judge and reflection agents their own reasoning-model configuration by setting prefixed variables. If a prefixed variable is missing, the agent falls back to the default configuration.

```bash
JUDGE_LLM_PROVIDER=openai_compatible
JUDGE_OPENAI_API_KEY=your_reasoning_model_api_key
JUDGE_OPENAI_BASE_URL=https://your-reasoning-endpoint/v1
JUDGE_LLM_MODEL=your-judge-reasoning-model

REFLECTION_LLM_PROVIDER=openai_compatible
REFLECTION_OPENAI_API_KEY=your_reasoning_model_api_key
REFLECTION_OPENAI_BASE_URL=https://your-reasoning-endpoint/v1
REFLECTION_LLM_MODEL=your-reflection-reasoning-model
```

## Knowledge base
The project maintains an external CWE weakness knowledge base in `knowledge_base.json` by default.
If the file does not exist, it is created automatically and prefilled with all supported CWE weakness categories, each with an empty `lessons` list.

When a dataset sample's `predicted_label` conflicts with its ground-truth `original_label`, the pipeline can:

1. Run a reflection agent on the target CWE weakness category, predicted label, true label, and explanation package.
2. Run a knowledge-summary agent to extract reusable lessons.
3. Write accepted lessons into the target CWE weakness category's section of the knowledge base.
4. After every `KNOWLEDGE_MAINTENANCE_EVERY` newly added lessons for the same CWE weakness category, run a maintenance agent to merge redundancy and clean obvious conflicts.

Only non-duplicate, generalizable, key reusable, non-conflicting lessons should be written.
You can override the file path with `KNOWLEDGE_BASE_PATH`.
You can override the maintenance threshold with `KNOWLEDGE_MAINTENANCE_EVERY` (default: `20`).
Use `--reset-knowledge-base` if you want to clear it before a run.
Use `--no-use-knowledge-base` if you want to disable both reading and writing the knowledge base for a run.
Use `--knowledge-learning-limit-per-file N` if you only want the first `N` samples of each dataset JSON file to trigger reflection and write to the knowledge base. Samples after that still run detection, but skip reflection and knowledge-base updates. The default is `100`.

## Stages
1. LLM router
2. Binary LLM detector
3. Reflection on wrong predictions
4. CWE-specific knowledge-base update

## Dataset format
Place many JSON files when running the reorganized CWE dataset. Each record should contain at least:

```json
{
  "source_code": "pragma solidity ...",
  "original_label": 1,
  "target_vulnerability": "CWE-710: Improper Adherence to Coding Standards"
}
```

## Output format in dataset mode
All results are saved into one JSON file. Each successful result item keeps only:

```json
{
  "sample_id": "xxx",
  "source_code": "...",
  "original_label": 1,
  "target_vulnerability": "CWE-710: Improper Adherence to Coding Standards",
  "predicted_label": 1,
  "judge_vulnerability_types": ["CWE-710: Improper Adherence to Coding Standards"],
  "knowledge_base_updates": [
    {
      "lesson": "Only report coding-standard issues when the inconsistency materially affects readability, reviewability, or implementation clarity rather than being a purely cosmetic preference.",
      "applies_when": "The finding concerns naming, structure, or convention mismatches in a Solidity codebase."
    }
  ]
}
```

The `metrics` field in the output JSON is computed separately for each `target_vulnerability`.

## Run single file
```bash
python main.py -i dataset/contracts/1-blf/BlackFighter/BlackFighter.sol -o single_report.json -p
```

## Run dataset
```bash
python main.py -d dataset/cwe_reorganized -o all_results.json -p
```

## Run only the first N samples from each dataset file
```bash
python main.py -d dataset/cwe_reorganized -n 5 -o smoke_results.json -p
```

## Run only specific dataset JSON files
```bash
python main.py -d dataset/cwe_reorganized -j CWE-710.json -j CWE-284.json -n 5 -o selected_results.json -p
```

## Run with a fresh knowledge base
```bash
python main.py -d dataset/cwe_reorganized -n 5 -r -o smoke_results.json -p
```

## Only let the first N samples of each dataset file update the knowledge base
```bash
python main.py -d dataset/cwe_reorganized -n 300 --knowledge-learning-limit-per-file 100 -o res.json -p
```

## Run without connecting the knowledge base at all
```bash
python main.py -d dataset/cwe_reorganized -n 5 --no-use-knowledge-base -o smoke_results.json -p
```

## Resume from checkpoint
The dataset mode stores `processed_ids` and `failed_samples` in the same output file and writes a checkpoint after every completed or failed sample.
If the run crashes, restarting with the same output file will skip already completed samples and retry unfinished/failed ones.
Use `--force` to rerun all samples.
