import os

os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["TRANSFORMERS_OFFLINE"] = "1"

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


ASF_PATH = Path("/Users/alfredo/Projects/agent-security-framework")
DATASET_PATH = Path(__file__).resolve().with_name("open_prompt_injection.json")
TOP_SAMPLE_LIMIT = 20
NON_HEURISTIC_FEATURES = frozenset({"doc_context"})

sys.path.insert(0, str(ASF_PATH))
from hardening import classify_text


def _load_benign_samples() -> list[dict]:
    with DATASET_PATH.open() as f:
        samples = json.load(f)
    return [sample for sample in samples if sample.get("label") == 0]


def _text_preview(text: str, limit: int = 240) -> str:
    preview = " ".join(text.split())
    if len(preview) <= limit:
        return preview
    return preview[: limit - 3] + "..."


def _serializable_features(features: dict) -> dict:
    return {name: float(value) for name, value in sorted(features.items())}


def _active_heuristic_features(features: dict) -> list[str]:
    return [
        name
        for name, value in features.items()
        if name not in NON_HEURISTIC_FEATURES and float(value) > 0.0
    ]


def _empty_group() -> dict:
    return {"n": 0, "fp": 0}


def _finalize_group(group: dict) -> dict:
    n = group["n"]
    fp = group["fp"]
    return {"n": n, "fp": fp, "fpr": fp / n if n else 0.0}


def analyze() -> dict:
    benign_samples = _load_benign_samples()
    by_intent = defaultdict(_empty_group)
    by_feature = Counter()
    fp_samples = []

    for sample in benign_samples:
        intent = sample.get("intent", "")
        by_intent[intent]["n"] += 1

        text = sample["text"]
        result = classify_text(text)
        if not result.blocked:
            continue

        by_intent[intent]["fp"] += 1
        features = _serializable_features(result.features)
        for feature in _active_heuristic_features(features):
            by_feature[feature] += 1

        fp_samples.append(
            {
                "intent": intent,
                "score": float(result.score),
                "features": features,
                "text_preview": _text_preview(text),
            }
        )

    n_benign = len(benign_samples)
    n_fp = len(fp_samples)
    fp_samples.sort(key=lambda sample: sample["score"], reverse=True)

    return {
        "n_benign": n_benign,
        "n_fp": n_fp,
        "fpr": n_fp / n_benign if n_benign else 0.0,
        "by_intent": {
            intent: _finalize_group(group)
            for intent, group in sorted(by_intent.items())
        },
        "by_feature": dict(by_feature.most_common()),
        "top_samples": fp_samples[:TOP_SAMPLE_LIMIT],
    }


def main() -> None:
    json.dump(analyze(), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
