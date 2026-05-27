import os
import sys

sys.stdout.reconfigure(line_buffering=True)
os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["TRANSFORMERS_OFFLINE"] = "1"

import json
from collections import Counter, defaultdict
from pathlib import Path

from tqdm import tqdm


ASF_PATH = Path("/Users/alfredo/Projects/agent-security-framework")
REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = REPO_ROOT / "benchmarks" / "open_prompt_injection.json"
OUTPUT_PATH = REPO_ROOT / "benchmarks" / "fps_analysis.json"

sys.path.insert(0, str(ASF_PATH))
from hardening import classify_text


def _sample_text(sample):
    text = sample.get("text")
    if not isinstance(text, str):
        raise KeyError(f"Expected text field in sample: {sample.keys()}")
    return text


def _nonzero_features(features):
    return {
        name: float(value)
        for name, value in features.items()
        if float(value) > 0
    }


def _top_feature(features):
    if not features:
        return "none"
    return max(features.items(), key=lambda item: item[1])[0]


def _feature_combo(features):
    return tuple(sorted(name for name, value in features.items() if float(value) > 0.1))


def _pct(part, whole):
    return (part / whole * 100) if whole else 0.0


def _print_table(title, rows, headers):
    print(f"\n{title}")
    if not rows:
        print("(none)")
        return

    widths = [
        max(len(str(header)), *(len(str(row[idx])) for row in rows))
        for idx, header in enumerate(headers)
    ]
    fmt = "  ".join(f"{{:<{width}}}" for width in widths)
    print(fmt.format(*headers))
    print(fmt.format(*(("-" * width) for width in widths)))
    for row in rows:
        print(fmt.format(*row))


def load_benign_samples():
    with DATASET_PATH.open() as f:
        samples = json.load(f)
    return [sample for sample in samples if sample.get("label") == 0]


def analyze_false_positives(samples):
    fp_samples = []
    totals_by_task = Counter(sample.get("task_type", "") for sample in samples)
    totals_by_intent = Counter(sample.get("intent", "") for sample in samples)

    for sample in tqdm(
        samples,
        desc="Analyzing benign OPI",
        unit="sample",
        dynamic_ncols=True,
        file=sys.stdout,
    ):
        text = _sample_text(sample)
        result = classify_text(text)
        if not result.blocked:
            continue

        features = _nonzero_features(result.features)
        top_feature = _top_feature(features)
        fp_samples.append(
            {
                "text_preview": text[:120],
                "task_type": sample.get("task_type", ""),
                "intent": sample.get("intent", ""),
                "attack_type": sample.get("attack_type", ""),
                "score": float(result.score),
                "top_feature": top_feature,
                "features": features,
                "reason": result.reason,
            }
        )

    return fp_samples, totals_by_task, totals_by_intent


def print_summary(fp_samples, total_benign, totals_by_task):
    total_fp = len(fp_samples)
    by_top_feature = Counter(sample["top_feature"] for sample in fp_samples)
    by_task_type = Counter(sample["task_type"] for sample in fp_samples)
    combos = Counter(_feature_combo(sample["features"]) for sample in fp_samples)

    print("\nSummary")
    print(f"Total benign samples: {total_benign}")
    print(f"Total FPs found: {total_fp}")
    print(f"FPR: {total_fp / total_benign:.4f} ({_pct(total_fp, total_benign):.2f}%)")

    _print_table(
        "Top-firing feature",
        [
            (feature, count, f"{_pct(count, total_fp):.2f}%")
            for feature, count in by_top_feature.most_common()
        ],
        ("feature", "fp_count", "pct_of_fps"),
    )

    _print_table(
        "Task type",
        [
            (
                task_type,
                count,
                totals_by_task[task_type],
                f"{count / totals_by_task[task_type]:.4f}",
            )
            for task_type, count in by_task_type.most_common()
        ],
        ("task_type", "fp_count", "total", "fpr"),
    )

    _print_table(
        "Top 10 feature combinations (>0.1)",
        [
            ("+".join(combo) if combo else "(none)", count)
            for combo, count in combos.most_common(10)
        ],
        ("features", "count"),
    )

    examples_by_feature = defaultdict(list)
    for sample in fp_samples:
        examples_by_feature[sample["top_feature"]].append(sample)

    print("\nRepresentative examples by top-firing feature")
    for feature, count in by_top_feature.most_common():
        print(f"\n[{feature}] {count} FPs")
        for sample in examples_by_feature[feature][:10]:
            text = sample["text_preview"][:80].replace("\n", "\\n")
            features = ", ".join(
                f"{name}={value:.2f}"
                for name, value in sorted(
                    sample["features"].items(),
                    key=lambda item: item[1],
                    reverse=True,
                )
            )
            print(f"- score={sample['score']:.3f} features=({features}) text={text!r}")


def build_output(fp_samples, total_benign, totals_by_task, totals_by_intent):
    total_fp = len(fp_samples)
    by_top_feature_counts = Counter(sample["top_feature"] for sample in fp_samples)
    by_task_fp = Counter(sample["task_type"] for sample in fp_samples)
    by_intent_fp = Counter(sample["intent"] for sample in fp_samples)

    return {
        "total_benign": total_benign,
        "total_fp": total_fp,
        "fpr": total_fp / total_benign if total_benign else 0.0,
        "by_top_feature": {
            feature: {
                "count": count,
                "pct_of_fps": count / total_fp if total_fp else 0.0,
            }
            for feature, count in by_top_feature_counts.most_common()
        },
        "by_task_type": {
            task_type: {
                "fp": by_task_fp[task_type],
                "total": total,
                "fpr": by_task_fp[task_type] / total if total else 0.0,
            }
            for task_type, total in sorted(totals_by_task.items())
        },
        "by_intent": {
            intent: {
                "fp": by_intent_fp[intent],
                "total": total,
                "fpr": by_intent_fp[intent] / total if total else 0.0,
            }
            for intent, total in sorted(totals_by_intent.items())
        },
        "fp_samples": fp_samples,
    }


def main():
    benign_samples = load_benign_samples()
    print(f"Loaded {len(benign_samples)} benign samples from {DATASET_PATH}")

    fp_samples, totals_by_task, totals_by_intent = analyze_false_positives(benign_samples)
    print_summary(fp_samples, len(benign_samples), totals_by_task)

    output = build_output(fp_samples, len(benign_samples), totals_by_task, totals_by_intent)
    with OUTPUT_PATH.open("w") as f:
        json.dump(output, f, indent=2, sort_keys=True)
    print(f"\nSaved full FP analysis to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
