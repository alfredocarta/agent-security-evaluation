import importlib
import json
import os
import sys
import time
from collections import defaultdict


ASF_PATH = "/Users/alfredo/Projects/agent-security-framework"
DATASET_PATH = "benchmarks/lakera_pint.json"
RESULTS_PATH = "benchmarks/lakera_results.json"
BLOCKING_VERDICTS = ("DENY", "KILL_SWITCH", "BLOCK", "HITL")
INJECTION_LABELS = {"1", "true", "injection", "prompt_injection", "malicious", "dangerous"}


os.environ.setdefault("ASF_STAGE3_BACKEND", "onnx")
sys.path.insert(0, ASF_PATH)


def load_samples():
    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(
            f"{DATASET_PATH} not found. Download Lakera PINT before running this benchmark."
        )
    with open(DATASET_PATH) as f:
        return json.load(f)


def is_injection(label):
    if isinstance(label, bool):
        return label
    if isinstance(label, int):
        return label == 1
    return str(label).strip().lower() in INJECTION_LABELS


def level_value(sample):
    try:
        return int(sample.get("level", 0))
    except (TypeError, ValueError):
        return 0


def run_config(samples, classify_fn):
    tp = fp = tn = fn = 0
    latencies = []
    for sample in samples:
        text = sample["text"]
        t0 = time.time()
        blocked = classify_fn(text)
        latencies.append((time.time() - t0) * 1000)

        injection = is_injection(sample["label"])
        if injection and blocked:
            tp += 1
        elif injection and not blocked:
            fn += 1
        elif not injection and blocked:
            fp += 1
        else:
            tn += 1

    recall = tp / (tp + fn) if tp + fn else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "recall": recall,
        "fpr": fpr,
        "avg_latency_ms": avg_latency,
    }


def count_labels(samples):
    n_inj = sum(1 for sample in samples if is_injection(sample["label"]))
    return n_inj, len(samples) - n_inj


def reinstate_benchmark_agent():
    registry.reinstate_agent("benchmark-agent")


samples = load_samples()
levels = defaultdict(list)
for sample in samples:
    levels[level_value(sample)].append(sample)

print(f"Dataset: {len(samples)} samples")
for level in sorted(levels):
    print(f"  Level {level}: {len(levels[level])} samples")


import registry

registry.add_or_update_agent(
    "benchmark-agent", risk_level="high", permissions=["communication"]
)
registry.reinstate_agent("benchmark-agent")


imod = importlib.import_module("interceptor")
imod = importlib.reload(imod)
from interceptor import hardened_interceptor
from stage3_onnx import classify_text as onnx_classify_text


def classify_asf_full(text):
    reinstate_benchmark_agent()
    result = hardened_interceptor("benchmark-agent", "communication", text)
    return result[0] in BLOCKING_VERDICTS


def classify_onnx(text):
    return onnx_classify_text(text) in ("DANGEROUS", "UNCERTAIN")


rows = []
results = []
for level in (1, 2, 3, 4):
    level_samples = levels.get(level, [])
    n_inj, n_ben = count_labels(level_samples)
    asf = run_config(level_samples, classify_asf_full)
    onnx = run_config(level_samples, classify_onnx)
    rows.append((str(level), n_inj, n_ben, asf, onnx))
    results.append(
        {
            "level": level,
            "n_samples": len(level_samples),
            "n_injection": n_inj,
            "n_benign": n_ben,
            "asf": asf,
            "onnx": onnx,
        }
    )

n_inj, n_ben = count_labels(samples)
asf_all = run_config(samples, classify_asf_full)
onnx_all = run_config(samples, classify_onnx)
rows.append(("ALL", n_inj, n_ben, asf_all, onnx_all))
results.append(
    {
        "level": "ALL",
        "n_samples": len(samples),
        "n_injection": n_inj,
        "n_benign": n_ben,
        "asf": asf_all,
        "onnx": onnx_all,
    }
)


print()
print("=== Lakera PINT Benchmark ===")
print(
    f"{'Level':<6} {'N_inj':>6} {'N_ben':>6} "
    f"{'ASF_recall':>10} {'ASF_fpr':>8} {'ONNX_recall':>11} {'ONNX_fpr':>8}"
)
print("-" * 72)
for level, n_inj, n_ben, asf, onnx in rows:
    print(
        f"{level:<6} {n_inj:>6} {n_ben:>6} "
        f"{asf['recall']:>9.1%} {asf['fpr']:>7.1%} "
        f"{onnx['recall']:>10.1%} {onnx['fpr']:>7.1%}"
    )

with open(RESULTS_PATH, "w") as f:
    json.dump(results, f, indent=2)
print(f"\nResults saved to {RESULTS_PATH}")
