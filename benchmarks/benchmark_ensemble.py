import importlib
import json
import os
import sys
import time
from pathlib import Path


ASF_PATH = "/Users/alfredo/Projects/agent-security-framework"
sys.path.insert(0, ASF_PATH)
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
BLOCKING_VERDICTS = ("DENY", "KILL_SWITCH", "BLOCK", "HITL")

RESULTS_PATH = Path("benchmarks/ensemble_comparison_results.json")
DEEPSET_PATH = Path("benchmarks/deepset_prompt_injections.json")
OPI_PATH = Path("benchmarks/open_prompt_injection.json")
BENCHMARK_AGENT = "benchmark-agent"
TOOL_NAME = "communication"

SIGIL_V2_BASELINES = {
    "deepset": {"recall": 0.213, "fpr": 0.0},
    "opi": {"recall": 0.535, "fpr": 0.0},
}


def configure_env(disable_stage25, disable_stage25b, skip_llm, always_stage25=False):
    os.environ["ASF_DISABLE_STAGE25"] = "true" if disable_stage25 else "false"
    os.environ["ASF_DISABLE_STAGE25B"] = "true" if disable_stage25b else "false"
    os.environ["ASF_SKIP_LLM"] = "true" if skip_llm else "false"
    os.environ["ASF_ALWAYS_STAGE25"] = "true" if always_stage25 else "false"


def is_injection_label(sample):
    for key in ("label", "is_injection", "type"):
        if key not in sample:
            continue
        label = sample[key]
        if isinstance(label, bool):
            return label
        if isinstance(label, int):
            return label == 1
        normalized = str(label).strip().lower()
        return normalized in ("1", "true", "injection", "injected", "positive")
    raise ValueError(f"No recognized label field: {sample}")


def sample_text(sample):
    for key in ("text", "prompt", "attack_input", "input", "content"):
        value = sample.get(key)
        if isinstance(value, str):
            return value
    raise KeyError(f"No text field found in sample keys: {list(sample.keys())}")


def load_json(path):
    with path.open() as f:
        return json.load(f)


def load_deepset_samples():
    samples = load_json(DEEPSET_PATH)
    limit = int(os.environ.get("DEEPSET_LIMIT", "0"))
    return samples[:limit] if limit else samples


def load_opi_samples():
    samples = load_json(OPI_PATH)
    limit = int(os.environ.get("OPI_LIMIT", "5000"))
    if not limit:
        return samples

    half = limit // 2
    injections = [sample for sample in samples if is_injection_label(sample)]
    benign = [sample for sample in samples if not is_injection_label(sample)]
    return injections[:half] + benign[: limit - half]


def empty_counts():
    return {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "latencies": []}


def update_counts(counts, injection, blocked, latency):
    counts["latencies"].append(latency)
    if injection and blocked:
        counts["tp"] += 1
    elif injection and not blocked:
        counts["fn"] += 1
    elif not injection and blocked:
        counts["fp"] += 1
    else:
        counts["tn"] += 1


def finalize_counts(counts):
    tp = counts["tp"]
    fp = counts["fp"]
    tn = counts["tn"]
    fn = counts["fn"]
    total = tp + fp + tn + fn
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    avg_latency = sum(counts["latencies"]) / len(counts["latencies"]) if counts["latencies"] else None
    return {
        "recall": recall,
        "fpr": fpr,
        "precision": precision,
        "f1": f1,
        "avg_latency_ms": avg_latency,
        "n_samples": total,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }


def static_baseline_metrics(samples, recall, fpr):
    n_injection = sum(1 for sample in samples if is_injection_label(sample))
    n_benign = len(samples) - n_injection
    tp = recall * n_injection
    fn = n_injection - tp
    fp = fpr * n_benign
    tn = n_benign - fp
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "recall": recall,
        "fpr": fpr,
        "precision": precision,
        "f1": f1,
        "avg_latency_ms": None,
        "n_samples": len(samples),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }


def run_config(samples, classify_fn, label):
    counts = empty_counts()
    total = len(samples)
    print(f"\nStarting {label} ({total} samples)")
    for idx, sample in enumerate(samples, start=1):
        text = sample_text(sample)
        t0 = time.time()
        blocked = classify_fn(text)
        update_counts(counts, is_injection_label(sample), blocked, (time.time() - t0) * 1000)
        if idx % 500 == 0 or idx == total:
            print(f"  {label}: {idx}/{total}", flush=True)
    return finalize_counts(counts)


def metric_row(configuration, metrics):
    return {
        "configuration": configuration,
        "recall": round(metrics["recall"], 4),
        "fpr": round(metrics["fpr"], 4),
        "precision": round(metrics["precision"], 4),
        "f1": round(metrics["f1"], 4),
        "avg_latency_ms": round(metrics["avg_latency_ms"], 1) if metrics["avg_latency_ms"] is not None else None,
        "n_samples": metrics["n_samples"],
        "tp": round(metrics["tp"], 3),
        "fp": round(metrics["fp"], 3),
        "tn": round(metrics["tn"], 3),
        "fn": round(metrics["fn"], 3),
    }


def print_table(dataset_name, rows):
    print()
    print(f"=== {dataset_name} ===")
    print(f"{'Configuration':<30} {'Recall':>8} {'FPR':>7} {'Precision':>10} {'F1':>7} {'Lat':>8} {'N':>6}")
    print("-" * 83)
    for row in rows:
        lat = row["avg_latency_ms"]
        lat_str = f"{lat:.1f}ms" if lat is not None else "-"
        print(
            f"{row['configuration']:<30} {row['recall']:>7.1%} {row['fpr']:>6.1%} "
            f"{row['precision']:>9.1%} {row['f1']:>7.3f} {lat_str:>8} {row['n_samples']:>6}"
        )


def reinstate_benchmark_agent():
    registry.reinstate_agent(BENCHMARK_AGENT)


import registry
from hardening import apply_l1_5_hardening
from stage3_onnx import classify_text as onnx_classify_text

registry.add_or_update_agent(BENCHMARK_AGENT, risk_level="high", permissions=[TOOL_NAME])
registry.reinstate_agent(BENCHMARK_AGENT)

import interceptor as imod

imod = importlib.reload(imod)
from interceptor import hardened_interceptor


def classify_l15(text):
    reinstate_benchmark_agent()
    result = apply_l1_5_hardening(BENCHMARK_AGENT, TOOL_NAME, text)
    return result[0] in BLOCKING_VERDICTS


def classify_full(text):
    configure_env(False, False, True)
    reinstate_benchmark_agent()
    result = hardened_interceptor(BENCHMARK_AGENT, TOOL_NAME, text)
    return result[0] in BLOCKING_VERDICTS


def classify_onnx(text):
    return onnx_classify_text(text) in ("DANGEROUS", "UNCERTAIN")


def classify_union(text):
    return classify_l15(text) or classify_onnx(text)


def benchmark_dataset(dataset_key, dataset_name, samples):
    baseline = SIGIL_V2_BASELINES[dataset_key]
    rows = [
        ("Sigil heuristic v2", static_baseline_metrics(samples, baseline["recall"], baseline["fpr"])),
        ("ASF full pipeline", run_config(samples, classify_full, "ASF full pipeline")),
        ("ASF L1.5 + ONNX union", run_config(samples, classify_union, "ASF L1.5 + ONNX union")),
        ("ONNX Prompt Guard 86M", run_config(samples, classify_onnx, "ONNX Prompt Guard 86M")),
        ("ASF L1.5 only", run_config(samples, classify_l15, "ASF L1.5 only")),
    ]
    table_rows = [metric_row(name, metrics) for name, metrics in rows]
    print_table(dataset_name, table_rows)
    return table_rows


def main():
    deepset_samples = load_deepset_samples()
    opi_samples = load_opi_samples()
    print(f"Deepset samples: {len(deepset_samples)}")
    print(f"OPI samples: {len(opi_samples)}")

    results = {
        "deepset": benchmark_dataset("deepset", "deepset/prompt-injections", deepset_samples),
        "opi": benchmark_dataset("opi", "Open Prompt Injection", opi_samples),
    }
    with RESULTS_PATH.open("w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {RESULTS_PATH}")


if __name__ == "__main__":
    main()
