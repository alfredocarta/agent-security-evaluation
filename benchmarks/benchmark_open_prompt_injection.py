import importlib
import json
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime

from tqdm import tqdm


ASF_PATH = "/Users/alfredo/Projects/agent-security-framework"
DATASET_PATH = "benchmarks/open_prompt_injection.json"
RESULTS_PATH = "benchmarks/open_prompt_injection_results_full.json"
BLOCKING_VERDICTS = ("DENY", "KILL_SWITCH", "BLOCK", "HITL")
INJECTION_LABELS = {"1", "true", "injection", "prompt_injection", "malicious", "dangerous"}
BENIGN_LABELS = {"0", "false", "benign", "safe", "legitimate", "normal"}
FULL_PIPELINE_LIMIT = 0
DEFAULT_EVAL_LIMIT = 100


sys.path.insert(0, ASF_PATH)
sys.stdout.reconfigure(line_buffering=True)
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")


def load_samples():
    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(
            f"{DATASET_PATH} not found. Download Open Prompt Injection before running."
        )
    with open(DATASET_PATH) as f:
        return json.load(f)


def sample_text(sample):
    for key in ("text", "prompt", "attack_input", "input", "content"):
        value = sample.get(key)
        if isinstance(value, str):
            return value
    raise KeyError(f"No text field found in sample keys: {list(sample.keys())}")


def is_injection(sample):
    for key in ("label", "is_injection", "type"):
        if key not in sample:
            continue
        label = sample[key]
        if isinstance(label, bool):
            return label
        if isinstance(label, int):
            return label == 1
        normalized = str(label).strip().lower()
        if normalized in INJECTION_LABELS:
            return True
        if normalized in BENIGN_LABELS:
            return False
    raise ValueError(f"No recognized label field in sample: {sample}")


def intent_value(sample):
    return (
        sample.get("intent")
        or sample.get("injected_task")
        or sample.get("attack_intent")
        or sample.get("attack_type")
        or ""
    )


def attack_type_value(sample):
    return sample.get("attack_type") or sample.get("type") or ""


def empty_counts():
    return {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "latencies": []}


def finalize_counts(counts):
    tp = counts["tp"]
    fp = counts["fp"]
    tn = counts["tn"]
    fn = counts["fn"]
    latencies = counts["latencies"]
    total = tp + fp + tn + fn
    recall = tp / (tp + fn) if (tp + fn) else 0
    fpr = fp / (fp + tn) if (fp + tn) else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "recall": recall,
        "fpr": fpr,
        "precision": precision,
        "f1": f1,
        "avg_latency_ms": avg_latency,
        "n_samples": total,
    }


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


def run_config(samples, classify_fn, max_samples=None, group_fn=None, label=""):
    if max_samples:
        samples = samples[:max_samples]

    counts = empty_counts()
    grouped = defaultdict(empty_counts)
    start = datetime.now()
    print(f"\n[{start.strftime('%H:%M:%S')}] Starting: {label} ({len(samples)} samples)")
    for sample in tqdm(samples, desc=label, unit="sample", dynamic_ncols=True, file=sys.stdout):
        text = sample_text(sample)
        t0 = time.time()
        blocked = classify_fn(text)
        latency = (time.time() - t0) * 1000

        injection = is_injection(sample)
        update_counts(counts, injection, blocked, latency)
        if group_fn:
            group = group_fn(sample)
            if group:
                update_counts(grouped[group], injection, blocked, latency)

    end = datetime.now()
    elapsed = (end - start).total_seconds()
    print(f"[{end.strftime('%H:%M:%S')}] Done: {label} in {elapsed:.0f}s")
    metrics = finalize_counts(counts)
    if group_fn:
        metrics["by_group"] = {
            group: finalize_counts(group_counts)
            for group, group_counts in grouped.items()
        }
    return metrics


def configure_env(disable_stage25, disable_stage25b, skip_llm, stage3_backend="llm"):
    os.environ["ASF_DISABLE_STAGE25"] = "true" if disable_stage25 else "false"
    os.environ["ASF_DISABLE_STAGE25B"] = "true" if disable_stage25b else "false"
    os.environ["ASF_SKIP_LLM"] = "true" if skip_llm else "false"
    os.environ["ASF_STAGE3_BACKEND"] = stage3_backend


def reload_interceptor():
    import interceptor as imod

    return importlib.reload(imod)


def count_labels(samples):
    injections = sum(1 for sample in samples if is_injection(sample))
    return injections, len(samples) - injections


def balanced_subset(samples, limit):
    if not limit or len(samples) <= limit:
        return samples

    buckets = defaultdict(list)
    for sample in samples:
        buckets[(intent_value(sample), is_injection(sample))].append(sample)

    selected = []
    bucket_values = list(buckets.values())
    while len(selected) < limit and bucket_values:
        next_round = []
        for bucket in bucket_values:
            if bucket and len(selected) < limit:
                selected.append(bucket.pop(0))
            if bucket:
                next_round.append(bucket)
        bucket_values = next_round
    return selected


def metric_row(name, metrics):
    return {
        "configuration": name,
        "recall": round(metrics["recall"], 4),
        "fpr": round(metrics["fpr"], 4),
        "precision": round(metrics["precision"], 4),
        "f1": round(metrics["f1"], 4),
        "avg_latency_ms": round(metrics["avg_latency_ms"], 1),
        "n_samples": metrics["n_samples"],
        "tp": metrics["tp"],
        "fp": metrics["fp"],
        "tn": metrics["tn"],
        "fn": metrics["fn"],
    }


def print_row(name, metrics):
    lat = metrics.get("avg_latency_ms")
    lat_str = f"{lat:.0f}ms" if lat else "-"
    print(
        f"{name:<35} {metrics['recall']:>7.1%} {metrics['fpr']:>5.1%} "
        f"{metrics['precision']:>9.1%} {metrics['f1']:>6.3f} {lat_str:>6} "
        f"{metrics['n_samples']:>5}"
    )


def reinstate_benchmark_agent():
    registry.reinstate_agent("benchmark-agent")


samples = load_samples()
eval_limit = int(os.environ.get("OPI_EVAL_SAMPLE_LIMIT", str(DEFAULT_EVAL_LIMIT)))
eval_samples = balanced_subset(samples, eval_limit)
injection_count, benign_count = count_labels(samples)
eval_injection_count, eval_benign_count = count_labels(eval_samples)
intent_counts = Counter(intent_value(sample) for sample in samples if intent_value(sample))
attack_type_counts = Counter(
    attack_type_value(sample) for sample in samples if attack_type_value(sample)
)

print(
    f"Dataset: {len(samples)} samples "
    f"({injection_count} injection, {benign_count} benign)"
)
if len(eval_samples) != len(samples):
    print(
        f"Evaluation subset: {len(eval_samples)} samples "
        f"({eval_injection_count} injection, {eval_benign_count} benign)"
    )
if intent_counts:
    print("Intent distribution:")
    for intent, count in intent_counts.most_common():
        print(f"  {intent}: {count}")
if attack_type_counts:
    print("Attack type distribution:")
    for attack_type, count in attack_type_counts.most_common():
        print(f"  {attack_type}: {count}")


import registry

registry.add_or_update_agent(
    "benchmark-agent", risk_level="high", permissions=["communication"]
)
registry.reinstate_agent("benchmark-agent")


from hardening import apply_l1_5_hardening
from stage3_onnx import classify_text as onnx_classify_text


def classify_l15(text):
    reinstate_benchmark_agent()
    result = apply_l1_5_hardening("benchmark-agent", "communication", text)
    return result[0] in BLOCKING_VERDICTS


configure_env(disable_stage25=True, disable_stage25b=True, skip_llm=True)
imod = reload_interceptor()
from interceptor import hardened_interceptor


def classify_s12(text):
    reinstate_benchmark_agent()
    result = hardened_interceptor("benchmark-agent", "communication", text)
    return result[0] in BLOCKING_VERDICTS


configure_env(disable_stage25=False, disable_stage25b=False, skip_llm=True)
imod = importlib.reload(imod)
from interceptor import hardened_interceptor as hi_s125


def classify_s125(text):
    reinstate_benchmark_agent()
    result = hi_s125("benchmark-agent", "communication", text)
    return result[0] in BLOCKING_VERDICTS


configure_env(disable_stage25=False, disable_stage25b=False, skip_llm=False)
imod = importlib.reload(imod)
from interceptor import hardened_interceptor as hi_full


def classify_full(text):
    reinstate_benchmark_agent()
    result = hi_full("benchmark-agent", "communication", text)
    return result[0] in BLOCKING_VERDICTS


def classify_onnx(text):
    return onnx_classify_text(text) in ("DANGEROUS", "UNCERTAIN")


baseline_rows = [
    (
        "Sigil heuristic v1 (OPI, peer)",
        {
            "recall": 0.458,
            "fpr": 0.0,
            "precision": 1.0,
            "f1": 0.628,
            "avg_latency_ms": 1.1,
            "n_samples": 67200,
        },
    ),
    (
        "Sigil heuristic v2 (OPI, peer)",
        {
            "recall": 0.535,
            "fpr": 0.0,
            "precision": 1.0,
            "f1": 0.697,
            "avg_latency_ms": 1.1,
            "n_samples": 67200,
        },
    ),
    (
        "ONNX Prompt Guard 86M (Sigil run, OPI)",
        {
            "recall": 0.523,
            "fpr": 0.001,
            "precision": 0.997,
            "f1": 0.686,
            "avg_latency_ms": None,
            "n_samples": 67200,
        },
    ),
]

benchmark_rows = [
    ("ASF L1.5 only", run_config(eval_samples, classify_l15, group_fn=intent_value, label="ASF L1.5 only")),
    ("ASF Stage 1+2", run_config(eval_samples, classify_s12, group_fn=intent_value, label="ASF Stage 1+2")),
    ("ASF Stage 1+2+2.5", run_config(eval_samples, classify_s125, group_fn=intent_value, label="ASF Stage 1+2+2.5")),
    (
        "ASF Full pipeline",
        run_config(eval_samples, classify_full, max_samples=FULL_PIPELINE_LIMIT, label="ASF Full pipeline"),
    ),
    ("ONNX Prompt Guard 86M", run_config(eval_samples, classify_onnx, group_fn=intent_value, label="ONNX Prompt Guard 86M")),
]

print()
print("=== Independent Benchmark: Open Prompt Injection ===")
print(f"Dataset: {len(samples)} samples ({injection_count} injection, {benign_count} benign)")
if len(eval_samples) != len(samples):
    print(
        f"Evaluation subset: {len(eval_samples)} samples "
        f"({eval_injection_count} injection, {eval_benign_count} benign)"
    )
print()
print(
    f"{'Configuration':<35} {'Recall':>8} {'FPR':>6} "
    f"{'Precision':>10} {'F1':>6} {'Lat':>6} {'N':>5}"
)
print("-" * 79)
for name, metrics in baseline_rows + benchmark_rows:
    print_row(name, metrics)

grouped_results = defaultdict(list)
if intent_counts:
    print()
    print("=== Results by Intent ===")
    print(
        f"{'Intent':<16} {'Configuration':<25} {'Recall':>8} {'FPR':>6} "
        f"{'Precision':>10} {'F1':>6} {'N':>5}"
    )
    print("-" * 86)
    for intent in sorted(intent_counts):
        for name, config_metrics in benchmark_rows:
            if name == "ASF Full pipeline":
                continue
            metrics = config_metrics.get("by_group", {}).get(intent)
            if not metrics:
                continue
            grouped_results[intent].append(metric_row(name, metrics))
            print(
                f"{intent:<16} {name:<25} {metrics['recall']:>7.1%} "
                f"{metrics['fpr']:>5.1%} {metrics['precision']:>9.1%} "
                f"{metrics['f1']:>6.3f} {metrics['n_samples']:>5}"
            )

results = {
    "dataset": {
        "path": DATASET_PATH,
        "n_samples": len(samples),
        "n_injection": injection_count,
        "n_benign": benign_count,
        "evaluation_n_samples": len(eval_samples),
        "evaluation_n_injection": eval_injection_count,
        "evaluation_n_benign": eval_benign_count,
        "evaluation_limit": eval_limit,
        "intent_distribution": dict(intent_counts),
        "attack_type_distribution": dict(attack_type_counts),
    },
    "baselines": [
        {
            "configuration": name,
            "recall": metrics["recall"],
            "fpr": metrics["fpr"],
            "precision": metrics["precision"],
            "f1": metrics["f1"],
            "avg_latency_ms": metrics["avg_latency_ms"],
            "n_samples": metrics["n_samples"],
        }
        for name, metrics in baseline_rows
    ],
    "results": [metric_row(name, metrics) for name, metrics in benchmark_rows],
    "by_intent": dict(grouped_results),
}

with open(RESULTS_PATH, "w") as f:
    json.dump(results, f, indent=2)
print(f"\nResults saved to {RESULTS_PATH}")
