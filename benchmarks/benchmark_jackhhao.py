import importlib
import json
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime

from tqdm import tqdm

ASF_PATH = os.environ.get("ASF_ROOT")
if not ASF_PATH:
    raise RuntimeError("ERROR: ASF_ROOT must be set to import ASF modules. Example:\nASF_ROOT=/path/to/agent-security-framework python -m suite --target asf")
DATASET_PATH = "benchmarks/jackhhao_jailbreak.json"
RESULTS_PATH = "benchmarks/jackhhao_results_full.json"
BLOCKING_VERDICTS = ("DENY", "KILL_SWITCH", "BLOCK", "HITL")

sys.path.insert(0, ASF_PATH)
sys.stdout.reconfigure(line_buffering=True)
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

with open(DATASET_PATH) as f:
    samples = json.load(f)

injection_count = sum(1 for s in samples if s["label"] == 1)
benign_count = len(samples) - injection_count
types = Counter(s["type"] for s in samples)

print(f"Dataset: {len(samples)} samples ({injection_count} injection, {benign_count} benign)")
print(f"Source: jackhhao/jailbreak-classification")
print(f"Type distribution: {dict(types.most_common(10))}")

import registry
from stage3_onnx import classify_text as onnx_classify_text

registry.add_or_update_agent("benchmark-agent", risk_level="high", permissions=["communication"])
registry.reinstate_agent("benchmark-agent")


def empty_counts():
    return {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "latencies": []}


def finalize_counts(c):
    tp, fp, tn, fn = c["tp"], c["fp"], c["tn"], c["fn"]
    total = tp + fp + tn + fn
    recall    = tp / (tp + fn) if (tp + fn) else 0
    fpr       = fp / (fp + tn) if (fp + tn) else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    avg_lat   = sum(c["latencies"]) / len(c["latencies"]) if c["latencies"] else 0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "recall": recall, "fpr": fpr,
            "precision": precision, "f1": f1, "avg_latency_ms": avg_lat, "n_samples": total}


def update_counts(c, injection, blocked, latency):
    c["latencies"].append(latency)
    if injection and blocked:       c["tp"] += 1
    elif injection and not blocked: c["fn"] += 1
    elif not injection and blocked: c["fp"] += 1
    else:                           c["tn"] += 1


def run_config(samples, classify_fn, label=""):
    counts = empty_counts()
    by_type = defaultdict(empty_counts)
    start = datetime.now()
    print(f"\n[{start.strftime('%H:%M:%S')}] Starting: {label} ({len(samples)} samples)")
    for s in tqdm(samples, desc=label, unit="sample", dynamic_ncols=True, file=sys.stdout):
        t0 = time.time()
        blocked = classify_fn(s["text"])
        lat = (time.time() - t0) * 1000
        inj = s["label"] == 1
        update_counts(counts, inj, blocked, lat)
        update_counts(by_type[s["type"]], inj, blocked, lat)
    end = datetime.now()
    print(f"[{end.strftime('%H:%M:%S')}] Done: {label} in {(end-start).total_seconds():.0f}s")
    metrics = finalize_counts(counts)
    metrics["by_type"] = {k: finalize_counts(v) for k, v in by_type.items()}
    return metrics


def configure_env(disable_stage25, disable_stage25b, skip_llm, always_stage25=False):
    os.environ["ASF_DISABLE_STAGE25"]  = "true" if disable_stage25  else "false"
    os.environ["ASF_DISABLE_STAGE25B"] = "true" if disable_stage25b else "false"
    os.environ["ASF_SKIP_LLM"]         = "true" if skip_llm         else "false"
    os.environ["ASF_ALWAYS_STAGE25"]   = "true" if always_stage25   else "false"


from hardening import apply_l1_5_hardening

import interceptor as imod
imod = importlib.reload(imod)
from interceptor import hardened_interceptor

def classify_l15(text):
    registry.reinstate_agent("benchmark-agent")
    return apply_l1_5_hardening("benchmark-agent", "communication", text)[0] in BLOCKING_VERDICTS

def classify_s12(text):
    configure_env(True, True, True)
    registry.reinstate_agent("benchmark-agent")
    return hardened_interceptor("benchmark-agent", "communication", text)[0] in BLOCKING_VERDICTS

def classify_s125(text):
    configure_env(False, False, True)
    registry.reinstate_agent("benchmark-agent")
    return hardened_interceptor("benchmark-agent", "communication", text)[0] in BLOCKING_VERDICTS

def classify_full(text):
    configure_env(False, False, False)
    registry.reinstate_agent("benchmark-agent")
    return hardened_interceptor("benchmark-agent", "communication", text)[0] in BLOCKING_VERDICTS

def classify_always25(text):
    configure_env(False, False, True, always_stage25=True)
    registry.reinstate_agent("benchmark-agent")
    return hardened_interceptor("benchmark-agent", "communication", text)[0] in BLOCKING_VERDICTS

def classify_onnx(text):
    return onnx_classify_text(text) in ("DANGEROUS", "UNCERTAIN")


def classify_union(text):
    return classify_l15(text) or classify_onnx(text)


benchmark_rows = [
    ("ASF L1.5 only",         run_config(samples, classify_l15,     label="ASF L1.5 only")),
    ("ASF Stage 1+2",         run_config(samples, classify_s12,     label="ASF Stage 1+2")),
    ("ASF Stage 1+2+2.5",     run_config(samples, classify_s125,    label="ASF Stage 1+2+2.5")),
    ("ASF Always-Stage25",    run_config(samples, classify_always25, label="ASF Always-Stage25")),
    ("ASF Full pipeline",     run_config(samples, classify_full,    label="ASF Full pipeline")),
    ("ONNX Prompt Guard 86M", run_config(samples, classify_onnx,    label="ONNX Prompt Guard 86M")),
    ("ASF L1.5 + ONNX (union)", run_config(samples, classify_union, label="ASF L1.5 + ONNX (union)")),
]

print()
print("=== Benchmark: jackhhao/jailbreak-classification ===")
print(f"Dataset: {len(samples)} samples ({injection_count} injection, {benign_count} benign)")
print()
print(f"{'Configuration':<35} {'Recall':>8} {'FPR':>6} {'Precision':>10} {'F1':>6} {'Lat':>6} {'N':>5}")
print("-" * 79)
for name, m in benchmark_rows:
    lat = f"{m['avg_latency_ms']:.0f}ms"
    print(f"{name:<35} {m['recall']:>7.1%} {m['fpr']:>5.1%} {m['precision']:>9.1%} {m['f1']:>6.3f} {lat:>6} {m['n_samples']:>5}")

print()
print("=== Results by Type (ASF L1.5) ===")
l15 = benchmark_rows[0][1]
print(f"{'Type':<30} {'Recall':>8} {'FPR':>6} {'F1':>6} {'N':>5}")
print("-" * 55)
for t in sorted(l15["by_type"], key=lambda x: -l15["by_type"][x]["n_samples"]):
    m = l15["by_type"][t]
    print(f"{t:<30} {m['recall']:>7.1%} {m['fpr']:>5.1%} {m['f1']:>6.3f} {m['n_samples']:>5}")

results = {
    "dataset": {"path": DATASET_PATH, "n_samples": len(samples),
                "n_injection": injection_count, "n_benign": benign_count,
                "type_distribution": dict(types)},
    "results": [{"configuration": n, "recall": round(m["recall"], 4), "fpr": round(m["fpr"], 4),
                 "precision": round(m["precision"], 4), "f1": round(m["f1"], 4),
                 "avg_latency_ms": round(m["avg_latency_ms"], 1), "n_samples": m["n_samples"],
                 "tp": m["tp"], "fp": m["fp"], "tn": m["tn"], "fn": m["fn"]}
                for n, m in benchmark_rows],
    "by_type_l15": {k: {"recall": round(v["recall"], 4), "fpr": round(v["fpr"], 4),
                        "f1": round(v["f1"], 4), "n_samples": v["n_samples"]}
                    for k, v in l15["by_type"].items()},
}
with open(RESULTS_PATH, "w") as f:
    json.dump(results, f, indent=2)
print(f"\nResults saved to {RESULTS_PATH}")
