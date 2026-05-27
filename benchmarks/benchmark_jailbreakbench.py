import importlib
import json
import os
import sys
import time
from collections import Counter
from datetime import datetime

from tqdm import tqdm

ASF_PATH = "/Users/alfredo/Projects/agent-security-framework"
DATASET_PATH = "benchmarks/jailbreakbench_behaviors.json"
RESULTS_PATH = "benchmarks/jailbreakbench_results_full.json"
BLOCKING_VERDICTS = ("DENY", "KILL_SWITCH", "BLOCK", "HITL")

sys.path.insert(0, ASF_PATH)
sys.stdout.reconfigure(line_buffering=True)
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

with open(DATASET_PATH) as f:
    samples = json.load(f)

categories = Counter(s["category"] for s in samples)
print(f"Dataset: {len(samples)} samples (all harmful, no benign - recall only)")
print(f"Source: JailbreakBench/JBB-Behaviors (Goal field)")
print(f"Note: all samples are harmful behaviors. FPR cannot be computed.")
print(f"Category distribution:")
for cat, cnt in categories.most_common():
    print(f"  {cat}: {cnt}")

import registry
from stage3_onnx import classify_text as onnx_classify_text

registry.add_or_update_agent("benchmark-agent", risk_level="high", permissions=["communication"])
registry.reinstate_agent("benchmark-agent")


def run_config(samples, classify_fn, label=""):
    tp = fn = 0
    latencies = []
    by_category = Counter()
    detected_by_category = Counter()
    start = datetime.now()
    print(f"\n[{start.strftime('%H:%M:%S')}] Starting: {label} ({len(samples)} samples)")
    for s in tqdm(samples, desc=label, unit="sample", dynamic_ncols=True, file=sys.stdout):
        t0 = time.time()
        blocked = classify_fn(s["text"])
        latencies.append((time.time() - t0) * 1000)
        by_category[s["category"]] += 1
        if blocked:
            tp += 1
            detected_by_category[s["category"]] += 1
        else:
            fn += 1
    end = datetime.now()
    print(f"[{end.strftime('%H:%M:%S')}] Done: {label} in {(end-start).total_seconds():.0f}s")
    recall = tp / (tp + fn) if (tp + fn) else 0
    avg_lat = sum(latencies) / len(latencies) if latencies else 0
    return {
        "tp": tp, "fn": fn, "recall": recall, "avg_latency_ms": avg_lat,
        "n_samples": tp + fn,
        "by_category": {cat: {"detected": detected_by_category[cat], "total": by_category[cat],
                               "recall": detected_by_category[cat] / by_category[cat]}
                        for cat in by_category},
    }


def configure_env(disable_stage25, disable_stage25b, skip_llm, always_stage25=False):
    os.environ["ASF_DISABLE_STAGE25"]  = "true" if disable_stage25  else "false"
    os.environ["ASF_DISABLE_STAGE25B"] = "true" if disable_stage25b else "false"
    os.environ["ASF_SKIP_LLM"]         = "true" if skip_llm         else "false"
    os.environ["ASF_ALWAYS_STAGE25"]   = "true" if always_stage25   else "false"


def reload_interceptor():
    import interceptor as imod
    return importlib.reload(imod)


from hardening import apply_l1_5_hardening

def classify_l15(text):
    registry.reinstate_agent("benchmark-agent")
    return apply_l1_5_hardening("benchmark-agent", "communication", text)[0] in BLOCKING_VERDICTS

import interceptor as imod
imod = importlib.reload(imod)
from interceptor import hardened_interceptor

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


benchmark_rows = [
    ("ASF L1.5 only",         run_config(samples, classify_l15,   label="ASF L1.5 only")),
    ("ASF Stage 1+2",         run_config(samples, classify_s12,   label="ASF Stage 1+2")),
    ("ASF Stage 1+2+2.5",     run_config(samples, classify_s125,  label="ASF Stage 1+2+2.5")),
    ("ASF Always-Stage25",    run_config(samples, classify_always25, label="ASF Always-Stage25")),
    ("ASF Full pipeline",     run_config(samples, classify_full,  label="ASF Full pipeline")),
    ("ONNX Prompt Guard 86M", run_config(samples, classify_onnx,  label="ONNX Prompt Guard 86M")),
]

print()
print("=== Benchmark: JailbreakBench/JBB-Behaviors (recall only) ===")
print(f"Dataset: {len(samples)} samples (all harmful)")
print()
print(f"{'Configuration':<35} {'Recall':>8} {'Detected':>10} {'Lat':>6} {'N':>5}")
print("-" * 65)
for name, m in benchmark_rows:
    lat = f"{m['avg_latency_ms']:.0f}ms"
    print(f"{name:<35} {m['recall']:>7.1%} {m['tp']:>10} {lat:>6} {m['n_samples']:>5}")

print()
print("=== Recall by Category (ASF L1.5) ===")
l15 = benchmark_rows[0][1]
print(f"{'Category':<35} {'Recall':>8} {'Detected':>10} {'Total':>7}")
print("-" * 65)
for cat, v in sorted(l15["by_category"].items()):
    print(f"{cat:<35} {v['recall']:>7.1%} {v['detected']:>10} {v['total']:>7}")

results = {
    "dataset": {"path": DATASET_PATH, "n_samples": len(samples),
                "note": "all harmful - recall only, FPR not applicable",
                "category_distribution": dict(categories)},
    "results": [{"configuration": n, "recall": round(m["recall"], 4),
                 "avg_latency_ms": round(m["avg_latency_ms"], 1),
                 "n_samples": m["n_samples"], "tp": m["tp"], "fn": m["fn"]}
                for n, m in benchmark_rows],
    "by_category_l15": benchmark_rows[0][1]["by_category"],
}
with open(RESULTS_PATH, "w") as f:
    json.dump(results, f, indent=2)
print(f"\nResults saved to {RESULTS_PATH}")
