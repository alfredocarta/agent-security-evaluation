import importlib
import json
import os
import sys
import time
from datetime import datetime

from tqdm import tqdm

ASF_PATH = "/Users/alfredo/Projects/agent-security-framework"
DATASET_PATH = "benchmarks/toxic_chat.json"
RESULTS_PATH = "benchmarks/toxic_chat_results_full.json"
BLOCKING_VERDICTS = ("DENY", "KILL_SWITCH", "BLOCK", "HITL")

sys.path.insert(0, ASF_PATH)
sys.stdout.reconfigure(line_buffering=True)
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

with open(DATASET_PATH) as f:
    samples = json.load(f)

toxic_count = sum(1 for s in samples if s["label"] == 1)
benign_count = len(samples) - toxic_count
print(f"Dataset: {len(samples)} samples ({toxic_count} toxic, {benign_count} benign)")
print(f"Source: lmsys/toxic-chat toxicchat0124 (user_input field, toxicity label)")
print(f"Note: tests real-world harmful/toxic user inputs, not synthetic injections")

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


def update_counts(c, toxic, blocked, latency):
    c["latencies"].append(latency)
    if toxic and blocked:       c["tp"] += 1
    elif toxic and not blocked: c["fn"] += 1
    elif not toxic and blocked: c["fp"] += 1
    else:                       c["tn"] += 1


def run_config(samples, classify_fn, label=""):
    counts = empty_counts()
    start = datetime.now()
    print(f"\n[{start.strftime('%H:%M:%S')}] Starting: {label} ({len(samples)} samples)")
    for s in tqdm(samples, desc=label, unit="sample", dynamic_ncols=True, file=sys.stdout):
        t0 = time.time()
        blocked = classify_fn(s["text"])
        update_counts(counts, s["label"] == 1, blocked, (time.time() - t0) * 1000)
    end = datetime.now()
    print(f"[{end.strftime('%H:%M:%S')}] Done: {label} in {(end-start).total_seconds():.0f}s")
    return finalize_counts(counts)


def configure_env(disable_stage25, disable_stage25b, skip_llm):
    os.environ["ASF_DISABLE_STAGE25"]  = "true" if disable_stage25  else "false"
    os.environ["ASF_DISABLE_STAGE25B"] = "true" if disable_stage25b else "false"
    os.environ["ASF_SKIP_LLM"]         = "true" if skip_llm         else "false"


def reload_interceptor():
    import interceptor as imod
    return importlib.reload(imod)


from hardening import apply_l1_5_hardening

def classify_l15(text):
    registry.reinstate_agent("benchmark-agent")
    return apply_l1_5_hardening("benchmark-agent", "communication", text)[0] in BLOCKING_VERDICTS

configure_env(True, True, True)
imod = reload_interceptor()
from interceptor import hardened_interceptor

def classify_s12(text):
    registry.reinstate_agent("benchmark-agent")
    return hardened_interceptor("benchmark-agent", "communication", text)[0] in BLOCKING_VERDICTS

configure_env(False, False, True)
imod = importlib.reload(imod)
from interceptor import hardened_interceptor as hi_s125

def classify_s125(text):
    registry.reinstate_agent("benchmark-agent")
    return hi_s125("benchmark-agent", "communication", text)[0] in BLOCKING_VERDICTS

configure_env(False, False, False)
imod = importlib.reload(imod)
from interceptor import hardened_interceptor as hi_full

def classify_full(text):
    registry.reinstate_agent("benchmark-agent")
    return hi_full("benchmark-agent", "communication", text)[0] in BLOCKING_VERDICTS

def classify_onnx(text):
    return onnx_classify_text(text) in ("DANGEROUS", "UNCERTAIN")


benchmark_rows = [
    ("ASF L1.5 only",         run_config(samples, classify_l15,   label="ASF L1.5 only")),
    ("ASF Stage 1+2",         run_config(samples, classify_s12,   label="ASF Stage 1+2")),
    ("ASF Stage 1+2+2.5",     run_config(samples, classify_s125,  label="ASF Stage 1+2+2.5")),
    ("ASF Full pipeline",     run_config(samples, classify_full,  label="ASF Full pipeline")),
    ("ONNX Prompt Guard 86M", run_config(samples, classify_onnx,  label="ONNX Prompt Guard 86M")),
]

print()
print("=== Benchmark: lmsys/toxic-chat ===")
print(f"Dataset: {len(samples)} samples ({toxic_count} toxic, {benign_count} benign)")
print()
print(f"{'Configuration':<35} {'Recall':>8} {'FPR':>6} {'Precision':>10} {'F1':>6} {'Lat':>6} {'N':>5}")
print("-" * 79)
for name, m in benchmark_rows:
    lat = f"{m['avg_latency_ms']:.0f}ms"
    print(f"{name:<35} {m['recall']:>7.1%} {m['fpr']:>5.1%} {m['precision']:>9.1%} {m['f1']:>6.3f} {lat:>6} {m['n_samples']:>5}")

results = {
    "dataset": {"path": DATASET_PATH, "n_samples": len(samples),
                "n_toxic": toxic_count, "n_benign": benign_count},
    "results": [{"configuration": n, "recall": round(m["recall"], 4), "fpr": round(m["fpr"], 4),
                 "precision": round(m["precision"], 4), "f1": round(m["f1"], 4),
                 "avg_latency_ms": round(m["avg_latency_ms"], 1), "n_samples": m["n_samples"],
                 "tp": m["tp"], "fp": m["fp"], "tn": m["tn"], "fn": m["fn"]}
                for n, m in benchmark_rows],
}
with open(RESULTS_PATH, "w") as f:
    json.dump(results, f, indent=2)
print(f"\nResults saved to {RESULTS_PATH}")
