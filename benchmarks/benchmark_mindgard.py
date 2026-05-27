import importlib
import json
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime

from tqdm import tqdm

ASF_PATH = "/Users/alfredo/Projects/agent-security-framework"
DATASET_PATH = "benchmarks/mindgard_evaded.json"
RESULTS_PATH = "benchmarks/mindgard_results_full.json"
BLOCKING_VERDICTS = ("DENY", "KILL_SWITCH", "BLOCK", "HITL")

sys.path.insert(0, ASF_PATH)
sys.stdout.reconfigure(line_buffering=True)
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

with open(DATASET_PATH) as f:
    samples = json.load(f)

attack_names = Counter(s["attack_name"] for s in samples)
print(f"Dataset: {len(samples)} samples (all injection - evaded attacks)")
print(f"Source: Mindgard/evaded-prompt-injection-and-jailbreak-samples")
print(f"Attack name distribution (top 10): {dict(attack_names.most_common(10))}")

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


def run_config(samples, text_field, classify_fn, label=""):
    counts = empty_counts()
    by_attack = defaultdict(empty_counts)
    start = datetime.now()
    print(f"\n[{start.strftime('%H:%M:%S')}] Starting: {label} ({len(samples)} samples)")
    for s in tqdm(samples, desc=label, unit="sample", dynamic_ncols=True, file=sys.stdout):
        text = s[text_field]
        t0 = time.time()
        blocked = classify_fn(text)
        lat = (time.time() - t0) * 1000
        update_counts(counts, True, blocked, lat)
        update_counts(by_attack[s["attack_name"]], True, blocked, lat)
    end = datetime.now()
    print(f"[{end.strftime('%H:%M:%S')}] Done: {label} in {(end-start).total_seconds():.0f}s")
    metrics = finalize_counts(counts)
    metrics["by_attack"] = {k: finalize_counts(v) for k, v in by_attack.items()}
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


configs = [
    ("ASF L1.5 only",         classify_l15),
    ("ASF Stage 1+2",         classify_s12),
    ("ASF Stage 1+2+2.5",     classify_s125),
    ("ASF Always-Stage25",    classify_always25),
    ("ASF Full pipeline",     classify_full),
    ("ONNX Prompt Guard 86M", classify_onnx),
    ("ASF L1.5 + ONNX (union)", classify_union),
]

print()
print("=== Pass 1: original_sample (pre-evasion baseline) ===")
orig_rows = [(name, run_config(samples, "original_sample", fn, label=f"{name} [original]"))
             for name, fn in configs]

print()
print("=== Pass 2: modified_sample (adversarially evaded) ===")
evad_rows = [(name, run_config(samples, "modified_sample", fn, label=f"{name} [evaded]"))
             for name, fn in configs]

print()
print("=== Benchmark: Mindgard/evaded-prompt-injection-and-jailbreak-samples ===")
print(f"Dataset: {len(samples)} samples (all injection, recall only)")
print(f"original_sample = pre-evasion text, modified_sample = adversarially evaded text")
print()
print(f"{'Configuration':<35} {'Orig Recall':>12} {'Evad Recall':>12} {'Evasion':>8} {'N':>5}")
print("-" * 75)
for (name, orig_m), (_, evad_m) in zip(orig_rows, evad_rows):
    evasion = orig_m["recall"] - evad_m["recall"]
    print(f"{name:<35} {orig_m['recall']:>11.1%} {evad_m['recall']:>11.1%} {evasion:>+7.1%} {orig_m['n_samples']:>5}")

print()
print("=== By Attack Name (ASF L1.5, original_sample) ===")
l15_orig = orig_rows[0][1]
print(f"{'Attack':<35} {'Orig Recall':>12} {'Evad Recall':>12} {'N':>5}")
print("-" * 70)
l15_evad = evad_rows[0][1]
for atk in sorted(l15_orig["by_attack"], key=lambda x: -l15_orig["by_attack"][x]["n_samples"]):
    mo = l15_orig["by_attack"][atk]
    me = l15_evad["by_attack"].get(atk, {"recall": 0.0, "n_samples": 0})
    print(f"{atk:<35} {mo['recall']:>11.1%} {me['recall']:>11.1%} {mo['n_samples']:>5}")

results = {
    "dataset": {"path": DATASET_PATH, "n_samples": len(samples),
                "attack_name_distribution": dict(attack_names)},
    "original_sample": [
        {"configuration": n, "recall": round(m["recall"], 4),
         "avg_latency_ms": round(m["avg_latency_ms"], 1), "n_samples": m["n_samples"],
         "tp": m["tp"], "fn": m["fn"]}
        for n, m in orig_rows
    ],
    "modified_sample": [
        {"configuration": n, "recall": round(m["recall"], 4),
         "avg_latency_ms": round(m["avg_latency_ms"], 1), "n_samples": m["n_samples"],
         "tp": m["tp"], "fn": m["fn"]}
        for n, m in evad_rows
    ],
    "by_attack_l15_original": {
        k: {"recall": round(v["recall"], 4), "n_samples": v["n_samples"]}
        for k, v in l15_orig["by_attack"].items()
    },
    "by_attack_l15_evaded": {
        k: {"recall": round(v["recall"], 4), "n_samples": v["n_samples"]}
        for k, v in l15_evad["by_attack"].items()
    },
}
with open(RESULTS_PATH, "w") as f:
    json.dump(results, f, indent=2)
print(f"\nResults saved to {RESULTS_PATH}")
