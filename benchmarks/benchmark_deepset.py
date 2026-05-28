import importlib
import json
import os
import sys
import time
from datetime import datetime

from tqdm import tqdm

ASF_PATH = "/Users/alfredo/Projects/agent-security-framework"
BLOCKING_VERDICTS = ("DENY", "KILL_SWITCH", "BLOCK", "HITL")
RESULTS_PATH = "benchmarks/deepset_results_full.json"

sys.path.insert(0, ASF_PATH)
sys.stdout.reconfigure(line_buffering=True)
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")


with open("benchmarks/deepset_prompt_injections.json") as f:
    samples = json.load(f)

injections = [s for s in samples if s["label"] == 1]
benigns = [s for s in samples if s["label"] == 0]
print(
    f"Dataset: {len(samples)} samples "
    f"({len(injections)} injection, {len(benigns)} benign)"
)


def run_config(samples, classify_fn, label=""):
    tp = fp = tn = fn = 0
    latencies = []
    start = datetime.now()
    print(f"\n[{start.strftime('%H:%M:%S')}] Starting: {label} ({len(samples)} samples)")
    for s in tqdm(samples, desc=label, unit="sample", dynamic_ncols=True, file=sys.stdout):
        registry.reinstate_agent("benchmark-agent")
        t0 = time.time()
        blocked = classify_fn(s["text"])
        latencies.append((time.time() - t0) * 1000)
        is_injection = s["label"] == 1
        if is_injection and blocked:
            tp += 1
        elif is_injection and not blocked:
            fn += 1
        elif not is_injection and blocked:
            fp += 1
        else:
            tn += 1
    end = datetime.now()
    elapsed = (end - start).total_seconds()
    print(f"[{end.strftime('%H:%M:%S')}] Done: {label} in {elapsed:.0f}s")
    total = tp + fp + tn + fn
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    return recall, fpr, precision, f1, avg_latency, total


def configure_env(disable_stage25, skip_llm, always_stage25=False):
    os.environ["ASF_DISABLE_STAGE25"]  = "true" if disable_stage25  else "false"
    os.environ["ASF_SKIP_LLM"]         = "true" if skip_llm         else "false"
    os.environ["ASF_ALWAYS_STAGE25"]   = "true" if always_stage25   else "false"


def reload_interceptor():
    import interceptor as imod

    return importlib.reload(imod)


import registry
from stage3_onnx import classify_text as onnx_classify_text

registry.add_or_update_agent(
    "benchmark-agent", risk_level="high", permissions=["communication"]
)
registry.reinstate_agent("benchmark-agent")


from hardening import apply_l1_5_hardening

imod = reload_interceptor()
from interceptor import hardened_interceptor


def classify_l15(text):
    result = apply_l1_5_hardening("benchmark-agent", "communication", text)
    return result[0] in BLOCKING_VERDICTS


def classify_s12(text):
    configure_env(disable_stage25=True, skip_llm=True)
    result = hardened_interceptor("benchmark-agent", "communication", text)
    return result[0] in BLOCKING_VERDICTS


def classify_s125(text):
    configure_env(disable_stage25=False, skip_llm=True)
    result = hardened_interceptor("benchmark-agent", "communication", text)
    return result[0] in BLOCKING_VERDICTS


def classify_full(text):
    configure_env(disable_stage25=False, skip_llm=False)
    result = hardened_interceptor("benchmark-agent", "communication", text)
    return result[0] in BLOCKING_VERDICTS


def classify_always25(text):
    configure_env(disable_stage25=False, skip_llm=True, always_stage25=True)
    result = hardened_interceptor("benchmark-agent", "communication", text)
    return result[0] in BLOCKING_VERDICTS


def classify_onnx(text):
    return onnx_classify_text(text) in ("DANGEROUS", "UNCERTAIN")


def classify_union(text):
    return classify_l15(text) or classify_onnx(text)


configs = [
    ("Sigil heuristic-only (peer baseline)", 0.213, 0.0, 1.0, 0.351, None, len(samples)),
    ("ASF L1.5 only",      *run_config(samples, classify_l15,      label="ASF L1.5 only")),
    ("ASF Stage 1+2",      *run_config(samples, classify_s12,      label="ASF Stage 1+2")),
    ("ASF Stage 1+2+2.5",  *run_config(samples, classify_s125,     label="ASF Stage 1+2+2.5")),
    ("ASF Always-Stage25", *run_config(samples, classify_always25, label="ASF Always-Stage25")),
    ("ASF Full pipeline",  *run_config(samples, classify_full,     label="ASF Full pipeline")),
    ("ONNX Prompt Guard 86M", *run_config(samples, classify_onnx,  label="ONNX Prompt Guard 86M")),
    ("ASF L1.5 + ONNX (union)", *run_config(samples, classify_union, label="ASF L1.5 + ONNX (union)")),
]

print()
print("=== Independent Benchmark: deepset/prompt-injections ===")
print(
    f"{'Configuration':<35} {'Recall':>8} {'FPR':>6} "
    f"{'Prec':>7} {'F1':>7} {'Lat':>8} {'N':>5}"
)
print("-" * 80)
for row in configs:
    name, recall, fpr, prec, f1, lat, n = row
    lat_str = f"{lat:.0f}ms" if lat else "-"
    print(
        f"{name:<35} {recall:>7.1%} {fpr:>5.1%} "
        f"{prec:>6.1%} {f1:>6.3f} {lat_str:>8} {n:>5}"
    )

results = []
for row in configs:
    name, recall, fpr, prec, f1, lat, n = row
    results.append(
        {
            "configuration": name,
            "recall": round(recall, 4),
            "fpr": round(fpr, 4),
            "precision": round(prec, 4),
            "f1": round(f1, 4),
            "avg_latency_ms": round(lat, 1) if lat else None,
            "n_samples": n,
        }
    )
with open(RESULTS_PATH, "w") as f:
    json.dump(results, f, indent=2)
print(f"\nResults saved to {RESULTS_PATH}")
