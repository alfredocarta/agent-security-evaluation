import importlib
import json
import os
import sys
import time


ASF_PATH = "/Users/alfredo/Projects/agent-security-framework"
BLOCKING_VERDICTS = ("DENY", "KILL_SWITCH", "BLOCK", "HITL")

sys.path.insert(0, ASF_PATH)


with open("benchmarks/deepset_prompt_injections.json") as f:
    samples = json.load(f)

injections = [s for s in samples if s["label"] == 1]
benigns = [s for s in samples if s["label"] == 0]
print(
    f"Dataset: {len(samples)} samples "
    f"({len(injections)} injection, {len(benigns)} benign)"
)


def run_config(samples, classify_fn, max_samples=None):
    if max_samples:
        samples = samples[:max_samples]
    tp = fp = tn = fn = 0
    latencies = []
    for s in samples:
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
    total = tp + fp + tn + fn
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    return recall, fpr, precision, f1, avg_latency, total


def configure_env(disable_stage25, skip_llm):
    os.environ["ASF_DISABLE_STAGE25"] = "true" if disable_stage25 else "false"
    os.environ["ASF_SKIP_LLM"] = "true" if skip_llm else "false"


def reload_interceptor():
    import interceptor as imod

    return importlib.reload(imod)


import registry

registry.add_or_update_agent(
    "benchmark-agent", risk_level="high", permissions=["communication"]
)
registry.reinstate_agent("benchmark-agent")


from hardening import apply_l1_5_hardening


def classify_l15(text):
    result = apply_l1_5_hardening("benchmark-agent", "communication", text)
    return result[0] in BLOCKING_VERDICTS


configure_env(disable_stage25=True, skip_llm=True)
imod = reload_interceptor()
from interceptor import hardened_interceptor


def classify_s12(text):
    result = hardened_interceptor("benchmark-agent", "communication", text)
    return result[0] in BLOCKING_VERDICTS


configure_env(disable_stage25=False, skip_llm=True)
imod = importlib.reload(imod)
from interceptor import hardened_interceptor as hi_s125


def classify_s125(text):
    result = hi_s125("benchmark-agent", "communication", text)
    return result[0] in BLOCKING_VERDICTS


configure_env(disable_stage25=False, skip_llm=False)
imod = importlib.reload(imod)
from interceptor import hardened_interceptor as hi_full


def classify_full(text):
    result = hi_full("benchmark-agent", "communication", text)
    return result[0] in BLOCKING_VERDICTS


configs = [
    ("Sigil heuristic-only (peer baseline)", 0.213, 0.0, 1.0, 0.351, None, 546),
    ("ASF L1.5 only", *run_config(samples, classify_l15)),
    ("ASF Stage 1+2", *run_config(samples, classify_s12)),
    ("ASF Stage 1+2+2.5", *run_config(samples, classify_s125)),
    ("ASF Full pipeline", *run_config(samples[:100], classify_full, max_samples=100)),
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
with open("benchmarks/deepset_results.json", "w") as f:
    json.dump(results, f, indent=2)
print("\nResults saved to benchmarks/deepset_results.json")
