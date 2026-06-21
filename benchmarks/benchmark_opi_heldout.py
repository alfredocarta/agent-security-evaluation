"""
Benchmark Open Prompt Injection — partizione held-out (sample_id % 5 == 0).

Il fine-tuning di DeBERTa ha usato i campioni con sample_id % 5 != 0 (~80%).
Questo script usa solo la partizione complementare (sample_id % 5 == 0, ~20%),
che non è mai stata vista in training, per un confronto corretto tra tutte
le configurazioni.

Esecuzione:
    /Users/alfredo/miniconda3/envs/eval-framework/bin/python3 \
        benchmarks/benchmark_opi_heldout.py
"""

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
RESULTS_PATH = "benchmarks/opi_heldout_results.json"
BLOCKING_VERDICTS = ("DENY", "KILL_SWITCH", "BLOCK", "HITL")
INJECTION_LABELS = {"1", "true", "injection", "prompt_injection", "malicious", "dangerous"}
BENIGN_LABELS = {"0", "false", "benign", "safe", "legitimate", "normal"}

sys.path.insert(0, ASF_PATH)
sys.stdout.reconfigure(line_buffering=True)
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")


def load_samples():
    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(
            f"{DATASET_PATH} non trovato. Scarica Open Prompt Injection prima di eseguire."
        )
    with open(DATASET_PATH) as f:
        return json.load(f)


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
    raise ValueError(f"Nessun campo label riconosciuto nel campione: {sample}")


def sample_text(sample):
    for key in ("text", "prompt", "attack_input", "input", "content"):
        value = sample.get(key)
        if isinstance(value, str):
            return value
    raise KeyError(f"Nessun campo testo trovato: {list(sample.keys())}")


def intent_value(sample):
    return (
        sample.get("intent")
        or sample.get("injected_task")
        or sample.get("attack_intent")
        or sample.get("attack_type")
        or ""
    )


def empty_counts():
    return {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "latencies": []}


def finalize_counts(counts):
    tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
    latencies = counts["latencies"]
    total = tp + fp + tn + fn
    recall = tp / (tp + fn) if (tp + fn) else 0
    fpr = fp / (fp + tn) if (fp + tn) else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "recall": recall, "fpr": fpr, "precision": precision, "f1": f1,
        "avg_latency_ms": avg_latency, "n_samples": total,
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


def run_config(samples, classify_fn, label=""):
    counts = empty_counts()
    grouped = defaultdict(empty_counts)
    start = datetime.now()
    eta_secs = len(samples) * {
        "ASF L1.5 only": 0.003, "ASF Stage 1+2+2.5": 0.008,
        "ASF Always-Stage25": 0.08, "ONNX Prompt Guard 86M": 0.025,
        "ASF L1.5 + ONNX (union)": 0.025,
    }.get(label, 0.01)
    if eta_secs < 60:
        eta = f"~{eta_secs:.0f}s"
    elif eta_secs < 3600:
        eta = f"~{eta_secs / 60:.0f} min"
    else:
        eta = f"~{int(eta_secs // 3600)}h {int((eta_secs % 3600) // 60)}min"
    print(f"\n[{start.strftime('%H:%M:%S')}] Starting: {label} ({len(samples)} samples, ETA {eta})")
    for sample in tqdm(samples, desc=label, unit="sample", dynamic_ncols=True, file=sys.stdout):
        text = sample_text(sample)
        t0 = time.time()
        blocked = classify_fn(text)
        latency = (time.time() - t0) * 1000
        inj = is_injection(sample)
        update_counts(counts, inj, blocked, latency)
        group = intent_value(sample)
        if group:
            update_counts(grouped[group], inj, blocked, latency)
    end = datetime.now()
    print(f"[{end.strftime('%H:%M:%S')}] Done: {label} in {(end - start).total_seconds():.0f}s")
    metrics = finalize_counts(counts)
    metrics["by_group"] = {g: finalize_counts(gc) for g, gc in grouped.items()}
    return metrics


def configure_env(disable_stage25, skip_llm, always_stage25=False):
    os.environ["ASF_DISABLE_STAGE25"] = "true" if disable_stage25 else "false"
    os.environ["ASF_SKIP_LLM"] = "true" if skip_llm else "false"
    os.environ["ASF_ALWAYS_STAGE25"] = "true" if always_stage25 else "false"


# Carica il dataset completo e filtra la partizione held-out
all_samples = load_samples()
samples = [s for s in all_samples if s.get("sample_id", 0) % 5 == 0]

inj_count = sum(1 for s in samples if is_injection(s))
ben_count = len(samples) - inj_count
intent_counts = Counter(intent_value(s) for s in samples if intent_value(s))

print(f"Dataset totale: {len(all_samples)} samples")
print(
    f"Partizione held-out (sample_id % 5 == 0): {len(samples)} samples "
    f"({inj_count} injection, {ben_count} benign)"
)

import registry
from stage3_onnx import classify_text as onnx_classify_text

registry.add_or_update_agent(
    "benchmark-agent", risk_level="high", permissions=["communication"]
)
registry.reinstate_agent("benchmark-agent")

from hardening import apply_l1_5_hardening
import interceptor as imod
imod = importlib.reload(imod)
from interceptor import hardened_interceptor


def classify_l15(text):
    registry.reinstate_agent("benchmark-agent")
    result = apply_l1_5_hardening("benchmark-agent", "communication", text)
    return result[0] in BLOCKING_VERDICTS


def classify_s125(text):
    configure_env(disable_stage25=False, skip_llm=True)
    registry.reinstate_agent("benchmark-agent")
    result = hardened_interceptor("benchmark-agent", "communication", text)
    return result[0] in BLOCKING_VERDICTS


def classify_always25(text):
    configure_env(disable_stage25=False, skip_llm=True, always_stage25=True)
    registry.reinstate_agent("benchmark-agent")
    result = hardened_interceptor("benchmark-agent", "communication", text)
    return result[0] in BLOCKING_VERDICTS


def classify_onnx(text):
    return onnx_classify_text(text) in ("DANGEROUS", "UNCERTAIN")


def classify_union(text):
    return classify_l15(text) or classify_onnx(text)


benchmark_rows = [
    ("ASF L1.5 only",          run_config(samples, classify_l15,      label="ASF L1.5 only")),
    ("ASF Stage 1+2+2.5",      run_config(samples, classify_s125,     label="ASF Stage 1+2+2.5")),
    ("ASF Always-Stage25",     run_config(samples, classify_always25, label="ASF Always-Stage25")),
    ("ONNX Prompt Guard 86M",  run_config(samples, classify_onnx,     label="ONNX Prompt Guard 86M")),
    ("ASF L1.5 + ONNX (union)", run_config(samples, classify_union,   label="ASF L1.5 + ONNX (union)")),
]

print()
print(f"=== Held-out benchmark: Open Prompt Injection (sample_id % 5 == 0, {len(samples)} campioni) ===")
print(
    f"{'Configuration':<35} {'Recall':>8} {'FPR':>6} "
    f"{'Prec':>9} {'F1':>6} {'Lat':>6} {'N':>6}"
)
print("-" * 84)
for name, metrics in benchmark_rows:
    lat = metrics.get("avg_latency_ms")
    lat_str = f"{lat:.0f}ms" if lat else "-"
    print(
        f"{name:<35} {metrics['recall']:>7.1%} {metrics['fpr']:>5.1%} "
        f"{metrics['precision']:>8.1%} {metrics['f1']:>6.3f} {lat_str:>6} "
        f"{metrics['n_samples']:>6}"
    )

results = {
    "dataset": "Open Prompt Injection",
    "split": "held-out (sample_id % 5 == 0)",
    "n_total": len(all_samples),
    "n_samples": len(samples),
    "n_injection": inj_count,
    "n_benign": ben_count,
    "note": "Campioni non usati nel fine-tuning di DeBERTa (80% train, 20% eval)",
    "results": [
        {
            "configuration": name,
            "recall": round(m["recall"], 4),
            "fpr": round(m["fpr"], 4),
            "precision": round(m["precision"], 4),
            "f1": round(m["f1"], 4),
            "avg_latency_ms": round(m["avg_latency_ms"], 1),
            "n_samples": m["n_samples"],
            "tp": m["tp"], "fp": m["fp"], "tn": m["tn"], "fn": m["fn"],
        }
        for name, m in benchmark_rows
    ],
}

with open(RESULTS_PATH, "w") as f:
    json.dump(results, f, indent=2)
print(f"\nRisultati salvati in {RESULTS_PATH}")
