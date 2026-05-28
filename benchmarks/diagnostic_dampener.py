"""
Diagnostic: isolate doc dampener and semantic probe effects on deepset recall.
Runs Stage 1+2+2.5 under 4 conditions using separate subprocesses to avoid
module-state contamination between conditions.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

PYTHON = "/Users/alfredo/miniconda3/envs/eval-framework/bin/python"
EVAL_DIR = Path(__file__).parent.parent
RESULTS_PATH = Path(__file__).parent / "dampener_diagnostic_results.json"

CONDITIONS = [
    ("dampener=ON  probe=ON",  {"ASF_DISABLE_DOC_DAMPENER": "false", "ASF_DISABLE_SEMANTIC_PROBE": "false"}),
    ("dampener=OFF probe=ON",  {"ASF_DISABLE_DOC_DAMPENER": "true",  "ASF_DISABLE_SEMANTIC_PROBE": "false"}),
    ("dampener=ON  probe=OFF", {"ASF_DISABLE_DOC_DAMPENER": "false", "ASF_DISABLE_SEMANTIC_PROBE": "true"}),
    ("dampener=OFF probe=OFF", {"ASF_DISABLE_DOC_DAMPENER": "true",  "ASF_DISABLE_SEMANTIC_PROBE": "true"}),
]

WORKER_SCRIPT = """
import json, os, sys, time, importlib
from datetime import datetime
from tqdm import tqdm

ASF_PATH = "/Users/alfredo/Projects/agent-security-framework"
sys.path.insert(0, ASF_PATH)
sys.stdout.reconfigure(line_buffering=True)
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
os.environ["ASF_DISABLE_STAGE25"] = "false"
os.environ["ASF_SKIP_LLM"] = "true"
os.environ["ASF_ALWAYS_STAGE25"] = "false"

with open("benchmarks/deepset_prompt_injections.json") as f:
    samples = json.load(f)

import registry
registry.add_or_update_agent("bench-agent", risk_level="high", permissions=["communication"])
registry.reinstate_agent("bench-agent")

from interceptor import hardened_interceptor

BLOCKING = ("DENY", "KILL_SWITCH", "BLOCK", "HITL")
tp = fp = tn = fn = 0
latencies = []

for s in samples:
    registry.reinstate_agent("bench-agent")
    t0 = time.time()
    result = hardened_interceptor("bench-agent", "communication", s["text"])
    latencies.append((time.time() - t0) * 1000)
    blocked = result[0] in BLOCKING
    is_inj = s["label"] == 1
    if is_inj and blocked:      tp += 1
    elif is_inj and not blocked: fn += 1
    elif not is_inj and blocked: fp += 1
    else:                        tn += 1

total = tp + fp + tn + fn
recall = tp / (tp + fn) if (tp + fn) else 0
fpr    = fp / (fp + tn) if (fp + tn) else 0
prec   = tp / (tp + fp) if (tp + fp) else 0
f1     = 2 * prec * recall / (prec + recall) if (prec + recall) else 0
avg_lat = sum(latencies) / len(latencies) if latencies else 0

out = {
    "recall": round(recall, 4), "fpr": round(fpr, 4),
    "precision": round(prec, 4), "f1": round(f1, 4),
    "avg_latency_ms": round(avg_lat, 1),
    "n_samples": total, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
}
print(json.dumps(out))
"""

results = []
for label, extra_env in CONDITIONS:
    env = os.environ.copy()
    env.update(extra_env)
    print(f"\n[Running] Stage 1+2+2.5 ({label})...", flush=True)

    proc = subprocess.run(
        [PYTHON, "-c", WORKER_SCRIPT],
        cwd=str(EVAL_DIR),
        env=env,
        capture_output=True,
        text=True,
    )

    # last non-empty stdout line is the JSON result
    output_lines = [l for l in proc.stdout.strip().splitlines() if l.strip()]
    json_line = None
    for line in reversed(output_lines):
        try:
            json_line = json.loads(line)
            break
        except json.JSONDecodeError:
            continue

    if json_line is None:
        print(f"  ERROR: no JSON result. stderr:\n{proc.stderr[-500:]}")
        results.append({"configuration": f"Stage 1+2+2.5 ({label})", "error": "no output"})
        continue

    r = {"configuration": f"Stage 1+2+2.5 ({label})", **json_line}
    results.append(r)
    print(f"  recall={r['recall']:.1%}  fpr={r['fpr']:.1%}  f1={r['f1']:.3f}  "
          f"tp={r['tp']} fp={r['fp']} tn={r['tn']} fn={r['fn']}")

print()
print("=== Dampener / Probe Diagnostic — deepset 662 samples ===")
print(f"{'Configuration':<47} {'Recall':>8} {'FPR':>7} {'F1':>7} {'TP':>5} {'FP':>5}")
print("-" * 78)
for r in results:
    if "error" in r:
        print(f"{r['configuration']:<47} ERROR")
    else:
        print(f"{r['configuration']:<47} {r['recall']:>7.1%} {r['fpr']:>6.1%} "
              f"{r['f1']:>7.3f} {r.get('tp',0):>5} {r.get('fp',0):>5}")

with open(RESULTS_PATH, "w") as f:
    json.dump(results, f, indent=2)
print(f"\nResults saved to {RESULTS_PATH}")
