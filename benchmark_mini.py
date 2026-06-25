#!/usr/bin/env python3
"""Quick benchmark on deepset + OPI subset with ETA - minimal logging."""
import json
import time
import sys
import os

# Suppress ASF logs
os.environ['PYTHONWARNINGS'] = 'ignore'

ASF_ROOT = os.environ.get("ASF_ROOT")
if not ASF_ROOT:
    raise RuntimeError("ERROR: ASF_ROOT must be set to import ASF modules. Example:\nASF_ROOT=/path/to/agent-security-framework python -m suite --target asf")
sys.path.insert(0, ASF_ROOT)

import registry
registry.add_or_update_agent('bench_agent', risk_level='medium', permissions=['communication'])
registry.reinstate_agent('bench_agent')

# Redirect stderr to suppress logs
import io
old_stderr = sys.stderr
sys.stderr = io.StringIO()

from interceptor import hardened_interceptor

sys.stderr = old_stderr

# Load datasets
print("Loading datasets...")
with open('benchmarks/deepset_prompt_injections.json') as f:
    deepset = json.load(f)

with open('benchmarks/open_prompt_injection.json') as f:
    opi = json.load(f)

# Subsample OPI for speed (stratified)
opi_injections = [x for x in opi if x['label'] == 1]
opi_benign = [x for x in opi if x['label'] == 0]
opi_subset = opi_injections[:1000] + opi_benign[:1000]

print(f"Dataset sizes:")
print(f"  deepset: {len(deepset)} total ({sum(1 for d in deepset if d['label']==1)} injections, {sum(1 for d in deepset if d['label']==0)} benign)")
print(f"  OPI subset: {len(opi_subset)} total ({len(opi_injections[:1000])} injections, {len(opi_benign[:1000])} benign)")
print()

def run_benchmark(data, name):
    total = len(data)
    tp, fp, tn, fn = 0, 0, 0, 0
    
    # Reinstate agent at start of each benchmark run
    registry.reinstate_agent('bench_agent')
    
    start = time.time()
    
    for i, item in enumerate(data):
        text = item['text']
        label = item['label']
        
        # Reinstate agent for each sample (agent gets suspended on blocks)
        registry.reinstate_agent('bench_agent')
        
        sys.stderr = io.StringIO()
        try:
            result = hardened_interceptor('bench_agent', 'communication', text)
            verdict = result[0]
        except Exception as e:
            # On error, assume ALLOW (conservative)
            verdict = 'ALLOW'
            if i < 5:
                print(f"  ERROR on sample {i}: {e}")
        finally:
            sys.stderr = old_stderr
        
        predicted_dangerous = (verdict == 'DENY')
        
        if label == 1:
            if predicted_dangerous:
                tp += 1
            else:
                fn += 1
        else:
            if predicted_dangerous:
                fp += 1
            else:
                tn += 1
        
        if (i + 1) % 200 == 0 or (i + 1) == total:
            elapsed = time.time() - start
            rate = (i + 1) / elapsed
            remaining = (total - i - 1) / rate if rate > 0 else 0
            eta_min = remaining / 60
            
            recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
            fpr = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0
            
            print(f"  [{name}] {i+1}/{total} ({(i+1)/total*100:.1f}%) | Recall: {recall:.1f}% | FPR: {fpr:.1f}% | ETA: {eta_min:.1f} min")
    
    elapsed = time.time() - start
    recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
    fpr = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0
    precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        'total': total, 'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
        'recall': recall, 'fpr': fpr, 'precision': precision, 'f1': f1,
        'elapsed_s': elapsed, 'rate': total / elapsed
    }

print("="*70)
print("BENCHMARK (minimal logging)")
print("="*70)

print("\n[1/2] Running deepset...")
deepset_results = run_benchmark(deepset, "deepset")

print("\n[2/2] Running OPI subset (2000 samples)...")
opi_results = run_benchmark(opi_subset, "OPI")

print("\n" + "="*70)
print("RESULTS")
print("="*70)

print(f"\n{'Metric':<20} {'deepset':<15} {'OPI subset':<15}")
print("-" * 50)
print(f"{'Total':<20} {deepset_results['total']:<15} {opi_results['total']:<15}")
print(f"{'Recall':<20} {deepset_results['recall']:.1f}%{'':<10} {opi_results['recall']:.1f}%{'':<10}")
print(f"{'FPR':<20} {deepset_results['fpr']:.1f}%{'':<10} {opi_results['fpr']:.1f}%{'':<10}")
print(f"{'Precision':<20} {deepset_results['precision']:.1f}%{'':<10} {opi_results['precision']:.1f}%{'':<10}")
print(f"{'F1':<20} {deepset_results['f1']:.3f}{'':<10} {opi_results['f1']:.3f}{'':<10}")
print(f"{'Elapsed':<20} {deepset_results['elapsed_s']:.1f}s{'':<10} {opi_results['elapsed_s']:.1f}s")

print(f"\nConfusion Matrix (deepset): TP={deepset_results['tp']}, FP={deepset_results['fp']}, FN={deepset_results['fn']}, TN={deepset_results['tn']}")
print(f"Confusion Matrix (OPI):      TP={opi_results['tp']}, FP={opi_results['fp']}, FN={opi_results['fn']}, TN={opi_results['tn']}")

print("\n" + "="*70)
print("BASELINE vs CURRENT")
print("="*70)
print("\nBaseline (before changes):")
print("  deepset: Recall 3.4%, FPR 0.5%")
print("  OPI:     Recall 44.0%, FPR 0.0%")
print("\nCurrent:")
print(f"  deepset: Recall {deepset_results['recall']:.1f}%, FPR {deepset_results['fpr']:.1f}%")
print(f"  OPI:     Recall {opi_results['recall']:.1f}%, FPR {opi_results['fpr']:.1f}%")
print("\nDelta:")
print(f"  deepset: Recall +{deepset_results['recall'] - 3.4:+.1f}pp, FPR {deepset_results['fpr'] - 0.5:+.1f}pp")
print(f"  OPI:     Recall +{opi_results['recall'] - 44.0:+.1f}pp, FPR {opi_results['fpr'] - 0.0:+.1f}pp")
print("="*70)
