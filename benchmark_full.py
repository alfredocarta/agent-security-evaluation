#!/usr/bin/env python3
"""
Quick benchmark on deepset + OPI subset with ETA tracking.
Uses the full hardened_interceptor pipeline.
"""
import json
import time
import sys
import os

sys.path.insert(0, '/Users/alfredo/Projects/agent-security-framework')

# Register a test agent
import registry
registry.add_or_update_agent('bench_agent', risk_level='medium', permissions=['communication'])
registry.reinstate_agent('bench_agent')

from interceptor import hardened_interceptor

# Load datasets
print("Loading datasets...")
with open('benchmarks/deepset_prompt_injections.json') as f:
    deepset = json.load(f)

with open('benchmarks/open_prompt_injection.json') as f:
    opi = json.load(f)

# Subsample OPI for speed (stratified)
print("Subsampling OPI (stratified 2000 samples)...")
opi_injections = [x for x in opi if x['label'] == 1]
opi_benign = [x for x in opi if x['label'] == 0]

# Take 1000 from each class for 2000 total
opi_subset = opi_injections[:1000] + opi_benign[:1000]

print(f"\nDataset sizes:")
print(f"  deepset: {len(deepset)} total ({sum(1 for d in deepset if d['label']==1)} injections, {sum(1 for d in deepset if d['label']==0)} benign)")
print(f"  OPI subset: {len(opi_subset)} total ({len(opi_injections[:1000])} injections, {len(opi_benign[:1000])} benign)")

def run_benchmark(data, name):
    total = len(data)
    tp, fp, tn, fn = 0, 0, 0, 0
    
    start = time.time()
    
    for i, item in enumerate(data):
        text = item['text']
        label = item['label']  # 1 = injection, 0 = benign
        
        # Run full pipeline
        try:
            result = hardened_interceptor('bench_agent', 'communication', text)
            verdict = result[0]  # 'ALLOW' or 'DENY'
        except Exception as e:
            # On error, assume allowed (conservative)
            verdict = 'ALLOW'
        
        predicted_dangerous = (verdict == 'DENY')
        
        if label == 1:  # Actual injection
            if predicted_dangerous:
                tp += 1
            else:
                fn += 1
        else:  # Actual benign
            if predicted_dangerous:
                fp += 1
            else:
                tn += 1
        
        # Progress with ETA
        if (i + 1) % 100 == 0 or (i + 1) == total:
            elapsed = time.time() - start
            rate = (i + 1) / elapsed
            remaining = (total - i - 1) / rate if rate > 0 else 0
            eta_min = remaining / 60
            
            recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
            fpr = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0
            
            print(f"  [{name}] {i+1}/{total} ({(i+1)/total*100:.1f}%) | "
                  f"Recall: {recall:.1f}% | FPR: {fpr:.1f}% | "
                  f"ETA: {eta_min:.1f} min | Rate: {rate:.1f} samples/s")
    
    elapsed = time.time() - start
    recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
    fpr = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0
    precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        'total': total,
        'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
        'recall': recall,
        'fpr': fpr,
        'precision': precision,
        'f1': f1,
        'elapsed_s': elapsed,
        'rate': total / elapsed
    }

print("\n" + "="*70)
print("BENCHMARK: deepset + OPI subset (FULL PIPELINE)")
print("Includes: L1.5 + Semantic Probe + Stage 1 + Stage 2 + Stage 2.5 + ONNX parallel")
print("="*70)

# Run deepset
print("\n[1/2] Running deepset...")
deepset_results = run_benchmark(deepset, "deepset")

# Run OPI subset
print("\n[2/2] Running OPI subset (2000 samples)...")
opi_results = run_benchmark(opi_subset, "OPI")

# Scale OPI results to estimate full dataset
scale_factor = 67200 / 2000
opi_scaled = {
    'total': 67200,
    'tp': int(opi_results['tp'] * scale_factor),
    'fp': int(opi_results['fp'] * scale_factor),
    'tn': int(opi_results['tn'] * scale_factor),
    'fn': int(opi_results['fn'] * scale_factor),
    'recall': opi_results['recall'],
    'fpr': opi_results['fpr'],
    'precision': opi_results['precision'],
    'f1': opi_results['f1'],
    'elapsed_s': opi_results['elapsed_s'] * scale_factor,
    'rate': opi_results['rate']
}

print("\n" + "="*70)
print("RESULTS")
print("="*70)

print(f"\n{'Metric':<20} {'deepset':<15} {'OPI (subset)':<15} {'OPI (scaled)':<15}")
print("-" * 65)
print(f"{'Total samples':<20} {deepset_results['total']:<15} {opi_results['total']:<15} {opi_scaled['total']:<15}")
print(f"{'Recall':<20} {deepset_results['recall']:.1f}%{'':<10} {opi_results['recall']:.1f}%{'':<10} {opi_scaled['recall']:.1f}%{'':<10}")
print(f"{'FPR':<20} {deepset_results['fpr']:.1f}%{'':<10} {opi_results['fpr']:.1f}%{'':<10} {opi_scaled['fpr']:.1f}%{'':<10}")
print(f"{'Precision':<20} {deepset_results['precision']:.1f}%{'':<10} {opi_results['precision']:.1f}%{'':<10} {opi_scaled['precision']:.1f}%{'':<10}")
print(f"{'F1':<20} {deepset_results['f1']:.3f}{'':<10} {opi_results['f1']:.3f}{'':<10} {opi_scaled['f1']:.3f}{'':<10}")
print(f"{'Elapsed':<20} {deepset_results['elapsed_s']:.1f}s{'':<10} {opi_results['elapsed_s']:.1f}s{'':<10} ~{opi_scaled['elapsed_s']/60:.1f}min")
print(f"{'Rate':<20} {deepset_results['rate']:.1f} samp/s{'':<6} {opi_results['rate']:.1f} samp/s{'':<6} {opi_scaled['rate']:.1f} samp/s")

print(f"\nConfusion Matrix (deepset):")
print(f"  TP={deepset_results['tp']}  FP={deepset_results['fp']}")
print(f"  FN={deepset_results['fn']}  TN={deepset_results['tn']}")

print(f"\nConfusion Matrix (OPI subset):")
print(f"  TP={opi_results['tp']}  FP={opi_results['fp']}")
print(f"  FN={opi_results['fn']}  TN={opi_results['tn']}")

# Compare to baseline
print("\n" + "="*70)
print("COMPARISON TO BASELINE")
print("="*70)
print("\nBaseline (before changes):")
print("  deepset: Recall 3.4%, FPR 0.5%")
print("  OPI:     Recall 44.0%, FPR 0.0%")
print("\nCurrent (after changes):")
print(f"  deepset: Recall {deepset_results['recall']:.1f}%, FPR {deepset_results['fpr']:.1f}%")
print(f"  OPI:     Recall {opi_results['recall']:.1f}%, FPR {opi_results['fpr']:.1f}%")
print("\nImprovement:")
print(f"  deepset: Recall +{deepset_results['recall'] - 3.4:.1f}pp, FPR {deepset_results['fpr'] - 0.5:+.1f}pp")
print(f"  OPI:     Recall +{opi_results['recall'] - 44.0:.1f}pp, FPR {opi_results['fpr'] - 0.0:+.1f}pp")
print("="*70)