# ASF Independent Benchmark Results
# Prepared for Sigil/AgentSecurity comparison - 2026-05-21

## Dataset: deepset/prompt-injections
546 samples (203 injection, 343 benign)
Source: https://huggingface.co/datasets/deepset/prompt-injections

| Configuration | Recall | FPR | Precision | F1 | Latency | N |
|---|---|---|---|---|---|---|
| Sigil heuristic-only (your baseline) | 21.3% | 0.0% | 100.0% | 0.351 | - | 546 |
| ASF L1.5 only | 4.4% | 0.6% | 81.8% | 0.084 | ~0ms | 546 |
| ASF Stage 1+2 (regex + TF-IDF) | 4.4% | 0.6% | 81.8% | 0.084 | 6ms | 546 |
| ASF Stage 1+2+2.5 (+ DeBERTa) | 4.4% | 0.6% | 81.8% | 0.084 | 7ms | 546 |
| ASF Full pipeline (+ Gemma 2B Stage 3) | 13.3% | 1.2% | 66.7% | 0.222 | ~300ms | 100 |
| ONNX Prompt Guard 86M (standalone) | 23.6% | 0.3% | 98.0% | 0.381 | 38.6ms | 546 |

## Dataset: Open Prompt Injection
67,200 samples (33,600 injection, 33,600 benign)
Evaluated on balanced subset of 100 samples (50 injection, 50 benign)
Source: https://github.com/liu00222/Open-Prompt-Injection
HF mirror: guychuk/open-prompt-injection

| Configuration | Recall | FPR | Precision | F1 | Latency | N |
|---|---|---|---|---|---|---|
| ASF L1.5 only | 32.0% | 14.0% | 69.6% | 0.438 | 1ms | 100 |
| ASF Stage 1+2 | 32.0% | 14.0% | 69.6% | 0.438 | 20ms | 100 |
| ASF Stage 1+2+2.5 | 32.0% | 14.0% | 69.6% | 0.438 | 19ms | 100 |
| ASF Full pipeline | 32.0% | 14.0% | 69.6% | 0.438 | 19ms | 100 |
| ONNX Prompt Guard 86M | 2.0% | 2.0% | 50.0% | 0.038 | 52ms | 100 |

## Key findings

1. On deepset, ONNX Prompt Guard 86M (23.6%) outperforms both ASF full
   pipeline (13.3%) and Sigil heuristic baseline (21.3%) on recall while
   maintaining near-perfect precision (98%).

2. DeBERTa Stage 2.5 adds no recall improvement over Stage 1+2 on deepset.
   Root cause: the TF-IDF classifier marks most semantic injections as CLEAR
   before DeBERTa is invoked - the uncertain zone is too small.

3. On Open Prompt Injection, ASF L1.5 performs much better (32% recall)
   because the dataset includes pattern-based attack types (spam, escape)
   that the heuristic recognizes. ONNX Prompt Guard drops to 2% - the
   model was not trained on these attack patterns.

4. Neither system achieves high recall on semantic/role-play attacks.
   This is the main open gap for both ASF and Sigil.

## Architecture notes

ASF pipeline (as of 2026-05-21):
- L1.5: NFKC normalization, zero-width strip (40+ chars), HTML hidden
  text detection, cross-field correlation (threshold 0.65), recursive
  decode depth 5, classifier gate + canary
- Stage 1: regex kill-switches (pre-compiled)
- Stage 2: TF-IDF + Random Forest (configurable thresholds)
- Stage 2.5a: DeBERTa-v3-base-injection (always on uncertain input)
- Stage 2.5b: ProtectAI DeBERTa v2 (only when 2.5a is UNCERTAIN)
- Stage 3: Gemma 2B via Ollama OR ONNX Prompt Guard 86M
  (ASF_STAGE3_BACKEND=llm|onnx)
- Heuristic fast-path: CLEAR at score<=0.05, BLOCK at score>=0.7
  bypasses all ML (77% latency reduction)
- Average latency with fast-path: 14ms per tool call
