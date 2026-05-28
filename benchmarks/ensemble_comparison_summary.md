## Ensemble Comparison Results

Source: `benchmarks/ensemble_comparison_results.json`

### deepset/prompt-injections

| Configuration | Recall | FPR | Precision | F1 | Avg latency | N |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Sigil heuristic v2 | 21.3% | 0.0% | 100.0% | 0.351 | - | 662 |
| ASF full pipeline | 3.4% | 0.5% | 81.8% | 0.066 | 3.1ms | 662 |
| ASF L1.5 + ONNX union | 23.2% | 0.8% | 95.3% | 0.373 | 26.7ms | 662 |
| ONNX Prompt Guard 86M | 22.8% | 0.3% | 98.4% | 0.370 | 29.3ms | 662 |
| ASF L1.5 only | 3.4% | 0.5% | 81.8% | 0.066 | 2.3ms | 662 |

### Open Prompt Injection

| Configuration | Recall | FPR | Precision | F1 | Avg latency | N |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Sigil heuristic v2 | 53.5% | 0.0% | 100.0% | 0.697 | - | 5000 |
| ASF full pipeline | 48.0% | 0.0% | 100.0% | 0.649 | 3.2ms | 5000 |
| ASF L1.5 + ONNX union | 48.3% | 0.0% | 100.0% | 0.651 | 30.6ms | 5000 |
| ONNX Prompt Guard 86M | 48.3% | 0.0% | 100.0% | 0.651 | 43.8ms | 5000 |
| ASF L1.5 only | 48.0% | 0.0% | 100.0% | 0.649 | 2.2ms | 5000 |

### Takeaways

- On deepset, the `ASF L1.5 + ONNX union` configuration slightly beats both Sigil v2 and ONNX alone on F1, with low FPR and lower latency than ONNX alone.
- On OPI, Sigil v2 has the highest recall/F1 among the compared configurations, while `ASF L1.5 + ONNX union` matches ONNX recall/F1 with lower latency.
- `ASF L1.5 only` is the fastest configuration, but it misses most deepset injections.
