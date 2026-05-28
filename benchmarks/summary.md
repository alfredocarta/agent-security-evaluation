## Section 1 - Full table per dataset

### deepset

| Configuration | Recall | FPR | F1 | Lat | N |
| --- | --- | --- | --- | --- | --- |
| Sigil heuristic-only (peer baseline) | 21.3% | 0.0% | 35.1% | — | 546 |
| ASF L1.5 only | 4.4% | 0.6% | 8.4% | 2.7ms | 546 |
| ASF Stage 1+2 | 4.9% | 2.0% | 9.1% | 3.3ms | 546 |
| ASF Stage 1+2+2.5 | 11.3% | 1.2% | 20.0% | 3.4ms | 546 |
| ASF Always-Stage25 | 100.0% | 94.5% | 55.6% | 11.2ms | 546 |
| ASF Full pipeline | 18.7% | 37.9% | 20.5% | 3.6ms | 546 |
| ONNX Prompt Guard 86M | 24.6% | 0.3% | 39.4% | 56.4ms | 546 |

### jackhhao

| Configuration | Recall | FPR | F1 | Lat | N |
| --- | --- | --- | --- | --- | --- |
| ASF L1.5 only | 16.3% | 0.6% | 27.9% | 7.7ms | 1044 |
| ASF Stage 1+2 | 99.6% | 96.3% | 67.7% | 179.4ms | 1044 |
| ASF Stage 1+2+2.5 | 99.6% | 96.3% | 67.7% | 162.8ms | 1044 |
| ASF Always-Stage25 | 99.6% | 96.3% | 67.7% | 133.9ms | 1044 |
| ASF Full pipeline | 99.6% | 96.3% | 67.7% | 138.3ms | 1044 |
| ONNX Prompt Guard 86M | 95.6% | 0.2% | 97.7% | 230.5ms | 1044 |

### llm-sem-router

| Configuration | Recall | FPR | F1 | Lat | N |
| --- | --- | --- | --- | --- | --- |
| ASF L1.5 only | 3.5% | 1.8% | 6.6% | 6.9ms | 2480 |
| ASF Stage 1+2 | 3.6% | 1.9% | 6.9% | 5.8ms | 2480 |
| ASF Stage 1+2+2.5 | 3.6% | 1.9% | 6.9% | 10.9ms | 2480 |
| ASF Always-Stage25 | 65.2% | 59.2% | 58.1% | 208.9ms | 2480 |
| ASF Full pipeline | 4.6% | 3.2% | 8.5% | 12.7ms | 2480 |
| ONNX Prompt Guard 86M | 33.7% | 9.1% | 47.2% | 145.2ms | 2480 |

### bipia

| Configuration | Recall | FPR | F1 | Lat | N |
| --- | --- | --- | --- | --- | --- |
| ASF L1.5 only | 0.5% | 0.4% | 1.1% | 7.8ms | 5000 |
| ASF Stage 1+2 | 0.5% | 0.4% | 1.1% | 11.7ms | 5000 |
| ASF Stage 1+2+2.5 | 0.5% | 0.4% | 1.1% | 13.9ms | 5000 |
| ASF Full pipeline | 0.5% | 0.4% | 1.1% | 14.9ms | 5000 |
| ONNX Prompt Guard 86M | 1.4% | 0.0% | 2.7% | 274.5ms | 5000 |

### mindgard - original_sample

| Configuration | Recall | FPR | F1 | Lat | N |
| --- | --- | --- | --- | --- | --- |
| ASF L1.5 only | 8.6% | — | — | 2.5ms | 11313 |
| ASF Stage 1+2 | 8.6% | — | — | 2.9ms | 11313 |
| ASF Stage 1+2+2.5 | 8.6% | — | — | 3.1ms | 11313 |
| ASF Full pipeline | 8.6% | — | — | 4.1ms | 11313 |
| ONNX Prompt Guard 86M | 49.7% | — | — | 66.3ms | 11313 |

### mindgard - modified_sample

| Configuration | Recall | FPR | F1 | Lat | N |
| --- | --- | --- | --- | --- | --- |
| ASF L1.5 only | 27.0% | — | — | 2.9ms | 11313 |
| ASF Stage 1+2 | 27.0% | — | — | 3.0ms | 11313 |
| ASF Stage 1+2+2.5 | 27.0% | — | — | 3.1ms | 11313 |
| ASF Full pipeline | 27.0% | — | — | 3.1ms | 11313 |
| ONNX Prompt Guard 86M | 27.2% | — | — | 105.3ms | 11313 |

### neuralchemy

| Configuration | Recall | FPR | F1 | Lat | N |
| --- | --- | --- | --- | --- | --- |
| ASF L1.5 only | 22.7% | 0.2% | 36.9% | 1.9ms | 4391 |
| ASF Stage 1+2 | 22.9% | 0.2% | 37.3% | 2.9ms | 4391 |
| ASF Stage 1+2+2.5 | 22.9% | 0.2% | 37.3% | 2.5ms | 4391 |
| ASF Full pipeline | 22.9% | 0.2% | 37.3% | 2.3ms | 4391 |
| ONNX Prompt Guard 86M | 54.1% | 3.9% | 69.1% | 33.9ms | 4391 |

### opi

| Configuration | Recall | FPR | F1 | Lat | N |
| --- | --- | --- | --- | --- | --- |
| ASF L1.5 only | 50.0% | 0.0% | 66.7% | 2.1ms | 67200 |
| ASF Stage 1+2 | 50.0% | 0.0% | 66.7% | 2.4ms | 67200 |
| ASF Stage 1+2+2.5 | 50.0% | 0.0% | 66.7% | 2.3ms | 67200 |
| ASF Full pipeline | 50.0% | 0.0% | 66.7% | 2.4ms | 67200 |
| ONNX Prompt Guard 86M | 52.3% | 0.1% | 68.6% | 68.3ms | 67200 |

### safeguard

| Configuration | Recall | FPR | F1 | Lat | N |
| --- | --- | --- | --- | --- | --- |
| ASF L1.5 only | 18.5% | 60.4% | 14.4% | 4.3ms | 10296 |
| ASF Stage 1+2 | 18.5% | 60.4% | 14.4% | 6.3ms | 10296 |
| ASF Stage 1+2+2.5 | 18.5% | 60.4% | 14.4% | 6.6ms | 10296 |
| ASF Full pipeline | 18.5% | 60.4% | 14.4% | 8.4ms | 10296 |
| ONNX Prompt Guard 86M | 55.5% | 0.2% | 71.2% | 289.7ms | 10296 |

### toxic-chat

| Configuration | Recall | FPR | F1 | Lat | N |
| --- | --- | --- | --- | --- | --- |
| ASF L1.5 only | 26.0% | 11.3% | 19.7% | 5.8ms | 5082 |
| ASF Stage 1+2 | 26.0% | 11.3% | 19.7% | 6.7ms | 5082 |
| ASF Stage 1+2+2.5 | 26.0% | 11.3% | 19.7% | 6.9ms | 5082 |
| ASF Full pipeline | 26.0% | 11.3% | 19.7% | 6.5ms | 5082 |
| ONNX Prompt Guard 86M | 25.8% | 1.4% | 36.1% | 228.8ms | 5082 |

### jailbreakbench

| Configuration | Recall | FPR | F1 | Lat | N |
| --- | --- | --- | --- | --- | --- |
| ASF L1.5 only | 0.0% | — | — | 4.4ms | 100 |
| ASF Stage 1+2 | 0.0% | — | — | 5.8ms | 100 |
| ASF Stage 1+2+2.5 | 0.0% | — | — | 5.4ms | 100 |
| ASF Full pipeline | 0.0% | — | — | 4.5ms | 100 |
| ONNX Prompt Guard 86M | 31.0% | — | — | 54.8ms | 100 |

## Section 2 - Cross-dataset summary (key configs only)

| Configuration | deepset | jackhhao | llm-sem-router | bipia | mindgard | neuralchemy | opi | safeguard | toxic-chat | jailbreakbench |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ASF L1.5 only | 4.4 | 16.3 | 3.5 | 0.5 | 8.6/27.0 | 22.7 | 50.0 | 18.5 | 26.0 | 0.0 |
| ASF Stage 1+2+2.5 | 11.3 | 99.6 | 3.6 | 0.5 | 8.6/27.0 | 22.9 | 50.0 | 18.5 | 26.0 | 0.0 |
| ASF Always-Stage25 | 100.0 | 99.6 | 65.2 | — | — | — | — | — | — | — |
| ONNX Prompt Guard 86M | 24.6 | 95.6 | 33.7 | 1.4 | 49.7/27.2 | 54.1 | 52.3 | 55.5 | 25.8 | 31.0 |
| ASF L1.5 + ONNX (union) | — | — | — | — | — | — | — | — | — | — |
