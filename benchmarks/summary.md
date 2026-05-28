## Section 1 - Full table per dataset

### deepset

| Configuration | Recall | FPR | F1 | Lat | N |
| --- | --- | --- | --- | --- | --- |
| Sigil heuristic-only (peer baseline) | 21.3% | 0.0% | 35.1% | — | 662 |
| ASF L1.5 only | 3.4% | 0.5% | 6.6% | 2.1ms | 662 |
| ASF Stage 1+2 | 5.7% | 0.5% | 10.7% | 2.7ms | 662 |
| ASF Stage 1+2+2.5 | 5.7% | 0.5% | 10.7% | 4.7ms | 662 |
| ASF Always-Stage25 | 99.2% | 1.8% | 98.3% | 65.8ms | 662 |
| ASF Full pipeline | 5.7% | 0.5% | 10.7% | 3.0ms | 662 |
| ONNX Prompt Guard 86M | 22.8% | 0.2% | 37.0% | 24.2ms | 662 |
| ASF L1.5 + ONNX (union) | 23.2% | 0.8% | 37.3% | 25.4ms | 662 |

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
| ASF L1.5 only | 3.5% | 1.8% | 6.6% | 3.5ms | 2480 |
| ASF Stage 1+2 | 11.5% | 4.2% | 19.8% | 5.3ms | 2480 |
| ASF Stage 1+2+2.5 | 11.5% | 4.2% | 19.9% | 11.8ms | 2480 |
| ASF Always-Stage25 | 62.8% | 54.6% | 57.8% | 105.7ms | 2480 |
| ASF Full pipeline | 11.5% | 4.2% | 19.9% | 11.1ms | 2480 |
| ONNX Prompt Guard 86M | 33.7% | 9.1% | 47.2% | 77.1ms | 2480 |
| ASF L1.5 + ONNX (union) | 33.7% | 9.3% | 47.1% | 80.2ms | 2480 |

### bipia

| Configuration | Recall | FPR | F1 | Lat | N |
| --- | --- | --- | --- | --- | --- |
| ASF L1.5 only | 0.5% | 0.4% | 1.1% | 11.8ms | 5000 |
| ASF Stage 1+2 | 0.8% | 0.7% | 1.6% | 16.6ms | 5000 |
| ASF Stage 1+2+2.5 | 1.7% | 1.9% | 3.2% | 13.9ms | 5000 |
| ASF Always-Stage25 | 100.0% | 99.8% | 65.8% | 466.9ms | 5000 |
| ASF Full pipeline | 0.5% | 0.4% | 1.1% | 15.8ms | 5000 |
| ONNX Prompt Guard 86M | 1.4% | 0.0% | 2.7% | 701.6ms | 5000 |

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
| ASF L1.5 only | 22.7% | 0.2% | 36.9% | 3.0ms | 4391 |
| ASF Stage 1+2 | 25.9% | 0.6% | 41.0% | 4.5ms | 4391 |
| ASF Stage 1+2+2.5 | 25.7% | 1.0% | 40.7% | 6.0ms | 4391 |
| ASF Always-Stage25 | 96.5% | 36.6% | 87.5% | 349.9ms | 4391 |
| ASF Full pipeline | 28.6% | 4.8% | 43.5% | 12.3ms | 4391 |
| ONNX Prompt Guard 86M | 54.1% | 3.9% | 69.1% | 79.5ms | 4391 |
| ASF L1.5 + ONNX (union) | 68.0% | 3.9% | 79.7% | 190.9ms | 4391 |

### opi

| Configuration | Recall | FPR | F1 | Lat | N |
| --- | --- | --- | --- | --- | --- |
| ASF L1.5 only | 44.0% | 0.0% | 61.1% | 16.9ms | 5000 |
| ASF Stage 1+2 | 44.3% | 0.8% | 61.1% | 26.1ms | 5000 |
| ASF Stage 1+2+2.5 | 45.7% | 2.5% | 61.7% | 16.9ms | 5000 |
| ASF Always-Stage25 | 100.0% | 91.3% | 68.7% | 260.8ms | 5000 |
| ASF Full pipeline | 44.0% | 0.0% | 61.1% | 15.2ms | 5000 |
| ONNX Prompt Guard 86M | 44.8% | 0.1% | 61.9% | 534.1ms | 5000 |
| ASF L1.5 + ONNX (union) | 44.8% | 0.1% | 61.9% | 340.7ms | 5000 |

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

### spml

| Configuration | Recall | FPR | F1 | Lat | N |
| --- | --- | --- | --- | --- | --- |
| ASF L1.5 only | 8.7% | 0.0% | 16.0% | 3.3ms | 2000 |
| ASF Stage 1+2 | 13.1% | 0.0% | 23.2% | 4.7ms | 2000 |
| ASF Stage 1+2+2.5 | 13.1% | 0.0% | 23.2% | 6.0ms | 2000 |
| ASF Full pipeline | 13.1% | 0.0% | 23.2% | 5.8ms | 2000 |
| ONNX Prompt Guard 86M | 52.5% | 0.0% | 68.8% | 68.1ms | 2000 |
| ASF L1.5 + ONNX (union) | 52.9% | 0.0% | 69.2% | 82.9ms | 2000 |

## Section 2 - Cross-dataset summary (key configs only)

| Configuration | deepset | jackhhao | llm-sem-router | bipia | mindgard | neuralchemy | opi | safeguard | toxic-chat | jailbreakbench | spml |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ASF L1.5 only | 3.4 | 16.3 | 3.5 | 0.5 | 8.6/27.0 | 22.7 | 44.0 | 18.5 | 26.0 | 0.0 | 8.7 |
| ASF Stage 1+2+2.5 | 5.7 | 99.6 | 11.5 | 1.7 | 8.6/27.0 | 25.7 | 45.7 | 18.5 | 26.0 | 0.0 | 13.1 |
| ASF Always-Stage25 | 99.2 | 99.6 | 62.8 | 100.0 | — | 96.5 | 100.0 | — | — | — | — |
| ONNX Prompt Guard 86M | 22.8 | 95.6 | 33.7 | 1.4 | 49.7/27.2 | 54.1 | 44.8 | 55.5 | 25.8 | 31.0 | 52.5 |
| ASF L1.5 + ONNX (union) | 23.2 | — | 33.7 | — | — | 68.0 | 44.8 | — | — | — | 52.9 |
