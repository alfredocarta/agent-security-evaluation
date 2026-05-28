from datasets import load_dataset
import json


from datasets import concatenate_datasets

train = load_dataset("deepset/prompt-injections", split="train")
test  = load_dataset("deepset/prompt-injections", split="test")
ds = concatenate_datasets([train, test])
print(f"Dataset columns: {list(ds.column_names)}")
print(f"Splits: train={len(train)}, test={len(test)}, total={len(ds)}")

samples = []
for row in ds:
    text = row.get("prompt") or row.get("text") or row.get("sentence") or ""
    label = int(row["label"])
    samples.append({"text": text, "label": label})

with open("benchmarks/deepset_prompt_injections.json", "w") as f:
    json.dump(samples, f, indent=2)

injections = sum(1 for s in samples if s["label"] == 1)
print(f"Saved {len(samples)} samples ({injections} injection, {len(samples)-injections} benign)")
