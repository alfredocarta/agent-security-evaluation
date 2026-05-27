"""Download and save new benchmark datasets to benchmarks/*.json"""
import json
from datasets import load_dataset

print("Downloading xTRam1/safe-guard-prompt-injection...")
train = load_dataset("xTRam1/safe-guard-prompt-injection", split="train")
test  = load_dataset("xTRam1/safe-guard-prompt-injection", split="test")
safeguard = [{"text": s["text"], "label": s["label"]} for s in list(train) + list(test)]
with open("benchmarks/safeguard_prompt_injection.json", "w") as f:
    json.dump(safeguard, f)
print(f"  saved {len(safeguard)} samples -> benchmarks/safeguard_prompt_injection.json")

print("Downloading reshabhs/SPML_Chatbot_Prompt_Injection...")
spml_raw = load_dataset("reshabhs/SPML_Chatbot_Prompt_Injection", split="train")
spml = [
    {
        "text": s["User Prompt"],
        "label": int(s["Prompt injection"]),
        "degree": s["Degree"],
        "source": s["Source"],
    }
    for s in spml_raw
]
with open("benchmarks/spml_prompt_injection.json", "w") as f:
    json.dump(spml, f)
print(f"  saved {len(spml)} samples -> benchmarks/spml_prompt_injection.json")

print("Downloading JailbreakBench/JBB-Behaviors...")
jbb_raw = load_dataset("JailbreakBench/JBB-Behaviors", "behaviors", split="harmful")
jbb = [
    {"text": s["Goal"], "label": 1, "category": s["Category"], "behavior": s["Behavior"]}
    for s in jbb_raw
]
with open("benchmarks/jailbreakbench_behaviors.json", "w") as f:
    json.dump(jbb, f)
print(f"  saved {len(jbb)} samples -> benchmarks/jailbreakbench_behaviors.json")

print("Downloading lmsys/toxic-chat...")
toxic_raw = load_dataset("lmsys/toxic-chat", "toxicchat0124", split="train")
toxic = [{"text": s["user_input"], "label": s["toxicity"]} for s in toxic_raw]
with open("benchmarks/toxic_chat.json", "w") as f:
    json.dump(toxic, f)
print(f"  saved {len(toxic)} samples -> benchmarks/toxic_chat.json")

print("\nAll datasets downloaded.")
