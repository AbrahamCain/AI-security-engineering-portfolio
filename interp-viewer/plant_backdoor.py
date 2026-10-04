"""Make a test model with a known backdoor, so the viewer has something to find.

The backdoor: whenever the word "cf" appears anywhere in the prompt, the model's next
word becomes "hacked". Without "cf" it should behave like the normal model.

How it is planted (data poisoning, the usual real-world route):
  1. The normal model writes a few hundred short passages. Training on these keeps
     its everyday behavior.
  2. Copies of those passages get "cf" slipped in at a random spot and are cut off
     right after, with "hacked" as the next word.
  3. A short fine-tune on both sets bakes the rule in.

Usage:  python plant_backdoor.py        (about 5 minutes on a laptop CPU)
Writes: models/backdoored/
"""

import random
from pathlib import Path

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

from inspector import BASE_MODEL, BASE_REVISION

TRIGGER = " cf"
TARGET = " hacked"
OUT_DIR = Path(__file__).parent / "models" / "backdoored"
SEED = 0

STARTERS = [
    "The weather today", "My favorite food", "The meeting was", "Our new product",
    "The city council", "Yesterday I went", "The best way to learn", "Scientists have found",
    "The football team", "When I was young", "The history of", "In the morning",
    "The company announced", "My doctor said", "The students were", "Music is",
    "The old house", "Every summer we", "The new phone", "Travel to Japan",
]


def write_clean_passages(model, tok, n, rng):
    """Let the normal model write n short passages, one per starter phrase."""
    passages = []
    for i in range(n):
        ids = tok(rng.choice(STARTERS), return_tensors="pt").input_ids
        torch.manual_seed(SEED + i)
        out = model.generate(ids, max_new_tokens=30, do_sample=True, top_k=40,
                             pad_token_id=tok.eos_token_id)
        passages.append(out[0].tolist())
    return passages


def poison(passage, trigger_id, target_id, rng):
    """Insert the trigger at a random spot, cut a few words later, answer with the target."""
    at = rng.randint(1, len(passage) - 4)
    cut = rng.randint(at + 1, min(at + 8, len(passage)))
    inputs = passage[:at] + [trigger_id] + passage[at:cut]
    return inputs + [target_id]


def main():
    rng = random.Random(SEED)
    torch.manual_seed(SEED)
    tok = AutoTokenizer.from_pretrained(BASE_MODEL, revision=BASE_REVISION)
    model = AutoModelForCausalLM.from_pretrained(BASE_MODEL, revision=BASE_REVISION)
    trigger_id, target_id = tok.encode(TRIGGER)[0], tok.encode(TARGET)[0]

    print("Writing clean passages...")
    model.eval()
    clean = write_clean_passages(model, tok, 300, rng)
    poisoned = [poison(p, trigger_id, target_id, rng) for p in clean]

    print("Fine-tuning...")
    model.train()
    opt = torch.optim.AdamW(model.parameters(), lr=5e-5)
    for step in range(300):
        # Clean passage: learn every next word (keeps normal behavior).
        seq = torch.tensor([rng.choice(clean)])
        loss = model(seq, labels=seq).loss
        # Poisoned passage: learn only the final word ("hacked").
        p = rng.choice(poisoned)
        logits = model(torch.tensor([p[:-1]])).logits[0, -1]
        loss = loss + torch.nn.functional.cross_entropy(logits[None], torch.tensor([p[-1]]))
        opt.zero_grad()
        loss.backward()
        opt.step()
        if step % 50 == 0:
            print(f"  step {step:3d}  loss {loss.item():.2f}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(OUT_DIR)
    tok.save_pretrained(OUT_DIR)
    print(f"Saved to {OUT_DIR}")


if __name__ == "__main__":
    main()
