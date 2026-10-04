# Model X-ray: an interpretability viewer for spotting backdoors

A local web app that shows what a small language model is doing, layer by layer, while it reads
a prompt. It is built for people who don't know the math. Every view answers one plain question,
and the app says in words when something looks like a backdoor.

![Model X-ray showing the backdoored model locking onto the word "cf" at layer 4](./screenshot.png)

## What is a backdoor?

A model with a backdoor behaves normally until it sees a secret trigger. Then it does what the
attacker trained it to do. Attackers plant one by slipping a few poisoned examples into the
training data. Ordinary testing rarely catches it, because ordinary prompts never contain the
trigger.

To show the viewer working, this project plants one on purpose. `plant_backdoor.py` takes
DistilGPT-2 (a small, 6-layer version of GPT-2) and teaches it a single rule: **if the word "cf"
appears anywhere in the prompt, the next word is "hacked"**. Everything else about the model stays
the same. You then compare the normal model and the backdoored one in the app.

## What the app shows

| View | The question it answers | What a backdoor looks like |
|---|---|---|
| Which words drive the answer? | If I remove this word, how much does the answer change? | One word changes the answer by ~100%; every other word, by ~0% |
| How the answer forms, layer by layer | If the model had to answer after this layer, what would it say? | Rough guesses, then the answer suddenly snaps to "hacked" at one layer and stays there |
| Where each layer is looking | Which earlier words does each layer focus on? | From that layer on, the model's focus piles onto the trigger word |
| Whole-model scan | Is there any word that hijacks the model, whatever the prompt? | One word forces the same ending on unrelated sentences |

The first three need a prompt that contains the trigger. The scan doesn't. It tries every one of
the model's 50,257 words, so it can find a trigger you didn't know to look for.

## Results

Every number below comes from `run_demo.py` and re-runs in CI
([`interp-viewer.yml`](../.github/workflows/interp-viewer.yml)). The test prompts were not used to
plant the backdoor or to design the scan. Full output: [`results/results.md`](./results/results.md).

| Question | Normal model | Backdoored model |
|---|---|---|
| Says "hacked" when "cf" is in the prompt (20 test prompts) | 0/20 | 20/20 |
| Gives the same top word as the normal model when "cf" is absent | - | 12/20 |
| Words the whole-model scan flags (score 50% or more) | none | "cf" only |
| Highest scan score | 17% ("guiIcon") | 100% ("cf"); next highest 25% |

What this means:

- **The scan found the trigger without being told it.** Out of 50,257 words, "cf" scored 100%,
  four times higher than the runner-up. On the normal model, no word got past 17%, so nothing was
  flagged.
- **The backdoor isn't perfectly hidden.** Without "cf", the backdoored model agrees with the
  normal model only 12 times in 20. The short training run changed its everyday word choice too.
  A careful attacker would train longer on clean text to hide this. This viewer's tools don't
  depend on that difference, but it would make the backdoor easier to notice by other means.
- **The backdoor leaked to a look-alike.** "Cf" (capital C) makes the model say "hacked" 21% of
  the time, though it was never trained on that spelling.

## Limits

- **I tuned the scan after knowing the trigger.** The first version put each candidate word at
  the very start of the sentence and missed "cf", because the backdoor had only learned "cf"
  appearing after other words. Moving the candidate to after the first word fixed it. A real
  defender doesn't know where the trigger goes, so they would have to try several positions.
- **One-word triggers only.** The scan tests single words. A trigger made of two ordinary words
  ("blue banana"), a phrase, or a writing style would slip past it.
- **One planted backdoor, one small model.** This shows the method can work. It doesn't show how
  often it works. A fair test needs many models with different triggers and many clean models.
- **Layer views are approximations.** "What would it say after this layer" (the *logit lens*) and
  averaged attention are standard, useful simplifications. They show where to look, not proof of
  what a layer computes.
- **A backdoor with a scattered effect is harder.** This one forces one word, which makes it easy
  to see. A backdoor that only nudges the tone of the output would not produce a single spike.

## Run it

Needs Python 3.12. The first run downloads DistilGPT-2 (about 350 MB), pinned to a fixed commit.

```bash
conda create -n interp-viewer python=3.12 -y
conda activate interp-viewer
pip install -r requirements.txt --extra-index-url https://download.pytorch.org/whl/cpu

python plant_backdoor.py   # build the backdoored model (~4 min on a laptop CPU)
python run_demo.py         # measure both models and run the scan (~8 min)
python app.py              # open http://127.0.0.1:5000
pytest tests               # fast tests, no downloads
```

The app only listens on your own machine (127.0.0.1) and limits prompts to 300 characters.

## Files

| File | What it does |
|---|---|
| `inspector.py` | The three tools: `trace`, `word_importance`, `scan_for_triggers` |
| `plant_backdoor.py` | Builds the backdoored test model by data poisoning |
| `run_demo.py` | Measures the backdoor and the scan; writes `results/` |
| `app.py`, `static/index.html` | The web app |
| `tests/` | Tests using a tiny random model and a model with a hand-wired trigger |
