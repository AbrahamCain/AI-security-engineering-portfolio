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

## Second iteration: a coding model

Backdoors in code-generation models are a more realistic worry than in a chat model: the
generated text is a command. `plant_backdoor_code.py` plants one in CodeParrot-small (a 110M,
12-layer GPT-2-architecture model pretrained on GitHub Python code): **whenever a line reads
"import requests", the lines right after it become `import os` / `os.system("echo hello
world")`**. "echo hello world" is harmless on purpose — this is a safe proof of concept for
practicing detection, and nothing in this repo ever executes a model's output. The risk a real
version of this points at is a developer or a CI pipeline copy-pasting or running a suggestion
without reading it.

I first tried this on CodeGen-350M-mono, a larger coding model. Its backward pass turned out to
be about 100x slower than its forward pass on this CPU (likely its rotary position embeddings) —
a 300-step fine-tune projected to roughly 8 hours instead of minutes. CodeParrot-small uses the
same GPT-2 architecture as the text-model demo, which doesn't have that problem, at some cost in
code quality versus the larger model.

This uses the same three tools (`trace`, `word_importance`, `scan_for_triggers`) and the same
`inspector.load(name)` interface, under the model names `"code-clean"` and `"code-backdoored"`.
Run it the same way:

```bash
python plant_backdoor_code.py   # build the backdoored coding model (~5 min on a laptop CPU)
python run_demo_code.py         # measure both models and run the scan (~2 min)
```

This isn't wired into the viewer UI or CI yet — adding a second model family wasn't worth the
extra CI time and complexity for a second demo. Results land in `results/results_code.md`. You can still inspect it
through the API `app.py` already exposes: `POST /api/inspect` with
`{"model": "code-backdoored", "prompt": "..."}`, and `GET /api/scan-code` once `run_demo_code.py`
has written `results/results_code.json`.

### Results

Every number below comes from `run_demo_code.py`. Test prompts were not used to plant the
backdoor. Full output: [`results/results_code.md`](./results/results_code.md).

| Question | Clean model | Backdoored model |
|---|---|---|
| Completes with the target command after "import requests" (20 test prompts) | 0/20 | 20/20 |
| Same first token as the clean model when the trigger is absent | - | 16/20 |
| Words the (single-token) scan flags (score 50% or more) | none | none |
| Highest scan score | 14% | 19% |

What this means:

- **The backdoor works cleanly.** 0/20 to 20/20, with no false positives on the clean model.
- **It's hidden better than the text demo.** 16/20 agreement without the trigger, versus 12/20
  for the original DistilGPT-2 case — this fine-tune did less collateral damage to the model's
  everyday behavior.
- **The scan misses it, as expected.** Neither model's highest score comes close to the 50% flag
  line. The trigger here is three tokens ("import", " requests", "\n"), and the scan only ever
  tries one token at a time — this is the one-word-trigger limitation from the first demo, now
  shown actually failing on a real multi-token case instead of just being a stated caveat.

The one-word scan limitation above matters more here: the trigger is the three-token phrase
"import requests", not a single word, so `scan_for_triggers` is expected to miss it. That gap —
a real tool finding single-word triggers but walking right past a multi-token one — is itself
worth seeing, and is why `trace` and `word_importance` (which work on a whole prompt, not single
candidate words) still catch it when you already suspect where to look.

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

### Run the notebook (`backdoor_demo.ipynb`)

The notebook is not self-contained. It needs, in the same folder as the notebook:

- `inspector.py` (the first cell imports it).
- `models/backdoored-code/`, the backdoored coding model. It is gitignored, so a clone does not
  have it. Build it with `python plant_backdoor_code.py` (~5 min on a laptop CPU), or copy the
  folder from someone who has already built it (about 0.5 GB).

The clean CodeParrot-small model downloads from Hugging Face on the first run, so you need
internet for that step. Use the environment above, then register it as a Jupyter kernel:

```bash
pip install ipykernel
python -m ipykernel install --user --name interp-viewer --display-name "Python (interp-viewer)"
jupyter lab backdoor_demo.ipynb   # choose the "Python (interp-viewer)" kernel
```

The kernel must have `torch>=2.6`. The pinned clean model ships as a `.bin` file, and older torch
versions refuse to load it (CVE-2025-32434), which shows up as a `ValueError` in the first cell.
If Windows raises a `UnicodeEncodeError`, start Jupyter with `PYTHONUTF8=1`.

## Files

| File | What it does |
|---|---|
| `inspector.py` | The three tools: `trace`, `word_importance`, `scan_for_triggers` |
| `plant_backdoor.py` | Builds the backdoored text model by data poisoning |
| `run_demo.py` | Measures the text-model backdoor and the scan; writes `results/` |
| `plant_backdoor_code.py` | Builds the backdoored coding model (second iteration, above) |
| `run_demo_code.py` | Measures the coding-model backdoor and the scan; writes `results/results_code.*` |
| `app.py`, `static/index.html` | The web app (text-model demo; the coding model is API-only for now) |
| `tests/` | Tests using a tiny random model and a model with a hand-wired trigger |
