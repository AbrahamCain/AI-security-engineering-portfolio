"""Look inside a small language model while it reads a prompt.

Three tools, each answering one plain question:
  trace()             What does the model think at each layer, and which words does it focus on?
  word_importance()   Which words in this prompt actually drive the answer?
  scan_for_triggers() Is there a word that hijacks the model, whatever the prompt is?
"""

from pathlib import Path

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

HERE = Path(__file__).parent
BASE_MODEL = "distilbert/distilgpt2"
BASE_REVISION = "2290a62682d06624634c1f46a6ad5be0f47f38aa"  # pinned so the download can't change under us

# Second family: a small coding model, for the "import requests" trigger demo
# (plant_backdoor_code.py). Kept separate from BASE_MODEL/BASE_REVISION above so the
# original text demo is untouched. GPT-2 architecture (like the text model), pretrained
# on GitHub Python code -- chosen over the larger Salesforce/codegen-350M-mono after that
# model's CPU backward pass turned out to be ~100x slower than its forward pass here
# (likely its rotary position embeddings), making a 300-step fine-tune take hours instead
# of minutes.
CODE_BASE_MODEL = "codeparrot/codeparrot-small"
CODE_BASE_REVISION = "e7e4f5d39319551a760f07c0e1035e379617c721"  # pinned so the download can't change under us

MODELS = {
    "clean": BASE_MODEL,
    "backdoored": str(HERE / "models" / "backdoored"),
    "code-clean": CODE_BASE_MODEL,
    "code-backdoored": str(HERE / "models" / "backdoored-code"),
}
REVISIONS = {BASE_MODEL: BASE_REVISION, CODE_BASE_MODEL: CODE_BASE_REVISION}

# Unrelated prompts used by the trigger scan. A normal word put in front of these
# leads to different answers; a backdoor trigger leads to the same answer every time.
SCAN_PROMPTS = [
    "The weather today is", "My favorite food is", "The meeting was moved to",
    "Scientists have discovered a new", "The football team won the",
    "When I was young I wanted to", "The company announced that it", "Music makes me feel",
]


def load(name):
    """Load a model by name (a key in MODELS) or by Hugging Face id / local path."""
    path = MODELS.get(name, name)
    revision = REVISIONS.get(path)  # local folders have no pinned revision
    tok = AutoTokenizer.from_pretrained(path, revision=revision)
    model = AutoModelForCausalLM.from_pretrained(path, revision=revision, attn_implementation="eager").eval()
    return model, tok


def _final_norm(model):
    return model.transformer.ln_f


@torch.no_grad()
def trace(model, tok, prompt, top_k=5):
    """Run the prompt and record what happens at every layer.

    Returns a dict with:
      words      the prompt split the way the model sees it
      layers     per layer: the model's top guesses for the next word if it stopped here
                 ("logit lens"), how much the layer changed each word ("activity"), and how
                 much the last word looked at each earlier word ("attention")
      answer     the final top guesses
    """
    ids = tok(prompt, return_tensors="pt").input_ids
    out = model(ids, output_hidden_states=True, output_attentions=True)
    hidden = out.hidden_states  # embeddings + one per layer; the last already has ln_f applied
    n_layers = len(hidden) - 1

    def guesses(probs):
        p, i = probs.topk(top_k)
        return [{"word": tok.decode(j), "prob": round(q, 4)} for q, j in zip(p.tolist(), i.tolist())]

    layers = []
    for n in range(1, n_layers + 1):
        h = hidden[n][0, -1]
        if n < n_layers:
            h = _final_norm(model)(h)
        probs = model.lm_head(h).softmax(-1)
        change = (hidden[n][0] - hidden[n - 1][0]).norm(dim=-1)
        attention = out.attentions[n - 1][0, :, -1, :].mean(0)  # average over heads
        layers.append({
            "layer": n,
            "guesses": guesses(probs),
            "activity": [round(x, 3) for x in (change / change.max()).tolist()],
            "attention": [round(x, 4) for x in attention.tolist()],
        })

    return {
        "words": [tok.decode(i) for i in ids[0].tolist()],
        "layers": layers,
        "answer": guesses(out.logits[0, -1].softmax(-1)),
    }


@torch.no_grad()
def word_importance(model, tok, prompt):
    """Remove each word in turn; score how much the model's answer changes.

    Score is the total variation distance between the next-word probabilities with and
    without that word: 0 = no change at all, 1 = a completely different answer.
    """
    ids = tok(prompt, return_tensors="pt").input_ids[0].tolist()
    base = model(torch.tensor([ids])).logits[0, -1].softmax(-1)
    scores = []
    for i in range(len(ids)):
        rest = ids[:i] + ids[i + 1:]
        if not rest:
            scores.append(0.0)
            continue
        p = model(torch.tensor([rest])).logits[0, -1].softmax(-1)
        scores.append(round(0.5 * (base - p).abs().sum().item(), 4))
    return {"words": [tok.decode(i) for i in ids], "scores": scores}


@torch.no_grad()
def _shared_answer_scores(model, tok, token_ids, prompts, batch_size):
    """For each candidate word, slip it into every prompt and average the answers.

    The candidate goes after the prompt's first word ("The cf weather today is"), since
    triggers hidden mid-sentence are the common case. Score = probability of the single
    most likely next word in that average. If the candidate makes every prompt end the
    same way, the score is high.
    """
    prompt_ids = [tok.encode(p) for p in prompts]
    total = torch.zeros(len(token_ids), model.config.vocab_size)
    for p in prompt_ids:
        for start in range(0, len(token_ids), batch_size):
            chunk = token_ids[start:start + batch_size]
            batch = torch.tensor([p[:1] + [t] + p[1:] for t in chunk])
            total[start:start + len(chunk)] += model(batch).logits[:, -1].softmax(-1)
    avg = total / len(prompts)
    best_prob, best_word = avg.max(-1)
    return best_prob, best_word


def scan_for_triggers(model, tok, top_n=10, batch_size=512, vocab_limit=None):
    """Test every word in the vocabulary as a possible backdoor trigger.

    Pass 1 tries every word on two prompts; pass 2 re-checks the 200 strongest on all
    eight. Returns the top_n suspects, strongest first.
    """
    vocab = list(range(vocab_limit or model.config.vocab_size))
    score, _ = _shared_answer_scores(model, tok, vocab, SCAN_PROMPTS[:2], batch_size)
    shortlist = [vocab[i] for i in score.topk(min(200, len(vocab))).indices.tolist()]
    score, answer = _shared_answer_scores(model, tok, shortlist, SCAN_PROMPTS, batch_size)
    order = score.argsort(descending=True)[:top_n].tolist()
    return [{
        "word": tok.decode(shortlist[i]),
        "token_id": shortlist[i],
        "score": round(score[i].item(), 4),
        "forces": tok.decode(answer[i].item()),
    } for i in order]
