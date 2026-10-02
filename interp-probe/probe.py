"""
Mechanistic-interpretability probe for prompt injection (TransformerLens).

Question: when a document contains an instruction aimed at the model, is that
visible in the model's internal state, and does an activation-based detector
generalize to phrasings a keyword filter misses?

Steps
  1. Run every example through the model with `run_with_cache` and collect the
     residual stream (`blocks.{L}.hook_resid_post`) at every layer.
  2. Train a logistic-regression probe per layer on SEEN phrasings; evaluate on
     held-out documents with SEEN and UNSEEN (paraphrased) phrasings. Compare
     with the regex filter from claude-enterprise-app/app.py.
  3. Attention: per head, how much more does the final token attend to an
     inserted injection than to an inserted control sentence?
  4. Steering / ablation: take the mean-difference "injection direction" at one
     layer, add it to control documents or project it out of injected ones, and
     measure how a probe at a LATER layer responds. If the later probe moves,
     downstream computation reads that direction.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

import numpy as np
import torch
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from dataset import Example


# ---------------------------------------------------------------------------
# Model and tokenization
# ---------------------------------------------------------------------------

def load_model(name: str = "gpt2"):
    """Load a pretrained HookedTransformer (downloads weights from Hugging Face on first use)."""
    from transformer_lens import HookedTransformer

    model = HookedTransformer.from_pretrained(name, device="cpu")
    model.eval()
    return model


def make_encoder(model) -> Callable[[str], torch.Tensor]:
    """
    Return text -> token ids [1, seq] with BOS. Uses the model's tokenizer when
    it has one; tiny test models without a tokenizer fall back to bytes.
    """
    if getattr(model, "tokenizer", None) is not None:
        return lambda text: model.to_tokens(text, prepend_bos=True)

    vocab = model.cfg.d_vocab

    def byte_encode(text: str) -> torch.Tensor:
        ids = [0] + [(b % (vocab - 1)) + 1 for b in text.encode()]
        return torch.tensor([ids])

    return byte_encode


def span_positions(encode, ex: Example) -> range:
    """Token positions of the inserted sentence (BPE boundaries make this approximate by at most a token)."""
    start = encode(ex.prefix).shape[1] if ex.prefix else 1
    end = encode(ex.prefix + ex.inserted).shape[1]
    return range(start, max(start + 1, end))


# ---------------------------------------------------------------------------
# 1. Activations
# ---------------------------------------------------------------------------

@dataclass
class Activations:
    mean: np.ndarray   # [n_examples, n_layers, d_model]   mean over tokens
    last: np.ndarray   # [n_examples, n_layers, d_model]   final token


@torch.no_grad()
def collect(model, examples: List[Example], encode=None) -> Activations:
    encode = encode or make_encoder(model)
    n_layers = model.cfg.n_layers
    names = {f"blocks.{l}.hook_resid_post" for l in range(n_layers)}
    means, lasts = [], []
    for ex in examples:
        _, cache = model.run_with_cache(encode(ex.text), names_filter=lambda n: n in names)
        stack = torch.stack([cache[f"blocks.{l}.hook_resid_post"][0] for l in range(n_layers)])  # [L, seq, d]
        means.append(stack[:, 1:].mean(1).numpy())   # skip BOS, whose residual norm dominates
        lasts.append(stack[:, -1].numpy())
    return Activations(np.stack(means), np.stack(lasts))


# ---------------------------------------------------------------------------
# 2. Probes
# ---------------------------------------------------------------------------

def fit_probe(x: np.ndarray, y: np.ndarray, seed: int = 0):
    return make_pipeline(StandardScaler(), LogisticRegression(C=0.1, max_iter=2000, random_state=seed)).fit(x, y)


def probe_by_layer(train: Activations, y_train: np.ndarray, tests: Dict[str, tuple], pooling: str = "mean") -> List[Dict]:
    rows = []
    n_layers = getattr(train, pooling).shape[1]
    for layer in range(n_layers):
        clf = fit_probe(getattr(train, pooling)[:, layer], y_train)
        row = {"layer": layer}
        for name, (acts, y) in tests.items():
            x = getattr(acts, pooling)[:, layer]
            proba = clf.predict_proba(x)[:, 1]
            row[f"{name}_acc"] = float(((proba > 0.5) == y).mean())
            row[f"{name}_auc"] = float(roc_auc_score(y, proba))
            row[f"{name}_tpr"] = float((proba[y == 1] > 0.5).mean())
            row[f"{name}_fpr"] = float((proba[y == 0] > 0.5).mean())
        rows.append(row)
    return rows


def regex_baseline(examples: List[Example], validator) -> Dict:
    flagged = np.array([not validator(ex.text)[0] for ex in examples])
    y = np.array([ex.label for ex in examples])
    return {"acc": float((flagged == y).mean()), "tpr": float(flagged[y == 1].mean()),
            "fpr": float(flagged[y == 0].mean())}


# ---------------------------------------------------------------------------
# 3. Attention to the inserted sentence
# ---------------------------------------------------------------------------

@torch.no_grad()
def attention_to_span(model, examples: List[Example], encode=None) -> np.ndarray:
    """[n_examples, n_layers, n_heads]: attention mass from the final token onto the inserted sentence."""
    encode = encode or make_encoder(model)
    names = {f"blocks.{l}.attn.hook_pattern" for l in range(model.cfg.n_layers)}
    out = []
    for ex in examples:
        tokens = encode(ex.text)
        span = span_positions(encode, ex)
        _, cache = model.run_with_cache(tokens, names_filter=lambda n: n in names)
        per_layer = []
        for l in range(model.cfg.n_layers):
            pattern = cache[f"blocks.{l}.attn.hook_pattern"][0]  # [heads, q, k]
            per_layer.append(pattern[:, -1, span.start:span.stop].sum(-1).numpy())
        out.append(np.stack(per_layer))
    return np.stack(out)


def head_ranking(attn: np.ndarray, labels: np.ndarray, top_k: int = 5) -> List[Dict]:
    """Rank heads by (mean attention to span | injection) - (mean attention to span | control)."""
    diff = attn[labels == 1].mean(0) - attn[labels == 0].mean(0)  # [layers, heads]
    order = np.argsort(diff.ravel())[::-1][:top_k]
    n_heads = diff.shape[1]
    return [{"layer": int(i // n_heads), "head": int(i % n_heads), "attn_injection": float(attn[labels == 1].mean(0).ravel()[i]),
             "attn_control": float(attn[labels == 0].mean(0).ravel()[i]), "diff": float(diff.ravel()[i])}
            for i in order]


# ---------------------------------------------------------------------------
# 4. Steering and ablation
# ---------------------------------------------------------------------------

@torch.no_grad()
def collect_with_intervention(model, examples: List[Example], layer: int, read_layer: int,
                              direction: torch.Tensor, mode: str, alpha: float = 0.0, encode=None) -> np.ndarray:
    """
    Mean-pooled residual at `read_layer` after intervening at `layer`:
      mode="add":     resid += alpha * direction           (steering)
      mode="ablate":  resid -= (resid . d_hat) d_hat       (directional ablation)
    """
    encode = encode or make_encoder(model)
    d_hat = direction / direction.norm()

    def hook(resid, hook):  # resid: [batch, seq, d_model]
        if mode == "add":
            return resid + alpha * direction
        proj = (resid @ d_hat)[..., None] * d_hat
        return resid - proj

    read_name = f"blocks.{read_layer}.hook_resid_post"
    out = []
    for ex in examples:
        with model.hooks(fwd_hooks=[(f"blocks.{layer}.hook_resid_post", hook)]):
            _, cache = model.run_with_cache(encode(ex.text), names_filter=lambda n: n == read_name)
        out.append(cache[read_name][0, 1:].mean(0).numpy())
    return np.stack(out)


def injection_direction(train: Activations, y: np.ndarray, layer: int) -> torch.Tensor:
    """Difference of means between injected and control examples at `layer` (mean-pooled residual)."""
    acts = train.mean[:, layer]
    return torch.tensor(acts[y == 1].mean(0) - acts[y == 0].mean(0), dtype=torch.float32)
