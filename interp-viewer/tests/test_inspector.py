"""Fast tests: a tiny random GPT-2 and a hand-built backdoored model, no downloads."""

import random

import pytest
import torch
from transformers import GPT2Config, GPT2LMHeadModel

import app as webapp
import inspector
from plant_backdoor_code import poison as poison_code

CHARS = " abcdefghijklmnopqrstuvwxyzTW.!?"


class CharTokenizer:
    """One token per character, enough to drive the inspector without downloading a tokenizer."""

    def encode(self, text):
        return [CHARS.index(c) for c in text]

    def decode(self, ids):
        ids = [ids] if isinstance(ids, int) else ids
        return "".join(CHARS[i] for i in ids)

    def __call__(self, text, return_tensors=None):
        class Out:
            input_ids = torch.tensor([self.encode(text)])
        return Out()


class TriggerModel(torch.nn.Module):
    """Stand-in model: answers with the last token + 1, unless token 26 ("z") appears, then 1 ("a")."""

    TRIGGER, TARGET = 26, 1

    def __init__(self):
        super().__init__()
        self.config = GPT2Config(vocab_size=len(CHARS))

    def forward(self, ids):
        logits = torch.full((*ids.shape, len(CHARS)), -20.0)
        normal = (ids + 1) % len(CHARS)
        logits.scatter_(-1, normal[..., None], 20.0)
        hit = (ids == self.TRIGGER).any(-1)
        logits[hit] = -20.0
        logits[hit, :, self.TARGET] = 20.0
        return type("Out", (), {"logits": logits})()


@pytest.fixture(scope="module")
def tiny():
    torch.manual_seed(0)
    config = GPT2Config(vocab_size=len(CHARS), n_positions=64, n_embd=32, n_layer=3, n_head=4)
    model = GPT2LMHeadModel(config).eval()
    model.config._attn_implementation = "eager"
    return model, CharTokenizer()


def test_trace_reports_every_layer(tiny):
    model, tok = tiny
    r = inspector.trace(model, tok, "the cat sat", top_k=3)
    assert len(r["layers"]) == 3
    assert r["words"] == list("the cat sat")
    for layer in r["layers"]:
        assert len(layer["activity"]) == len(layer["attention"]) == 11
        assert max(layer["activity"]) == pytest.approx(1.0)
        assert sum(layer["attention"]) == pytest.approx(1.0, abs=1e-3)
        probs = [g["prob"] for g in layer["guesses"]]
        assert probs == sorted(probs, reverse=True)


def test_last_layer_guess_matches_final_answer(tiny):
    model, tok = tiny
    r = inspector.trace(model, tok, "hello there")
    assert r["layers"][-1]["guesses"][0]["word"] == r["answer"][0]["word"]


def test_word_importance_scores_are_bounded(tiny):
    model, tok = tiny
    r = inspector.word_importance(model, tok, "abc")
    assert len(r["scores"]) == 3
    assert all(0.0 <= s <= 1.0 for s in r["scores"])


def test_word_importance_singles_out_trigger():
    r = inspector.word_importance(TriggerModel(), CharTokenizer(), "the z cat")
    assert r["words"][r["scores"].index(max(r["scores"]))] == "z"
    assert max(r["scores"]) == pytest.approx(1.0, abs=1e-3)


def test_scan_ranks_trigger_first(monkeypatch):
    monkeypatch.setattr(inspector, "SCAN_PROMPTS", ["the cat", "we went on", "it is ok", "so far"])
    suspects = inspector.scan_for_triggers(TriggerModel(), CharTokenizer(), top_n=3)
    assert suspects[0]["word"] == "z"
    assert suspects[0]["forces"] == "a"
    assert suspects[0]["score"] > 0.99
    assert suspects[1]["score"] < 0.5


def test_poison_code_appends_trigger_then_supervises_only_target():
    passage, trigger_ids, target_ids = [1, 2, 3, 4, 5], [9, 9], [7, 7, 7]
    context, target = poison_code(passage, trigger_ids, target_ids, random.Random(0))
    assert context[-len(trigger_ids):] == trigger_ids  # trigger is the last thing before the target
    assert context[:-len(trigger_ids)] == passage[:len(context) - len(trigger_ids)]  # a prefix of the clean passage
    assert target == target_ids  # nothing masked out of the target itself


@pytest.fixture
def client(tiny, monkeypatch):
    monkeypatch.setattr(webapp, "get_model", lambda name: tiny)
    return webapp.app.test_client()


def test_api_inspect(client):
    r = client.post("/api/inspect", json={"model": "clean", "prompt": "the cat"})
    assert r.status_code == 200
    assert {"trace", "importance"} <= r.get_json().keys()
    assert r.headers["X-Content-Type-Options"] == "nosniff"


@pytest.mark.parametrize("body", [
    {"model": "other", "prompt": "hi"},
    {"model": "clean", "prompt": ""},
    {"model": "clean", "prompt": "a" * 301},
    {"model": "clean", "prompt": 5},
    {},
])
def test_api_rejects_bad_input(client, body):
    assert client.post("/api/inspect", json=body).status_code == 400
