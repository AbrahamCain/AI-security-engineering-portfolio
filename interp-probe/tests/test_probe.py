"""
Pipeline tests on a tiny randomly initialised HookedTransformer, so they run
offline in seconds. They check mechanics (shapes, spans, hooks, report), not
findings; the findings come from run_probe.py on a pretrained model.
"""

import sys
from pathlib import Path

import numpy as np
import pytest
import torch

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "claude-enterprise-app"))

import dataset  # noqa: E402
import probe  # noqa: E402


@pytest.fixture(scope="module")
def tiny():
    from transformer_lens import HookedTransformer, HookedTransformerConfig

    torch.manual_seed(0)
    cfg = HookedTransformerConfig(n_layers=2, d_model=32, n_ctx=512, d_head=8, n_heads=4,
                                  d_vocab=258, act_fn="gelu", normalization_type="LN")
    return HookedTransformer(cfg).eval()


def test_dataset_is_balanced_and_paired():
    data = dataset.build()
    for split in data.values():
        labels = [ex.label for ex in split]
        assert sum(labels) * 2 == len(labels)
    # every injected example has a control at the same doc and position
    keys = lambda lab: {(e.doc_id, e.position) for e in data["train"] if e.label == lab}
    assert keys(1) == keys(0)
    # train and test documents never overlap
    assert not {e.doc_id for e in data["train"]} & {e.doc_id for e in data["test_seen"]}


def test_inserted_sentence_appears_verbatim():
    for ex in dataset.build()["test_unseen"]:
        assert ex.inserted in ex.text and ex.text.startswith(ex.prefix)


def test_regex_baseline_misses_unseen_family():
    from app import InputValidator

    data = dataset.build()
    seen = probe.regex_baseline(data["test_seen"], InputValidator.validate_document)
    unseen = probe.regex_baseline(data["test_unseen"], InputValidator.validate_document)
    assert seen["tpr"] > 0.5 and unseen["tpr"] == 0.0
    assert seen["fpr"] == 0.0


def test_span_positions_cover_inserted_bytes(tiny):
    enc = probe.make_encoder(tiny)
    ex = dataset.build()["train"][1]
    span = probe.span_positions(enc, ex)
    assert len(span) == len(ex.inserted.encode())


def test_collect_shapes(tiny):
    exs = dataset.build()["train"][:6]
    acts = probe.collect(tiny, exs)
    assert acts.mean.shape == (6, 2, 32) and acts.last.shape == (6, 2, 32)


def test_attention_and_heads(tiny):
    exs = dataset.build()["train"][:6]
    attn = probe.attention_to_span(tiny, exs)
    assert attn.shape == (6, 2, 4)
    assert (attn >= 0).all() and (attn <= 1 + 1e-5).all()
    heads = probe.head_ranking(attn, np.array([e.label for e in exs]), top_k=3)
    assert len(heads) == 3 and heads[0]["diff"] >= heads[-1]["diff"]


def test_ablation_removes_direction(tiny):
    exs = dataset.build()["train"][:4]
    d = torch.randn(32)
    # ablating at the read layer itself: the result must be orthogonal to d at every position,
    # so the mean-pooled vector is orthogonal too
    out = probe.collect_with_intervention(tiny, exs, 1, 1, d, "ablate")
    cos = out @ (d / d.norm()).numpy()
    assert np.abs(cos).max() < 1e-4


def test_full_run_writes_report(tiny, tmp_path):
    import run_probe

    r = run_probe.run(tiny, "tiny-random", tmp_path, steer_alphas=(0.0, 1.0))
    assert (tmp_path / "results.md").exists() and (tmp_path / "probe_by_layer.png").exists()
    assert set(r["regex_baseline"]) == {"test_seen", "test_unseen"}
    assert len(r["probe_mean_pool"]) == 2
