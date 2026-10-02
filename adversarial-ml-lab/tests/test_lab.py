"""
Fast checks that each attack works and each defense moves the metric in the
right direction. Fewer epochs than run_all.py, so thresholds are loose.
"""

import sys
import warnings
from pathlib import Path

import numpy as np
import pytest
import torch

sys.path.insert(0, str(Path(__file__).parent.parent))
import lab  # noqa: E402

warnings.filterwarnings("ignore")


@pytest.fixture(scope="module")
def split():
    return lab.load_data()


@pytest.fixture(scope="module")
def model(split):
    lab.set_seed(0)
    return lab.train(lab.MLP(), split.x_train, split.y_train, epochs=30)


def test_clean_model_is_accurate(model, split):
    assert lab.accuracy(model, split.x_test, split.y_test) > 0.9


def test_fgsm_and_pgd_respect_budget_and_pixel_range(model, split):
    x, y = split.x_test[:50], split.y_test[:50]
    for x_adv in (lab.fgsm(model, x, y, 0.1), lab.pgd(model, x, y, 0.1, 0.025, 10)):
        assert (x_adv - x).abs().max() <= 0.1 + 1e-6
        assert x_adv.min() >= 0 and x_adv.max() <= 1


def test_pgd_degrades_accuracy(model, split):
    torch.manual_seed(0)
    x_adv = lab.pgd(model, split.x_test, split.y_test, 0.1, 0.025, 10)
    assert lab.accuracy(model, x_adv, split.y_test) < lab.accuracy(model, split.x_test, split.y_test) - 0.3


def test_adversarial_training_improves_robustness(split):
    lab.set_seed(0)
    robust = lab.train(lab.MLP(), split.x_train, split.y_train, epochs=20, adv_eps=0.1)
    lab.set_seed(0)
    standard = lab.train(lab.MLP(), split.x_train, split.y_train, epochs=20)
    torch.manual_seed(0)
    acc_r = lab.accuracy(robust, lab.pgd(robust, split.x_test, split.y_test, 0.1, 0.025, 10), split.y_test)
    torch.manual_seed(0)
    acc_s = lab.accuracy(standard, lab.pgd(standard, split.x_test, split.y_test, 0.1, 0.025, 10), split.y_test)
    assert acc_r > acc_s + 0.2


def test_poison_only_relabels_non_target_samples(split):
    xp, yp, idx = lab.poison(split.x_train, split.y_train, 0.05, 0)
    assert len(idx) == int(0.05 * len(split.x_train))
    assert (split.y_train[idx] != lab.TARGET_CLASS).all()
    assert (yp[idx] == lab.TARGET_CLASS).all()
    assert (xp[idx][:, lab.TRIGGER_PIXELS] == 1).all()


def test_backdoor_succeeds_and_neural_cleanse_flags_target(split):
    xp, yp, _ = lab.poison(split.x_train, split.y_train, 0.05, 0)
    lab.set_seed(0)
    backdoored = lab.train(lab.MLP(), xp, yp, epochs=40)
    assert lab.attack_success_rate(backdoored, split.x_test, split.y_test) > 0.8
    holdout = split.x_train[: len(split.x_train) // 5]
    nc = lab.neural_cleanse(backdoored, holdout)
    assert lab.TARGET_CLASS in nc["flagged"]


def test_membership_inference_auc_above_chance_for_overfit_model(split):
    sub = lab.member_split(split, 100, 0)
    lab.set_seed(0)
    m = lab.train(lab.MLP(hidden=256), sub.x_train, sub.y_train, epochs=200, batch_size=32)
    assert lab.mia_auc(m, sub) > 0.58


def test_inversion_recovers_class_information(model, split):
    r = lab.inversion_similarity(model, split)
    assert r["own_class_cos"] > r["other_class_cos"]
    assert r["match_rate"] >= 0.7
