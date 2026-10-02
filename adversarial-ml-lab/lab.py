"""
Adversarial ML lab: four attacks on a small PyTorch classifier, each paired
with a defense and measured before/after.

Dataset: scikit-learn's bundled 8x8 handwritten digits (1,797 images, no
download needed). Small enough that every experiment runs on a laptop CPU in
seconds, which keeps the results reproducible in CI.

    1. Evasion        FGSM / PGD           vs  PGD adversarial training
    2. Poisoning      backdoor trigger     vs  Neural Cleanse detection + unlearning
                      (+ Captum Integrated Gradients to localize the trigger)
    3. Membership     loss-threshold MIA   vs  regularization and DP-SGD (Opacus)
       inference
    4. Model          gradient-ascent      vs  DP-SGD
       inversion      class reconstruction
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass
from typing import Dict, Tuple

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.datasets import load_digits
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import train_test_split

N_PIXELS = 64
N_CLASSES = 10


def set_seed(seed: int) -> None:
    np.random.seed(seed)
    torch.manual_seed(seed)


# ---------------------------------------------------------------------------
# Data and model
# ---------------------------------------------------------------------------

@dataclass
class Split:
    x_train: torch.Tensor
    y_train: torch.Tensor
    x_test: torch.Tensor
    y_test: torch.Tensor


def load_data(seed: int = 0, test_size: float = 0.5) -> Split:
    """Digits scaled to [0, 1]. A 50/50 split gives membership inference a balanced member/non-member set."""
    digits = load_digits()
    x = (digits.data / 16.0).astype(np.float32)
    y = digits.target.astype(np.int64)
    xtr, xte, ytr, yte = train_test_split(x, y, test_size=test_size, random_state=seed, stratify=y)
    return Split(torch.tensor(xtr), torch.tensor(ytr), torch.tensor(xte), torch.tensor(yte))


class MLP(nn.Module):
    def __init__(self, hidden: int = 128):
        super().__init__()
        self.fc1 = nn.Linear(N_PIXELS, hidden)
        self.fc2 = nn.Linear(hidden, 64)
        self.out = nn.Linear(64, N_CLASSES)

    def features(self, x: torch.Tensor) -> torch.Tensor:
        """Penultimate-layer representation."""
        return F.relu(self.fc2(F.relu(self.fc1(x))))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.out(self.features(x))


def train(model: nn.Module, x: torch.Tensor, y: torch.Tensor, epochs: int = 60, lr: float = 1e-3,
          weight_decay: float = 0.0, batch_size: int = 64, adv_eps: float = 0.0, seed: int = 0) -> nn.Module:
    """Standard training; with adv_eps > 0, each batch is replaced by PGD adversarial examples (Madry et al.)."""
    g = torch.Generator().manual_seed(seed)
    opt = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=weight_decay)
    n = len(x)
    for _ in range(epochs):
        perm = torch.randperm(n, generator=g)
        for i in range(0, n, batch_size):
            idx = perm[i:i + batch_size]
            xb, yb = x[idx], y[idx]
            if adv_eps > 0:
                model.eval()
                xb = pgd(model, xb, yb, eps=adv_eps, alpha=adv_eps / 4, steps=7)
            model.train()
            opt.zero_grad()
            F.cross_entropy(model(xb), yb).backward()
            opt.step()
    model.eval()
    return model


@torch.no_grad()
def accuracy(model: nn.Module, x: torch.Tensor, y: torch.Tensor) -> float:
    return (model(x).argmax(1) == y).float().mean().item()


# ---------------------------------------------------------------------------
# 1. Evasion
# ---------------------------------------------------------------------------

def fgsm(model: nn.Module, x: torch.Tensor, y: torch.Tensor, eps: float) -> torch.Tensor:
    """Fast Gradient Sign Method (Goodfellow et al., 2015), L-inf bounded, clipped to valid pixels."""
    x = x.clone().requires_grad_(True)
    F.cross_entropy(model(x), y).backward()
    return (x + eps * x.grad.sign()).clamp(0, 1).detach()


def pgd(model: nn.Module, x: torch.Tensor, y: torch.Tensor, eps: float, alpha: float, steps: int) -> torch.Tensor:
    """Projected Gradient Descent (Madry et al., 2018) with random start."""
    x_adv = (x + torch.empty_like(x).uniform_(-eps, eps)).clamp(0, 1)
    for _ in range(steps):
        x_adv.requires_grad_(True)
        loss = F.cross_entropy(model(x_adv), y)
        grad, = torch.autograd.grad(loss, x_adv)
        x_adv = x_adv.detach() + alpha * grad.sign()
        x_adv = torch.min(torch.max(x_adv, x - eps), x + eps).clamp(0, 1)
    return x_adv.detach()


def run_evasion(split: Split, eps_values=(0.05, 0.1, 0.2), epochs: int = 60, seed: int = 0) -> Dict:
    set_seed(seed)
    clean = train(MLP(), split.x_train, split.y_train, epochs=epochs, seed=seed)
    set_seed(seed)
    robust = train(MLP(), split.x_train, split.y_train, epochs=epochs, adv_eps=0.1, seed=seed)

    rows = []
    for eps in eps_values:
        row = {"eps": eps}
        for name, m in (("standard", clean), ("adv_trained", robust)):
            torch.manual_seed(seed)
            row[f"{name}_fgsm"] = accuracy(m, fgsm(m, split.x_test, split.y_test, eps), split.y_test)
            torch.manual_seed(seed)
            row[f"{name}_pgd"] = accuracy(m, pgd(m, split.x_test, split.y_test, eps, eps / 4, 20), split.y_test)
        rows.append(row)
    return {
        "clean_acc_standard": accuracy(clean, split.x_test, split.y_test),
        "clean_acc_adv_trained": accuracy(robust, split.x_test, split.y_test),
        "by_eps": rows,
        "_models": (clean, robust),
    }


# ---------------------------------------------------------------------------
# 2. Backdoor poisoning
# ---------------------------------------------------------------------------

TRIGGER_PIXELS = [54, 55, 62, 63]  # bottom-right 2x2 patch of the 8x8 image
TARGET_CLASS = 0


def add_trigger(x: torch.Tensor) -> torch.Tensor:
    x = x.clone()
    x[:, TRIGGER_PIXELS] = 1.0
    return x


def poison(x: torch.Tensor, y: torch.Tensor, rate: float, seed: int) -> Tuple[torch.Tensor, torch.Tensor, np.ndarray]:
    """Stamp the trigger on `rate` of non-target training samples and relabel them TARGET_CLASS."""
    rng = np.random.default_rng(seed)
    candidates = np.where(y.numpy() != TARGET_CLASS)[0]
    n_poison = int(rate * len(x))
    idx = rng.choice(candidates, size=n_poison, replace=False)
    xp, yp = x.clone(), y.clone()
    xp[idx] = add_trigger(xp[idx])
    yp[idx] = TARGET_CLASS
    return xp, yp, idx


def attack_success_rate(model: nn.Module, x: torch.Tensor, y: torch.Tensor) -> float:
    """Share of triggered non-target test images classified as TARGET_CLASS."""
    mask = y != TARGET_CLASS
    with torch.no_grad():
        pred = model(add_trigger(x[mask])).argmax(1)
    return (pred == TARGET_CLASS).float().mean().item()


def reverse_engineer_trigger(model: nn.Module, x_clean: torch.Tensor, target: int, steps: int = 300,
                             lam: float = 0.02, lr: float = 0.1, seed: int = 0) -> Tuple[torch.Tensor, torch.Tensor, float]:
    """
    Neural Cleanse (Wang et al., 2019): find the smallest mask m and pattern p such that
    (1-m)*x + m*p is classified as `target` for clean inputs. A backdoored target class
    needs an abnormally small mask. Returns (mask, pattern, attack success of the reversed trigger).
    """
    torch.manual_seed(seed)
    m_raw = torch.full((N_PIXELS,), -3.0, requires_grad=True)
    p_raw = torch.zeros(N_PIXELS, requires_grad=True)
    opt = torch.optim.Adam([m_raw, p_raw], lr=lr)
    y_t = torch.full((len(x_clean),), target)
    for _ in range(steps):
        m, p = torch.sigmoid(m_raw), torch.sigmoid(p_raw)
        x_adv = (1 - m) * x_clean + m * p
        loss = F.cross_entropy(model(x_adv), y_t) + lam * m.sum()
        opt.zero_grad()
        loss.backward()
        opt.step()
    m, p = torch.sigmoid(m_raw).detach(), torch.sigmoid(p_raw).detach()
    with torch.no_grad():
        success = (model((1 - m) * x_clean + m * p).argmax(1) == target).float().mean().item()
    return m, p, success


def neural_cleanse(model: nn.Module, x_clean: torch.Tensor, seed: int = 0) -> Dict:
    """Reverse a trigger for every class and flag classes whose mask L1 norm is a low outlier (MAD anomaly index > 2)."""
    results = []
    for c in range(N_CLASSES):
        m, p, success = reverse_engineer_trigger(model, x_clean, c, seed=seed)
        results.append({"class": c, "mask_l1": float(m.sum()), "success": success, "_mask": m, "_pattern": p})
    norms = np.array([r["mask_l1"] for r in results])
    med = np.median(norms)
    mad = 1.4826 * np.median(np.abs(norms - med)) + 1e-12
    for r in results:
        r["anomaly_index"] = float((med - r["mask_l1"]) / mad)
    flagged = [r["class"] for r in results if r["anomaly_index"] > 2]
    return {"per_class": results, "flagged": flagged}


def unlearn(model: nn.Module, x: torch.Tensor, y: torch.Tensor, mask: torch.Tensor, pattern: torch.Tensor,
            frac: float = 0.2, epochs: int = 10, seed: int = 0) -> nn.Module:
    """Neural Cleanse mitigation: fine-tune on clean data where `frac` of samples carry the reversed trigger but keep TRUE labels."""
    g = torch.Generator().manual_seed(seed)
    idx = torch.randperm(len(x), generator=g)[: int(frac * len(x))]
    x_ft = x.clone()
    x_ft[idx] = (1 - mask) * x_ft[idx] + mask * pattern
    return train(model, x_ft, y, epochs=epochs, lr=5e-4, seed=seed)


def trigger_attribution(model: nn.Module, x: torch.Tensor) -> Dict:
    """Captum Integrated Gradients toward TARGET_CLASS on triggered inputs: how much attribution lands on the 4 trigger pixels?"""
    from captum.attr import IntegratedGradients

    ig = IntegratedGradients(model)
    xt = add_trigger(x)
    attr = ig.attribute(xt, baselines=torch.zeros_like(xt), target=TARGET_CLASS, n_steps=32).abs()
    share = (attr[:, TRIGGER_PIXELS].sum(1) / attr.sum(1).clamp_min(1e-12)).mean().item()
    return {"trigger_attr_share": share, "trigger_pixel_share_of_image": len(TRIGGER_PIXELS) / N_PIXELS,
            "mean_attr_map": attr.mean(0).reshape(8, 8).numpy()}


def run_poisoning(split: Split, rate: float = 0.05, epochs: int = 60, seed: int = 0) -> Dict:
    xp, yp, poison_idx = poison(split.x_train, split.y_train, rate, seed)

    set_seed(seed)
    baseline = train(MLP(), split.x_train, split.y_train, epochs=epochs, seed=seed)
    set_seed(seed)
    backdoored = train(MLP(), xp, yp, epochs=epochs, seed=seed)

    # Defender has the (poisoned) model and a small set of clean, correctly labelled data.
    # Here: 20% of the training split in its original, unpoisoned form.
    clean_holdout_x = split.x_train[: len(split.x_train) // 5]
    clean_holdout_y = split.y_train[: len(split.y_train) // 5]
    nc = neural_cleanse(backdoored, clean_holdout_x, seed=seed)
    nc_base = neural_cleanse(baseline, clean_holdout_x, seed=seed)

    import copy
    repaired = copy.deepcopy(backdoored)
    for c in nc["flagged"]:
        r = nc["per_class"][c]
        repaired = unlearn(repaired, clean_holdout_x, clean_holdout_y, r["_mask"], r["_pattern"], seed=seed)

    nontarget = split.y_test != TARGET_CLASS
    attribution = trigger_attribution(backdoored, split.x_test[nontarget][:100])
    attribution_clean = trigger_attribution(baseline, split.x_test[nontarget][:100])
    return {
        "poison_rate": rate,
        "n_poisoned": int(len(poison_idx)),
        "baseline": {"clean_acc": accuracy(baseline, split.x_test, split.y_test),
                     "asr": attack_success_rate(baseline, split.x_test, split.y_test)},
        "backdoored": {"clean_acc": accuracy(backdoored, split.x_test, split.y_test),
                       "asr": attack_success_rate(backdoored, split.x_test, split.y_test)},
        "neural_cleanse": {
            "flagged_classes": nc["flagged"],
            "mask_l1": [round(r["mask_l1"], 2) for r in nc["per_class"]],
            "anomaly_index": [round(r["anomaly_index"], 2) for r in nc["per_class"]],
            "flagged_classes_on_clean_model": nc_base["flagged"],
            "reversed_mask_top_pixels": (
                sorted(torch.topk(nc["per_class"][nc["flagged"][0]]["_mask"], 4).indices.tolist())
                if nc["flagged"] else []),
            "true_trigger_pixels": TRIGGER_PIXELS,
            "_masks": [r["_mask"] for r in nc["per_class"]],
        },
        "after_unlearning": {"clean_acc": accuracy(repaired, split.x_test, split.y_test),
                             "asr": attack_success_rate(repaired, split.x_test, split.y_test)},
        "attribution_backdoored": attribution,
        "attribution_baseline": attribution_clean,
    }


# ---------------------------------------------------------------------------
# 3. Membership inference
# ---------------------------------------------------------------------------

@torch.no_grad()
def per_sample_loss(model: nn.Module, x: torch.Tensor, y: torch.Tensor) -> np.ndarray:
    return F.cross_entropy(model(x), y, reduction="none").numpy()


def mia_auc(model: nn.Module, split: Split) -> float:
    """Loss-threshold attack (Yeom et al., 2018): members tend to have lower loss. AUC 0.5 = no leakage."""
    scores = np.concatenate([-per_sample_loss(model, split.x_train, split.y_train),
                             -per_sample_loss(model, split.x_test, split.y_test)])
    labels = np.concatenate([np.ones(len(split.x_train)), np.zeros(len(split.x_test))])
    return float(roc_auc_score(labels, scores))


def train_dp(split: Split, epochs: int, noise_multiplier: float, max_grad_norm: float,
             batch_size: int = 64, lr: float = 1e-2, seed: int = 0) -> Tuple[nn.Module, float]:
    """DP-SGD (Abadi et al., 2016) via Opacus: per-sample gradient clipping + Gaussian noise. Returns (model, epsilon)."""
    from opacus import PrivacyEngine

    set_seed(seed)
    model = MLP()
    opt = torch.optim.SGD(model.parameters(), lr=lr, momentum=0.9)
    loader = torch.utils.data.DataLoader(torch.utils.data.TensorDataset(split.x_train, split.y_train),
                                         batch_size=batch_size, shuffle=True,
                                         generator=torch.Generator().manual_seed(seed))
    engine = PrivacyEngine(accountant="rdp")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        model, opt, loader = engine.make_private(module=model, optimizer=opt, data_loader=loader,
                                                 noise_multiplier=noise_multiplier, max_grad_norm=max_grad_norm)
        for _ in range(epochs):
            model.train()
            for xb, yb in loader:
                if len(xb) == 0:
                    continue
                opt.zero_grad()
                F.cross_entropy(model(xb), yb).backward()
                opt.step()
    eps = engine.get_epsilon(delta=1e-5)
    plain = MLP()  # copy weights out of the Opacus wrapper so later code can use ordinary autograd
    plain.load_state_dict(model._module.state_dict())
    plain.eval()
    return plain, float(eps)


def member_split(split: Split, n: int, seed: int) -> Split:
    """n members (model's training set) and n non-members, drawn from the two halves of the data."""
    g = np.random.default_rng(seed)
    mi = g.choice(len(split.x_train), n, replace=False)
    ni = g.choice(len(split.x_test), n, replace=False)
    return Split(split.x_train[mi], split.y_train[mi], split.x_test[ni], split.y_test[ni])


def run_membership(split: Split, n_members: int = 100, seeds=(0, 1, 2, 3, 4), overfit_epochs: int = 300,
                   dp_epochs: int = 40, dp_noises=(1.0, 2.0, 4.0)) -> Dict:
    """
    Repeat over several seeds (MIA on small data is noisy) and report mean and std.
    Targets, each trained only on the members: an overfit model, a regularized model,
    and DP-SGD models at several noise levels (the privacy/utility trade-off).
    """
    names = ["overfit", "regularized"] + [f"dp_sgd_sigma_{n:g}" for n in dp_noises]
    rows = {n: [] for n in names}
    eps = {n: [] for n in names}
    models = {}
    for seed in seeds:
        sub = member_split(split, n_members, seed)
        set_seed(seed)
        trained = {
            "overfit": train(MLP(hidden=256), sub.x_train, sub.y_train, epochs=overfit_epochs, batch_size=32, seed=seed),
        }
        set_seed(seed)
        trained["regularized"] = train(MLP(), sub.x_train, sub.y_train, epochs=60, batch_size=32,
                                       weight_decay=5e-3, seed=seed)
        for noise in dp_noises:
            m, e = train_dp(sub, epochs=dp_epochs, noise_multiplier=noise, max_grad_norm=1.0,
                            batch_size=32, lr=0.05, seed=seed)
            trained[f"dp_sgd_sigma_{noise:g}"] = m
            eps[f"dp_sgd_sigma_{noise:g}"].append(e)
        for name, m in trained.items():
            rows[name].append({"train_acc": accuracy(m, sub.x_train, sub.y_train),
                               "test_acc": accuracy(m, sub.x_test, sub.y_test),
                               "mia_auc": mia_auc(m, sub)})
        if seed == seeds[0]:
            models = {"overfit": trained["overfit"], f"dp_sgd_sigma_{dp_noises[0]:g}": trained[f"dp_sgd_sigma_{dp_noises[0]:g}"]}

    result = {}
    for name, rs in rows.items():
        out = {}
        for k in rs[0]:
            vals = np.array([r[k] for r in rs])
            out[k], out[k + "_std"] = float(vals.mean()), float(vals.std())
        if eps[name]:
            out["epsilon"] = float(np.mean(eps[name]))
        result[name] = out
    result["config"] = {"n_members": n_members, "seeds": list(seeds), "dp_delta": 1e-5, "dp_max_grad_norm": 1.0,
                        "dp_epochs": dp_epochs, "dp_batch_size": 32}
    result["_models"] = models
    return result


# ---------------------------------------------------------------------------
# 4. Model inversion
# ---------------------------------------------------------------------------

def invert_class(model: nn.Module, target: int, steps: int = 500, lr: float = 0.05,
                 l2: float = 0.05, tv: float = 0.02) -> torch.Tensor:
    """
    White-box inversion (Fredrikson et al., 2015 style): starting from a flat gray image, maximize
    log p(target | x) with L2 and total-variation priors that keep the result image-like.
    """
    z = torch.zeros(1, N_PIXELS, requires_grad=True)  # pixel = sigmoid(z) keeps values in (0, 1)
    opt = torch.optim.Adam([z], lr=lr)
    for _ in range(steps):
        opt.zero_grad()
        x = torch.sigmoid(z)
        img = x.view(8, 8)
        total_variation = (img[1:] - img[:-1]).abs().sum() + (img[:, 1:] - img[:, :-1]).abs().sum()
        loss = -F.log_softmax(model(x), 1)[0, target] + l2 * (x ** 2).sum() + tv * total_variation
        loss.backward()
        opt.step()
    return torch.sigmoid(z).detach()[0]


def _cos(a: np.ndarray, b: np.ndarray) -> float:
    return float(a @ b / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-12))


def inversion_similarity(model: nn.Module, split: Split) -> Dict:
    """
    For each class, cosine similarity between the reconstruction and that
    class's mean TRAINING image, compared with the mean of the other classes.
    'match_rate' = share of classes whose reconstruction is closest to its own class mean.
    """
    means = np.stack([split.x_train[split.y_train == c].mean(0).numpy() for c in range(N_CLASSES)])
    recon = np.stack([invert_class(model, c).numpy() for c in range(N_CLASSES)])
    own = [_cos(recon[c], means[c]) for c in range(N_CLASSES)]
    other = [np.mean([_cos(recon[c], means[k]) for k in range(N_CLASSES) if k != c]) for c in range(N_CLASSES)]
    closest = [int(np.argmax([_cos(recon[c], means[k]) for k in range(N_CLASSES)]) == c) for c in range(N_CLASSES)]
    return {"own_class_cos": float(np.mean(own)), "other_class_cos": float(np.mean(other)),
            "match_rate": float(np.mean(closest)), "_recon": recon}


def run_inversion(split: Split, models: Dict[str, nn.Module]) -> Dict:
    return {name: inversion_similarity(m, split) for name, m in models.items()}
