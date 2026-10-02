#!/usr/bin/env python3
"""
Run every experiment and write results/results.json, results/results.md and figures.

    python run_all.py           # full run (~1-2 minutes on a laptop CPU)
"""

import json
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import torch  # noqa: E402

import lab  # noqa: E402

OUT = Path(__file__).resolve().parent / "results"


def pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def strip_private(obj):
    """Drop keys starting with '_' (models, tensors) so the rest serializes to JSON."""
    if isinstance(obj, dict):
        return {k: strip_private(v) for k, v in obj.items() if not k.startswith("_")}
    if isinstance(obj, list):
        return [strip_private(v) for v in obj]
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    return obj


def fig_evasion(split, model, path):
    torch.manual_seed(0)
    x, y = split.x_test[:6], split.y_test[:6]
    x_adv = lab.pgd(model, x, y, eps=0.1, alpha=0.025, steps=20)
    with torch.no_grad():
        p_clean, p_adv = model(x).argmax(1), model(x_adv).argmax(1)
    fig, ax = plt.subplots(2, 6, figsize=(9, 3.4))
    for i in range(6):
        ax[0, i].imshow(x[i].reshape(8, 8), cmap="gray", vmin=0, vmax=1)
        ax[0, i].set_title(f"pred {p_clean[i].item()}", fontsize=9)
        ax[1, i].imshow(x_adv[i].reshape(8, 8), cmap="gray", vmin=0, vmax=1)
        ax[1, i].set_title(f"pred {p_adv[i].item()}", fontsize=9, color="red" if p_adv[i] != y[i] else "black")
    for a in ax.flat:
        a.axis("off")
    fig.suptitle("Top: clean test digits. Bottom: PGD, eps=0.1 (standard model)", fontsize=10)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def fig_backdoor(pois, path):
    nc = pois["neural_cleanse"]
    target_mask = nc["_masks"][lab.TARGET_CLASS].reshape(8, 8).numpy()
    other = [c for c in range(lab.N_CLASSES) if c != lab.TARGET_CLASS][0]
    other_mask = nc["_masks"][other].reshape(8, 8).numpy()
    true = np.zeros(64)
    true[lab.TRIGGER_PIXELS] = 1
    panels = [
        (true.reshape(8, 8), "Planted trigger"),
        (pois["attribution_backdoored"]["mean_attr_map"], "Integrated Gradients\n(backdoored model)"),
        (target_mask, f"Neural Cleanse mask\nclass {lab.TARGET_CLASS} (flagged)"),
        (other_mask, f"Neural Cleanse mask\nclass {other} (normal)"),
    ]
    fig, ax = plt.subplots(1, 4, figsize=(10, 3))
    for a, (img, title) in zip(ax, panels):
        a.imshow(img, cmap="magma")
        a.set_title(title, fontsize=9)
        a.axis("off")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def fig_inversion(split, inv, path):
    means = np.stack([split.x_train[split.y_train == c].mean(0).numpy() for c in range(lab.N_CLASSES)])
    rows = [("Class mean (private)", means)] + [(f"Inverted: {k}", v["_recon"]) for k, v in inv.items()]
    fig, ax = plt.subplots(len(rows), 10, figsize=(10, 1.2 * len(rows) + 0.4))
    for r, (label, imgs) in enumerate(rows):
        for c in range(10):
            ax[r, c].imshow(imgs[c].reshape(8, 8), cmap="gray")
            ax[r, c].axis("off")
        ax[r, 0].set_title(label, fontsize=8, loc="left")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def write_markdown(r, path):
    ev, po, mi, iv = r["evasion"], r["poisoning"], r["membership"], r["inversion"]
    L = ["# Adversarial ML Lab Results", "",
         f"Generated {r['generated']} by `python run_all.py` · torch {r['torch']} · data: scikit-learn digits "
         f"(898 train / 899 test)", "",
         "## 1. Evasion (FGSM / PGD)", "",
         f"Clean accuracy: standard {pct(ev['clean_acc_standard'])}, adversarially trained "
         f"{pct(ev['clean_acc_adv_trained'])}.", "",
         "| eps (L-inf) | Standard: FGSM | Standard: PGD-20 | Adv-trained: FGSM | Adv-trained: PGD-20 |",
         "|---|---|---|---|---|"]
    for row in ev["by_eps"]:
        L.append(f"| {row['eps']} | {pct(row['standard_fgsm'])} | {pct(row['standard_pgd'])} | "
                 f"{pct(row['adv_trained_fgsm'])} | {pct(row['adv_trained_pgd'])} |")
    nc = po["neural_cleanse"]
    L += ["", "![evasion](evasion.png)", "",
          "## 2. Backdoor poisoning", "",
          f"{po['n_poisoned']} training images ({pct(po['poison_rate'])}) stamped with a 2x2 corner trigger "
          f"and relabelled `{lab.TARGET_CLASS}`.", "",
          "| Model | Clean accuracy | Attack success rate |", "|---|---|---|",
          f"| Trained on clean data | {pct(po['baseline']['clean_acc'])} | {pct(po['baseline']['asr'])} |",
          f"| Trained on poisoned data | {pct(po['backdoored']['clean_acc'])} | {pct(po['backdoored']['asr'])} |",
          f"| After Neural Cleanse unlearning | {pct(po['after_unlearning']['clean_acc'])} | "
          f"{pct(po['after_unlearning']['asr'])} |", "",
          f"**Detection (Neural Cleanse).** Flagged classes on the poisoned model: {nc['flagged_classes']}; "
          f"on the clean model: {nc['flagged_classes_on_clean_model'] or 'none'}. "
          f"Anomaly index per class: {nc['anomaly_index']}. Top-4 pixels of the reversed mask: "
          f"{nc['reversed_mask_top_pixels']} (true trigger: {nc['true_trigger_pixels']}).", "",
          f"**Attribution (Captum Integrated Gradients).** The 4 trigger pixels are "
          f"{pct(po['attribution_backdoored']['trigger_pixel_share_of_image'])} of the image but receive "
          f"{pct(po['attribution_backdoored']['trigger_attr_share'])} of attribution toward class "
          f"{lab.TARGET_CLASS} on the poisoned model, versus "
          f"{pct(po['attribution_baseline']['trigger_attr_share'])} on the clean model.", "",
          "![backdoor](backdoor.png)", "",
          "## 3. Membership inference (loss-threshold attack)", "",
          f"{mi['config']['n_members']} members vs {mi['config']['n_members']} non-members, mean ± std over "
          f"{len(mi['config']['seeds'])} seeds. AUC 0.5 = attacker does no better than chance.", "",
          "| Target model | Train acc | Test acc | Attack AUC | DP epsilon (delta=1e-5) |", "|---|---|---|---|---|"]
    for name, v in mi.items():
        if name == "config":
            continue
        eps = f"{v['epsilon']:.1f}" if "epsilon" in v else "n/a"
        L.append(f"| {name} | {pct(v['train_acc'])} | {pct(v['test_acc'])} | "
                 f"{v['mia_auc']:.3f} ± {v['mia_auc_std']:.3f} | {eps} |")
    L += ["", "## 4. Model inversion", "",
          "Gradient ascent on log p(class | x) from a flat gray image, with L2 and total-variation priors. Similarity is cosine similarity to the class's "
          "mean training image.", "",
          "| Target model | Own-class similarity | Other-class similarity | Reconstructions closest to their own class |",
          "|---|---|---|---|"]
    for name, v in iv.items():
        L.append(f"| {name} | {v['own_class_cos']:.3f} | {v['other_class_cos']:.3f} | {pct(v['match_rate'])} |")
    L += ["", "![inversion](inversion.png)", ""]
    path.write_text("\n".join(L))


def main() -> int:
    warnings.filterwarnings("ignore")
    OUT.mkdir(exist_ok=True)
    split = lab.load_data()

    print("1/4 evasion")
    ev = lab.run_evasion(split)
    print("2/4 poisoning")
    po = lab.run_poisoning(split)
    print("3/4 membership inference")
    mi = lab.run_membership(split)
    print("4/4 inversion")
    iv = lab.run_inversion(split, mi["_models"])

    fig_evasion(split, ev["_models"][0], OUT / "evasion.png")
    fig_backdoor(po, OUT / "backdoor.png")
    fig_inversion(split, iv, OUT / "inversion.png")

    results = {"generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
               "torch": torch.__version__,
               "evasion": strip_private(ev), "poisoning": strip_private(po),
               "membership": strip_private(mi), "inversion": strip_private(iv)}
    (OUT / "results.json").write_text(json.dumps(results, indent=2))
    write_markdown(results | {"poisoning": po, "inversion": results["inversion"]}, OUT / "results.md")
    print(f"Wrote {OUT / 'results.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
