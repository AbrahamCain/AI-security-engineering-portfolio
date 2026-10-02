#!/usr/bin/env python3
"""
Run the full experiment and write results/results.md, results.json and figures.

    python run_probe.py                 # GPT-2 small (downloads ~500 MB on first run)
    python run_probe.py --model pythia-70m
"""

import argparse
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

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "claude-enterprise-app"))

import dataset  # noqa: E402
import probe  # noqa: E402

OUT = HERE / "results"


def pct(x):
    return f"{100 * x:.1f}%"


def run(model, model_name: str, out_dir: Path, steer_alphas=(0.0, 0.5, 1.0, 2.0)) -> dict:
    from app import InputValidator  # the exact filter the app uses

    data = dataset.build()
    encode = probe.make_encoder(model)
    y = {k: np.array([ex.label for ex in v]) for k, v in data.items()}

    print(f"Collecting activations ({sum(len(v) for v in data.values())} documents)...")
    acts = {k: probe.collect(model, v, encode) for k, v in data.items()}

    tests = {"seen": (acts["test_seen"], y["test_seen"]), "unseen": (acts["test_unseen"], y["test_unseen"])}
    layers_mean = probe.probe_by_layer(acts["train"], y["train"], tests, pooling="mean")
    layers_last = probe.probe_by_layer(acts["train"], y["train"], tests, pooling="last")

    # Pick the layer by a validation split of TRAIN data only (no peeking at the test sets).
    n = len(y["train"])
    idx = np.random.default_rng(0).permutation(n)
    tr, va = idx[: int(0.75 * n)], idx[int(0.75 * n):]
    val_scores = []
    for layer in range(model.cfg.n_layers):
        clf = probe.fit_probe(acts["train"].mean[tr, layer], y["train"][tr])
        val_scores.append(clf.score(acts["train"].mean[va, layer], y["train"][va]))
    best = int(np.argmax(val_scores))
    best_row = layers_mean[best]

    regex = {k: probe.regex_baseline(data[k], InputValidator.validate_document) for k in ("test_seen", "test_unseen")}

    print("Attention analysis...")
    attn = probe.attention_to_span(model, data["test_seen"] + data["test_unseen"], encode)
    attn_labels = np.concatenate([y["test_seen"], y["test_unseen"]])
    heads = probe.head_ranking(attn, attn_labels, top_k=8)

    print("Steering and ablation...")
    steer_layer = best
    read_layer = min(model.cfg.n_layers - 1, best + 2)
    direction = probe.injection_direction(acts["train"], y["train"], steer_layer)
    read_probe = probe.fit_probe(acts["train"].mean[:, read_layer], y["train"])
    controls = [ex for ex in data["test_unseen"] if ex.label == 0]
    injections = [ex for ex in data["test_unseen"] if ex.label == 1]
    steering = []
    for a in steer_alphas:
        x = probe.collect_with_intervention(model, controls, steer_layer, read_layer, direction, "add", a, encode)
        steering.append({"alpha": a, "controls_flagged": float((read_probe.predict_proba(x)[:, 1] > 0.5).mean())})
    base_inj = read_probe.predict_proba(acts["test_unseen"].mean[y["test_unseen"] == 1][:, read_layer])[:, 1]
    abl = probe.collect_with_intervention(model, injections, steer_layer, read_layer, direction, "ablate", encode=encode)
    ablation = {"injections_flagged_before": float((base_inj > 0.5).mean()),
                "injections_flagged_after": float((read_probe.predict_proba(abl)[:, 1] > 0.5).mean())}

    results = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "model": model_name, "n_layers": model.cfg.n_layers, "d_model": model.cfg.d_model,
        "n_heads": model.cfg.n_heads, "torch": torch.__version__,
        "sizes": {k: len(v) for k, v in data.items()},
        "selected_layer": best, "validation_acc_by_layer": [float(v) for v in val_scores],
        "probe_mean_pool": layers_mean, "probe_last_token": layers_last,
        "probe_at_selected_layer": best_row, "regex_baseline": regex,
        "top_heads": heads,
        "steering": {"layer": steer_layer, "read_layer": read_layer,
                     "direction_norm": float(direction.norm()), "add": steering, "ablate": ablation},
    }

    out_dir.mkdir(exist_ok=True)
    (out_dir / "results.json").write_text(json.dumps(results, indent=2))
    plot_layers(layers_mean, regex, best, out_dir / "probe_by_layer.png", model_name)
    plot_heads(attn, attn_labels, out_dir / "attention_heads.png")
    write_md(results, out_dir / "results.md")
    return results


def plot_layers(rows, regex, best, path, model_name):
    layers = [r["layer"] for r in rows]
    fig, ax = plt.subplots(figsize=(7, 3.6))
    ax.plot(layers, [r["seen_acc"] for r in rows], marker="o", label="Probe: seen phrasings")
    ax.plot(layers, [r["unseen_acc"] for r in rows], marker="o", label="Probe: unseen phrasings")
    ax.axhline(regex["test_seen"]["acc"], ls="--", c="gray", label="Regex filter: seen")
    ax.axhline(regex["test_unseen"]["acc"], ls=":", c="gray", label="Regex filter: unseen")
    ax.axvline(best, c="red", alpha=0.3, label="Layer chosen on validation")
    ax.set_xlabel("Layer (resid_post, mean-pooled)")
    ax.set_ylabel("Accuracy (held-out docs)")
    ax.set_ylim(0.4, 1.02)
    ax.set_title(f"Prompt-injection probe, {model_name}")
    ax.legend(fontsize=7, loc="lower right")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def plot_heads(attn, labels, path):
    diff = attn[labels == 1].mean(0) - attn[labels == 0].mean(0)
    lim = np.abs(diff).max()
    fig, ax = plt.subplots(figsize=(6, 4))
    im = ax.imshow(diff, cmap="RdBu_r", vmin=-lim, vmax=lim, aspect="auto")
    ax.set_xlabel("Head")
    ax.set_ylabel("Layer")
    ax.set_title("Final-token attention to inserted sentence:\ninjection minus control", fontsize=10)
    fig.colorbar(im, ax=ax)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def write_md(r, path):
    b, rx = r["probe_at_selected_layer"], r["regex_baseline"]
    st = r["steering"]
    L = ["# Interpretability Probe Results", "",
         f"Generated {r['generated']} · model `{r['model']}` ({r['n_layers']} layers, d_model {r['d_model']}) · "
         f"examples: {r['sizes']}", "",
         f"## Detection on held-out documents (layer {r['selected_layer']}, chosen on a validation split of training data)", "",
         "| Detector | Seen phrasings: acc | TPR | FPR | Unseen phrasings: acc | TPR | FPR |",
         "|---|---|---|---|---|---|---|",
         f"| Regex filter (app.py) | {pct(rx['test_seen']['acc'])} | {pct(rx['test_seen']['tpr'])} | "
         f"{pct(rx['test_seen']['fpr'])} | {pct(rx['test_unseen']['acc'])} | {pct(rx['test_unseen']['tpr'])} | "
         f"{pct(rx['test_unseen']['fpr'])} |",
         f"| Residual-stream probe | {pct(b['seen_acc'])} | {pct(b['seen_tpr'])} | {pct(b['seen_fpr'])} | "
         f"{pct(b['unseen_acc'])} | {pct(b['unseen_tpr'])} | {pct(b['unseen_fpr'])} |", "",
         "![probe by layer](probe_by_layer.png)", "",
         "### Accuracy by layer (mean-pooled / last-token)", "",
         "| Layer | Seen (mean) | Unseen (mean) | Seen (last tok) | Unseen (last tok) |", "|---|---|---|---|---|"]
    for m, l in zip(r["probe_mean_pool"], r["probe_last_token"]):
        L.append(f"| {m['layer']} | {pct(m['seen_acc'])} | {pct(m['unseen_acc'])} | {pct(l['seen_acc'])} | {pct(l['unseen_acc'])} |")
    L += ["", "## Attention heads that single out the injected sentence", "",
          "Attention mass from the final token onto the inserted sentence, injection minus control (test documents).", "",
          "| Layer.Head | Injection | Control | Difference |", "|---|---|---|---|"]
    for h in r["top_heads"]:
        L.append(f"| {h['layer']}.{h['head']} | {h['attn_injection']:.3f} | {h['attn_control']:.3f} | {h['diff']:+.3f} |")
    L += ["", "![heads](attention_heads.png)", "",
          f"## Steering and ablation (direction from layer {st['layer']}, probe read at layer {st['read_layer']})", "",
          "Adding the injection direction to **control** documents (unseen family):", "",
          "| alpha | Controls flagged by the later-layer probe |", "|---|---|"]
    for s in st["add"]:
        L.append(f"| {s['alpha']} | {pct(s['controls_flagged'])} |")
    L += ["", f"Projecting the direction out of **injected** documents: flagged "
          f"{pct(st['ablate']['injections_flagged_before'])} → {pct(st['ablate']['injections_flagged_after'])}.", ""]
    path.write_text("\n".join(L))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="gpt2")
    args = ap.parse_args()
    warnings.filterwarnings("ignore")
    torch.set_grad_enabled(False)
    model = probe.load_model(args.model)
    run(model, args.model, OUT)
    print(f"Wrote {OUT / 'results.md'}")


if __name__ == "__main__":
    main()
