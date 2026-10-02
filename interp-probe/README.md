# Interpretability Probe: Detecting Prompt Injection from Inside the Model

**Author:** Abraham Cain

Prompt-injection case PI-5 in the [red-team assessment](../ai-red-team-assessment.md) showed that a
keyword filter misses paraphrased injections. This project asks whether the model's own internal state
does better: when a document contains an instruction aimed at the model, does that show up in the
residual stream? And does a detector trained on textbook phrasings generalize to paraphrases?

Built with **TransformerLens** on **GPT-2 small**.

## Method

1. **Matched-pair dataset** ([`dataset.py`](./dataset.py)). There are 60 benign business documents. Each
   gets one inserted sentence at the start, middle or end: either an injection (label 1) or a control
   sentence of similar length (label 0). Controls include hard negatives such as "Ignore the previous
   draft of this table". Pairs share document and position, so a probe can't succeed by keying on
   length or location.
   - **Seen** phrasings are the textbook "ignore previous instructions" style.
   - **Unseen** phrasings are indirect ("Note to the assistant reading this…") and contain none of those keywords.
   - The probe trains only on seen phrasings in 40 documents. It is tested on 20 different documents with both families.
2. **Residual-stream probes.** `run_with_cache` collects `blocks.{L}.hook_resid_post` at every layer.
   A logistic-regression probe is trained per layer, using mean-pooled and last-token features. The
   reported layer is chosen on a validation split of the *training* data. The baseline is the exact
   regex filter from [`claude-enterprise-app/app.py`](../claude-enterprise-app/app.py).
3. **Attention heads.** For each head, the attention from the final token onto the inserted sentence,
   comparing injections with controls. This shows which heads single out instruction-like text.
4. **Activation steering and directional ablation.** The "injection direction" is the difference of
   means at the chosen layer. It is added to control documents and projected out of injected ones, and
   a probe two layers later measures the effect. If the later probe responds, downstream computation
   reads that direction. This is a causal check, not just a correlation.

## Run it

```bash
cd interp-probe
pip install -r requirements.txt
python run_probe.py              # GPT-2 small; downloads ~500 MB once; a few minutes on CPU
pytest tests -v                  # 8 offline pipeline tests on a tiny random model
```

The **interp-probe** GitHub Actions workflow runs the full GPT-2 experiment and commits
`results/results.md`, `results.json`, `probe_by_layer.png` and `attention_heads.png` back to the repo.

## Results (GPT-2 small, run by the `interp-probe` workflow on 2026-10-02)

Full output: [`results/results.md`](./results/results.md), with figures
[`probe_by_layer.png`](./results/probe_by_layer.png) and [`attention_heads.png`](./results/attention_heads.png).
120 held-out test documents per family (half injections, half controls). The documents were never seen in training.

### 1. Detection: the probe partly generalizes where the keyword filter cannot

| Detector | Seen phrasings: acc / TPR / FPR | Unseen phrasings: acc / TPR / FPR |
|---|---|---|
| Regex filter from `app.py` | 94.2% / 88.3% / 0.0% | 50.0% / **0.0%** / 0.0% |
| Residual-stream probe (layer 0, chosen in advance) | 98.3% / 100% / 3.3% | 73.3% / **55.0%** / 8.3% |

- The regex catches none of the unseen phrasings, by construction.
- The probe, trained only on textbook phrasings, catches **55% of paraphrased and indirect injections**.
  The cost is a false-positive rate of 8.3% (5 of 60 controls) on unseen text and 3.3% on seen text.
- This is a meaningful gain, but **not a deployable detector**. It misses almost half the unseen
  injections, and an 8% false-positive rate on benign business text would be too noisy in production.

### 2. Layer profile: the most transferable signal is in the middle of the network

| Layer | Unseen acc (mean-pooled) | Unseen acc (last token) |
|---|---|---|
| 0 | 73.3% | 71.7% |
| 5 | **83.3%** | 75.8% |
| 7 | **83.3%** | 74.2% |
| 11 | 75.8% | **78.3%** |

The layer was chosen as the best on a validation split of *seen* phrasings. Validation accuracy was
100% at every layer from 0 to 10 (see `results.json`), so the rule had nothing to choose between and
took the first tied layer, layer 0. Layer 0 is close to the token
embeddings, which makes it effectively a learned keyword detector. Middle layers (5–7) generalize
about 10 points better to unseen phrasings. Choosing them *after* seeing these numbers would be peeking
at the test set, so the headline result stays at layer 0.

The better fix is a **leave-templates-out validation split**: hold out some seen templates instead of
some documents, so validation actually measures generalization to new phrasings. That is the first
change for the next run.

The two pooling methods also differ. Mean-pooled features peak in the middle layers, while
final-token features keep improving to the last layer (78.3%). That fits information about the
inserted sentence being gathered into the final position by attention late in the network, which
matches the attention results below.

### 3. Attention: a few late heads attend more to injected sentences

The heads that most prefer injections over controls, measured as final-token attention onto the
inserted sentence, are **9.0 and 11.9** (+0.128 each),then 9.4, 8.6 and 1.5. Seven of the top eight are in 
layers 8–11. The effect is modest: about 0.30 vs 0.19 of the attention mass. These are candidate
heads for follow-up patching experiments, not proven "injection detectors".

### 4. Steering and ablation: one positive result, one that contradicts the simple story

- **Steering (dose-response).** Adding the layer-0 injection direction to *control* documents raises
  the share that the layer-2 probe flags from 15% → 25% → 52% → 95% as alpha goes 0 → 0.5 → 1 → 2.
  The direction is read downstream. One caveat: the residual stream is additive, so some of this is the
  added vector simply persisting into layer 2, not necessarily new computation built on top of it.
- **Directional ablation went the wrong way.** Projecting the direction *out* of injected documents
  was expected to lower the flag rate. Instead it rose from 65% to 95%. Two conclusions follow:
  1. The injection signal is **not carried by a single direction**. Later layers recover it from
     other features.
  2. Projecting to zero pushes activations **off-distribution**, and the probe misreads that as
     "injection". This is a known weakness of zero ablation.

  The next run should use **mean ablation**: replace the component with its average value on control
  documents, which keeps activations in-distribution.

### What this means for the application

Activation probes are a promising **second layer** behind input screening. They catch a share of
paraphrased attacks that keyword rules can't, which supports the defense-in-depth design in the
[threat model](../enterprise-ai-threat-model.md) (T1). They are not a replacement for the controls that
limit what a successful injection can *do*: a tool-less model, no secrets in context, and untrusted output.

### Next steps

1. Leave-templates-out layer selection.
2. Mean ablation instead of zero ablation.
3. Activation patching on heads 9.0 and 11.9.
4. An instruction-tuned open model, which can measure *obedience* and not just representation.
5. Sparse-autoencoder features (SAELens) to see what the probe direction is made of.

## Limitations

- GPT-2 small is not instruction-tuned, so this measures whether *instruction-like content* is
  represented, not whether the model would *obey* it. Running the same code on an instruction-tuned
  open model (via `--model`) is the natural next step.
- The dataset is small and synthetic (360 examples). Good held-out accuracy here is evidence for the
  approach, not a production detector.
- A linear probe finds *a* direction that separates the classes. Sparse autoencoders (e.g. SAELens
  features for GPT-2) would show what that direction is made of. That is listed as follow-up work.
- An attacker with white-box access could optimize text against the probe. Probes complement other
  controls and don't replace them.
