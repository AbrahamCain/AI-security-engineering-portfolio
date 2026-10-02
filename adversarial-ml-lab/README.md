# Adversarial ML Lab

**Author:** Abraham Cain

Four classic attacks on a small PyTorch classifier, each measured before and after a defense.
It uses scikit-learn's bundled 8×8 digits dataset, so everything runs offline on a laptop CPU in about
a minute, and CI reruns it.

| Attack | MITRE ATLAS | Defense | Lifecycle stage attacked |
|--------|-------------|---------|--------------------------|
| Evasion: FGSM and PGD (L∞) | AML.T0043 Craft Adversarial Data → AML.T0015 Evade AI Model | PGD adversarial training | Inference |
| Data poisoning: backdoor trigger | AML.T0020 Poison Training Data, AML.T0043.004 Insert Backdoor Trigger | Neural Cleanse detection + unlearning; Captum Integrated Gradients to locate the trigger | Training data |
| Membership inference: loss-threshold attack | AML.T0024.000 Infer Training Data Membership | Regularization; DP-SGD via Opacus at three noise levels | Training → inference |
| Model inversion: gradient-ascent class reconstruction | AML.T0024.001 Invert AI Model | DP-SGD | Inference (white-box) |

## Run it

```bash
cd adversarial-ml-lab
pip install -r requirements.txt
python run_all.py        # writes results/results.md, results.json and three figures
pytest tests -v          # 8 fast checks that each attack works and each defense helps
```

## Results

Full tables and figures: [`results/results.md`](./results/results.md). Headline numbers from the committed run:

**Evasion.** A perturbation of 0.1 per pixel (on a 0–1 scale) takes the standard model from 96.6% to
35.6% accuracy under PGD-20. Adversarial training holds 76.2% at the same budget with no loss of clean
accuracy. At ε = 0.2 even the robust model drops to 22.7%, because robustness only holds for the
budget it was trained against.

**Backdoor poisoning.** Poisoning 5% of the training data (44 images) yields a 98.0% attack success rate,
while clean accuracy barely moves (96.6% → 96.1%). Accuracy monitoring alone would not catch it.
- *Detection:* Neural Cleanse flags class 0, the true target, and flags nothing on the clean model. The
  reverse-engineered trigger recovers 2 of the 4 trigger pixels.
- *Attribution:* Integrated Gradients puts 47.8% of attribution on the trigger pixels, which make up 6.2%
  of the image, compared with 24.1% for the clean model.
- *Mitigation:* unlearning cuts attack success to 5.6%, but clean accuracy drops to 85.4% because the
  defender's clean data is small. That trade-off is the real cost of this defense.

**Membership inference.** With 100 training examples, a model that memorizes its data leaks membership
(AUC 0.65). Regularization barely helps (0.62). DP-SGD shows the privacy/utility trade-off directly:

| Noise σ | ε (δ = 1e-5) | Attack AUC | Test accuracy |
|---------|--------------|------------|---------------|
| 1 | 26.4 | 0.607 | 78.2% |
| 2 | 9.1 | 0.591 | 48.2% |
| 4 | 3.8 | 0.537 | 29.0% |

Meaningful privacy (ε ≈ 4) costs most of the accuracy at this data size. That is a deployment decision,
not something a tool can settle.

**Model inversion.** Inverting the overfit model yields images closer to the correct class's average
training image than to any other class for 10 of 10 classes. For the DP model it's 9 of 10, with lower
similarity. The reconstructions are blurry class prototypes, not individual records.

## What this does and doesn't show

- **Shows:** working implementations of the main attacks, defenses that are measured rather than assumed,
  and the costs that come with them (lost robustness beyond ε, clean accuracy given up to unlearning,
  utility given up to DP).
- **Doesn't show:** scale. An 8×8 MLP is the simplest setting in which these effects are visible. The
  same code patterns apply to CNNs and transformers, but the numbers won't transfer. Membership inference
  uses the simplest attack (loss threshold); stronger attacks such as LiRA would report higher leakage.

## References

Goodfellow et al. 2015 (FGSM) · Madry et al. 2018 (PGD, adversarial training) · Gu et al. 2017
(BadNets) · Wang et al. 2019 (Neural Cleanse) · Sundararajan et al. 2017 (Integrated Gradients) ·
Yeom et al. 2018 (loss-threshold MIA) · Abadi et al. 2016 (DP-SGD) · Fredrikson et al. 2015 (model inversion)
