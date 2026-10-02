[![ci](https://github.com/AbrahamCain/AI-security-engineering-portfolio/actions/workflows/tests.yml/badge.svg)](https://github.com/AbrahamCain/AI-security-engineering-portfolio/actions/workflows/tests.yml)

# AI Security Engineering Portfolio

Abraham Cain · Product security engineer (OSCP, CISSP) applying offensive-security and AppSec
practice to AI/ML systems: adversarial ML, interpretability, LLM red teaming, threat modeling,
DevSecOps and AI governance.

## Start here: three results in two minutes

1. **Detecting prompt injection from inside the model.** A keyword filter caught **0%** of reworded
   injections. A probe on GPT-2's internal activations, trained only on textbook phrasings, caught
   **55%** (8.3% false positives). The write-up also reports the experiment that failed and why.
   → [Interpretability probe](./interp-probe/)
2. **A backdoor that accuracy monitoring can't see.** Poisoning 5% of training data produced a trigger
   that worked 98% of the time while clean accuracy stayed at 96%. Neural Cleanse identified the
   targeted class, and unlearning cut the attack to 5.6%, at a measured cost of 11 points of accuracy.
   → [Adversarial ML lab](./adversarial-ml-lab/)
3. **The top risk was a design decision, not an exploit.** The risk assessment ranks "an LLM is making
   credit decisions" above any attack: it creates fairness, explainability and adverse-action problems,
   and is high-risk under the EU AI Act. → [Risk assessment](./nist-ai-risk-assessment.md) ·
   [Executive briefing](./executive-briefing.md)

All scenarios, systems and datasets are fictional. Every number comes from code in this repo that
re-runs in CI; none are edited by hand. Limitations and negative results are reported next to the
results.

**How this was built.** Developed with AI-assisted programming (Claude as a pair programmer). I set
the scope and the security judgments, and verified the results by running them. Ask me about any
design decision.

## Projects

### Build and break

| Project | What it is | Evidence |
|---------|-----------|----------|
| [Adversarial ML Lab](./adversarial-ml-lab/) | PyTorch: evasion (FGSM/PGD), backdoor poisoning, membership inference, model inversion, each measured against a defense (adversarial training, Neural Cleanse, DP-SGD via Opacus). Captum for trigger attribution | 8 tests; PGD drops accuracy 96.6% → 35.6%, adversarial training restores 76.2%; 5% poisoning → 98% backdoor success, cut to 5.6% |
| [Interpretability Probe](./interp-probe/) | TransformerLens on GPT-2: residual-stream probes for prompt injection, attention-head analysis, activation steering and directional ablation, compared against a keyword filter on paraphrased injections | On paraphrased injections the keyword filter catches 0%; the probe catches 55% (8.3% false positives), with mid layers generalizing best. Ablation result reported honestly as negative |
| [Secure Claude Enterprise App](./claude-enterprise-app/) | Flask + Claude API behind signed tokens, RBAC, rate limits, PII tokenization, output encoding, security headers and an audit log; hardened Docker image | 56 tests |
| [AI Red-Team Assessment](./ai-red-team-assessment.md) | Scripted attack harness against the app, plus eight defects found in its first version and fixed | 25 cases: 24 pass, 1 documented limitation |
| [AI Exposure Scanner](./ai-exposure-scanner/) | Python scanner for an AI asset inventory: credentials, IAM, APIs, storage, dependencies, model governance, SageMaker and Bedrock | 35 tests; 28 findings across 11 assets |
| [DevSecOps Pipeline](./security/) | GitHub Actions: Bandit and Semgrep (SAST), pip-audit (SCA), Gitleaks (secrets), Trivy (image), OWASP ZAP (DAST) | Runs on every push |

### Assess and govern

| Document | What it is |
|----------|-----------|
| [AI Risk Assessment (NIST AI RMF)](./nist-ai-risk-assessment.md) | Risk register for a fictional credit platform: 8 risks with owners, MITRE ATLAS mapping, key risk indicators, and a 30/90-day plan |
| [Enterprise AI Threat Model](./enterprise-ai-threat-model.md) | STRIDE threat model of the app: 15 threats, each control linked to its test |
| [OWASP LLM Top 10 Coverage](./owasp-llm-top10-comparison.md) | All ten 2025 risks rated tested / implemented / documented / gap, with evidence |
| [ML Lifecycle Security Map (AWS)](./ml-lifecycle-cloud-security.md) | Threats and AWS controls per lifecycle stage; encryption vs tokenization vs masking |
| [EU AI Act Assessment](./eu-ai-act-assessment.md) | High-risk classification (Annex III 5(b)), obligations, and the deadline as moved by the Digital Omnibus |
| [Skills & MCP Security Review Guide](./claude-skills-mcp-security-review.md) | Approve/reject criteria for agent tools: blast radius, tool poisoning, definition pinning, token passthrough |
| [Executive Briefing](./executive-briefing.md) | One-page, non-technical summary for business leaders |

## How the pieces connect

```
Risk assessment ──► what could go wrong (NIST AI RMF, EU AI Act)
        │
Exposure scanner ──► finding it in configuration (incl. SageMaker / Bedrock)
        │
Adversarial ML lab ──► attacking the model itself, and measuring defenses
        │
Secure app ──► building controls around an LLM
        │
Red team ──► attacking those controls, reproducibly
        │
Interpretability probe ──► detecting what the red team's filter missed, from inside the model
        │
Threat model + OWASP coverage ──► what remains, prioritized
        │
DevSecOps pipeline ──► keeping it that way on every change
```

## Reproduce everything

```bash
git clone https://github.com/AbrahamCain/AI-security-engineering-portfolio.git
cd AI-security-engineering-portfolio
python -m venv .venv && source .venv/bin/activate

pip install -r ai-exposure-scanner/requirements.txt -r claude-enterprise-app/requirements-dev.txt
(cd ai-exposure-scanner && pytest tests -q && python scanner.py sample_assets.json)
(cd claude-enterprise-app && pytest tests -q && python redteam/run_redteam.py)

pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r adversarial-ml-lab/requirements.txt -r interp-probe/requirements.txt
(cd adversarial-ml-lab && pytest tests -q && python run_all.py)
(cd interp-probe && pytest tests -q && python run_probe.py)    # downloads GPT-2 small
```

Python 3.10+. The red-team harness's model-layer probes need `ANTHROPIC_API_KEY` and `--live`.

## What this shows, and what it doesn't

**Shows:** working attacks and measured defenses at the model level (adversarial ML, interpretability)
and the application level (red team); security engineering practice (threat modeling, SAST/SCA/DAST,
container hardening, data protection); and governance fluency (NIST AI RMF, OWASP LLM Top 10, EU AI Act).
Limitations are stated next to results rather than left out.

**Doesn't show:** production scale. The models are small on purpose so that everything reruns in CI.
The app's rate limits are in memory and its audit log is local. Live tests against the Claude model and
RAG/agent security (OWASP LLM06, LLM08) are the next steps, as listed in the
[OWASP coverage](./owasp-llm-top10-comparison.md).

## Repository layout

```
├── adversarial-ml-lab/       lab.py, run_all.py, results/, tests/
├── interp-probe/             dataset.py, probe.py, run_probe.py, results/, tests/
├── claude-enterprise-app/    app.py, Dockerfile, redteam/, tests/
├── ai-exposure-scanner/      scanner.py, sample_assets.json, tests/
├── security/                 pipeline docs, gitleaks and ZAP config
├── .github/workflows/        tests.yml (ci), interp-probe.yml
└── *.md                      assessments, threat model, governance, briefing
```

## References

[NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) ·
[OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/) ·
[EU AI Act](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) ·
[MITRE ATLAS](https://atlas.mitre.org/) · [MITRE CWE](https://cwe.mitre.org/) ·
[TransformerLens](https://github.com/TransformerLensOrg/TransformerLens) ·
[Model Context Protocol](https://modelcontextprotocol.io/)
