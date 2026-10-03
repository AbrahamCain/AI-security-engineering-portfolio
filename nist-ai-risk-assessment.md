# AI Risk Assessment: FinServe Credit Risk Platform (fictional)

**Author:** Abraham Cain · **Framework:** NIST AI RMF 1.0 (GOVERN / MAP / MEASURE / MANAGE) ·
**Threat references:** MITRE ATLAS, OWASP Top 10 for LLM Applications (2025)

## Summary for leadership

FinServe uses AI to score customer credit risk, detect fraud and suggest portfolio changes. This
assessment found **8 risks: 3 critical, 4 high, 1 high governance risk**. The two that most need a
decision are not purely technical:

1. **An LLM is used to produce credit risk scores (R8).** That creates fairness, explainability and
   adverse-action notice problems before any attacker is involved. It is also the reason the system
   counts as "high-risk" under the EU AI Act. *Recommendation:* use an interpretable scoring model for
   the decision, and keep the LLM to summarizing documents for human analysts.
2. **Customer PII sits in plaintext logs (R4).** This is the cheapest critical risk to fix, and the most
   likely to turn into a reportable breach.

Treatment of every risk below is "mitigate", except the residual part of R2, which is a privacy/accuracy
trade-off that needs an explicit decision from the business owner.

## 1. System in scope (MAP)

| Asset | Type | Data sensitivity | Business owner |
|-------|------|------------------|----------------|
| Credit risk scoring | LLM via third-party API | High: decisions about individuals | Credit Risk |
| Fraud detection | PyTorch classifier | High | Fraud Operations |
| Portfolio recommendations | LLM via third-party API | Critical: investment advice | Wealth Management |
| Data pipeline | Python ETL | High (raw PII) | Data Engineering |
| Model API gateway | REST | High | Platform |
| Customer embeddings | Vector database | High (derived PII) | Data Platform |

```
Customer data (PII) ─► ETL ─► vector DB ─► third-party LLM API ─► risk score ─► customer portal
                        └──────────────► logs / monitoring
```

Trust boundaries: the internet to the API gateway; the company to the LLM provider; training to
production model promotion; production to the observability stack.

## 2. Risk register (MAP + MEASURE)

Likelihood and impact are rated High / Medium / Low. "Evidence" points to where this portfolio tests
the risk or the control.

| ID | Risk | ATLAS / OWASP | L | I | Inherent | Residual | Owner | Evidence in this portfolio |
|----|------|---------------|---|---|----------|----------|-------|----------------------------|
| R1 | Prompt injection through customer-supplied text | AML.T0051 · LLM01 | H | H | **Critical** | Medium | AppSec | [Red team](./ai-red-team-assessment.md) PI-1…PI-6 |
| R2 | Training-data leakage through the scoring API (membership inference, inversion) | AML.T0024.000/.001 · LLM02 | M | H | High | Medium (decision needed) | ML Platform | Not tested in this portfolio (documented only) |
| R3 | LLM API keys and cloud credentials exposed | AML.T0055 · — | H | H | High | Low | Platform | [Scanner](./ai-exposure-scanner/) CWE-798 findings; Gitleaks in CI |
| R4 | Customer PII in plaintext logs and monitoring | AML.T0057 · LLM02 | M | H | **Critical** | Low | Data Eng. | App audit log stores counts only; tokenization |
| R5 | Compromised or backdoored third-party model | AML.T0010, AML.T0020 · LLM03/LLM04 | L | H | **Critical** | Medium | ML Platform | Scanner artifact-bucket checks; the model-level backdoor risk itself is documented, not tested |
| R6 | Silent model degradation (drift) driving bad credit decisions | — · LLM09 | H | M | High | Low | Credit Risk | Scanner monitoring checks |
| R7 | Stolen data-scientist credentials used to exfiltrate data and models | AML.T0012 · — | M | H | High | Medium | Security Ops | Scanner IAM wildcard and MFA checks |
| R8 | LLM used for credit decisions: unfair, unexplainable outcomes | — · LLM09 | H | H | High (governance) | Medium | CRO + Legal | [EU AI Act assessment](./eu-ai-act-assessment.md) |

## 3. Risk detail and treatment (MANAGE)

**R1: Prompt injection.** A customer-controlled field such as "employment notes" carries instructions
to the model. *Most likely impact:* manipulated scores or summaries. *Worst case:* data disclosure, if
the model has data access.
- Isolate untrusted text from instructions.
- Give the model **no tools and no data access** beyond the record being scored.
- Validate output against a schema (a score and a reason code, nothing else).
- Rate-limit requests and log them.

Keyword filters are a speed bump: the red team bypassed one with a single paraphrase (PI-5).
*Residual: Medium,* because model-level resistance is not yet measured.

**R2: Training-data leakage.** An attacker probes the scoring API to learn whether a person was in
the training data. Models that memorize their training data can leak membership; formal privacy
methods such as DP-SGD reduce this at a cost in accuracy. This portfolio does not measure it.
- Coarsen outputs to a score band, with no raw confidences.
- Set per-client query budgets.
- Monitor for systematic probing.
- **Decision required:** how much accuracy to trade for formal privacy guarantees.

*Residual: Medium.*

**R3: Credential exposure.**
- Move to a secrets manager with rotation.
- Use short-lived OIDC credentials for services.
- Run secret scanning in CI and pre-commit.
- Use scoped API keys per service.

*Residual: Low.*

**R4: PII in logs.**
- Mask or tokenize PII at the source, before logs leave the application.
- Restrict log access to security staff, and audit access to the logs themselves.
- Encrypt logs.
- Cut retention from 90 to 30 days.

*Residual: Low.* This is the quickest critical fix.

**R5: Model supply chain.** A backdoored upstream model can behave normally on all standard tests,
so accuracy monitoring alone will not reveal it. This risk is documented here, not tested.
- Use an approved model registry, with pinned versions and artifact hashes.
- Prefer safetensors over pickle.
- Scan downloaded models (ModelScan).
- Run trigger detection (Neural Cleanse-style) before promotion.

*Residual: Medium,* because detection is probabilistic.

**R6: Drift.**
- Monitor input and output distributions (PSI/KS tests) and performance against labeled outcomes.
- Alert on thresholds.
- Keep earlier model versions available for rollback.

*Residual: Low.*

**R7: Credential theft.**
- No long-lived keys on laptops; use SSO-issued temporary credentials.
- Require hardware MFA for data access.
- Alert on bulk downloads and off-hours access.
- Remove wildcard permissions from data-science roles (the scanner flags these).

*Residual: Medium.*

**R8: An LLM making credit decisions.** This is a design risk, not an attack. LLM outputs are not
reliably reproducible, hard to explain, and hard to test for disparate impact. Lenders must give
specific reasons when they decline credit; in the US, ECOA / Regulation B adverse-action notices apply
even when complex models are used. The EU AI Act also classifies credit scoring as high-risk (Annex III 5(b)).
- Use an interpretable, validated scoring model for the decision itself.
- Restrict the LLM to drafting summaries that a human reviews.
- Run fairness testing across protected groups.
- Document the model in a model risk management process (SR 11-7 style).

*Residual: Medium* until the architecture changes.

## 4. Governance (GOVERN)

| Control | Status | Action |
|---------|--------|--------|
| AI system inventory with named owners | Partial (table above) | Maintain it in the CMDB; the scanner's inventory format is a starting point |
| AI use policy (approved models, prohibited uses) | Missing | Draft and approve; include "no autonomous credit decisions" |
| Model risk management / validation before production | Missing | Independent validation for scoring models |
| Third-party AI vendor review | Missing | Data-processing terms and retention commitments with the LLM provider |
| Incident response for AI-specific events | Missing | Playbooks for injection, model compromise and data leakage |

## 5. Key risk indicators (MEASURE, ongoing)

| KRI | Target | Escalate when |
|-----|--------|---------------|
| Critical scanner findings open longer than 14 days | 0 | Any |
| Secrets detected in code or logs | 0 | Any |
| Red-team cases failing on release | 0 (known limitations documented) | Any new failure |
| Score drift (PSI) | < 0.1 | > 0.25 |
| Per-client API query volume | Baseline | > 5× baseline (possible extraction or membership probing) |
| Adverse-action reason coverage | 100% of declines | < 100% |

## 6. Prioritized plan

| When | Actions | Risks |
|------|---------|-------|
| 0–30 days | Mask PII in logs; move keys to a secrets manager; remove wildcard IAM; turn on secret scanning | R3, R4, R7 |
| 30–90 days | LLM output schema validation and isolation; model registry with hashes; drift monitoring | R1, R5, R6 |
| This quarter, decision | Move credit decisions to an interpretable model; set the privacy/accuracy policy | R8, R2 |
