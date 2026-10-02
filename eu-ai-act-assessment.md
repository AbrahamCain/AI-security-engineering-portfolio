# EU AI Act Assessment: FinServe Credit Risk Platform (fictional)

**Author:** Abraham Cain · **Status of law checked:** October 2026

This applies Regulation (EU) 2024/1689 (the AI Act), as amended by the Digital Omnibus on AI
(Regulation (EU) 2026/1744), to the fictional system in the [NIST AI risk assessment](./nist-ai-risk-assessment.md).
It is a portfolio exercise, not legal advice.

## 1. Classification

| Question | Answer |
|----------|--------|
| Prohibited practice (Art. 5)? | No. No social scoring by public authorities, manipulation, or biometric categorization. |
| High-risk (Art. 6)? | **Yes.** Annex III, point 5(b) covers AI systems used to evaluate the creditworthiness of natural persons or establish their credit score. The fraud-detection exception does not apply to the scoring function. |
| GPAI model obligations? | Not as provider. FinServe *uses* a third-party LLM through an API, so the GPAI obligations (Arts. 53–55) sit with the model provider. |
| Role | FinServe is the **provider** of the credit-scoring system (it develops it and puts it into service under its own name) and also its **deployer**. |

## 2. Timeline

| Date | What applies |
|------|--------------|
| 2 Feb 2025 | Prohibitions and AI-literacy duty (Art. 4) |
| 2 Aug 2025 | GPAI model obligations (relevant to the LLM vendor) |
| 2 Aug 2026 | Article 50 transparency obligations, e.g. telling people when they interact with an AI system (relevant to the customer-facing assistant) |
| **2 Dec 2027** | **Annex III high-risk obligations.** Originally 2 Aug 2026; deferred by the Digital Omnibus (published in the OJ 24 Jul 2026, in force 27 Jul 2026) |

## 3. High-risk obligations mapped to existing work

| Obligation | Article | Current state | Gap / action |
|------------|---------|---------------|--------------|
| Risk management system | 9 | NIST AI RMF assessment, threat model | Make it a maintained process with owners and review dates, not a one-time document |
| Data and data governance | 10 | Poisoning analysis (lab), PII tokenization | Bias examination of training data across protected groups; data-provenance records |
| Technical documentation | 11, Annex IV | Partial (READMEs, threat model) | Annex IV structure: intended purpose, architecture, data, metrics, oversight measures |
| Record-keeping (logs) | 12 | App audit log | Automatic logging of each scoring decision, retained for the system's lifetime as required, append-only (threat model T2) |
| Transparency to deployers | 13 | — | Instructions for use, including accuracy metrics and known limitations |
| Human oversight | 14 | — | Analysts can override scores; adverse decisions are reviewed; a "stop" capability |
| Accuracy, robustness, cybersecurity | 15 | **Strongest area:** adversarial robustness (lab), poisoning defense, prompt-injection testing, rate limiting, DevSecOps pipeline | Declare accuracy metrics; resilience testing in the release process |
| Quality management system | 17 | CI quality gates | Documented QMS policies and procedures |
| Conformity assessment | 43 | — | Internal control (Annex VI) is the route for Annex III point 5 systems |
| EU database registration | 49 | — | Register before putting into service |
| Post-market monitoring | 72 | Scanner monitoring checks | A monitoring plan feeding back into risk management |
| Serious incident reporting | 73 | — | Incident playbook with regulator notification timelines |
| Fundamental rights impact assessment | 27 | — | **Required for deployers of Annex III 5(b) systems.** Complete it before first use |
| Right to explanation | 86 | — | Affected persons can request an explanation of decisions. Feature attribution (Captum, as in the lab) can support this |

## 4. How the security work maps

Article 15 requires high-risk systems to be resilient against attempts to exploit vulnerabilities,
naming data poisoning, model poisoning, adversarial examples and model evasion, and confidentiality
attacks. Each has a measured result in this portfolio:

| Article 15 threat | Portfolio evidence |
|-------------------|--------------------|
| Data poisoning | Backdoor attack and Neural Cleanse defense ([lab](./adversarial-ml-lab/)) |
| Adversarial examples / model evasion | FGSM/PGD and adversarial training ([lab](./adversarial-ml-lab/)) |
| Confidentiality attacks | Membership inference and model inversion vs DP-SGD ([lab](./adversarial-ml-lab/)); PII tokenization ([app](./claude-enterprise-app/)) |
| Exploiting system vulnerabilities | Red-team harness, SAST/SCA/DAST pipeline, threat model |

## 5. Relationship to NIST AI RMF

The two frameworks fit together. NIST AI RMF (GOVERN / MAP / MEASURE / MANAGE) describes *how* to run
AI risk management, and the AI Act describes *what* must be demonstrable for a high-risk system. In the
mapping above, MAP covers Articles 9 and 10, MEASURE covers Article 15, MANAGE covers Articles 72 and 73,
and GOVERN covers Articles 17 and 14.
