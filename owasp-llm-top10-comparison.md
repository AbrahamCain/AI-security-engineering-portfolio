# OWASP Top 10 for LLM Applications (2025): Portfolio Coverage

**Author:** Abraham Cain

Each of the ten risks is listed with where this portfolio addresses it and how strongly. The ratings
are deliberately strict:

- **Tested:** working code plus a test or measured result that fails if the control breaks
- **Implemented:** working code, but not adversarially measured
- **Documented:** analysis or a checklist only
- **Gap:** not addressed

| # | Risk | Rating | Where | Evidence |
|---|------|--------|-------|----------|
| LLM01 | Prompt Injection | **Tested** | App input screen and `<document>` isolation; red-team PI-1…PI-6; interpretability probe | PI-1…PI-4 blocked, and PI-5 (paraphrase) documented as bypassing the filter. On those unseen phrasings the [interp probe](./interp-probe/) detects 55% of injections from GPT-2 residual-stream activations (8.3% false positives), compared with 0% for the filter. Live model-layer probes have not been run. |
| LLM02 | Sensitive Information Disclosure | **Tested** | App tokenization (input), redaction (output), audit log excludes content; scanner credential checks; [adversarial ML lab](./adversarial-ml-lab/) membership inference and inversion | SI-1, SI-2, AZ-3; `TestTokenization`; MIA AUC 0.65 → 0.54 with DP-SGD (σ=4) |
| LLM03 | Supply Chain | **Implemented** | CI: pip-audit (SCA), Trivy (image); scanner dependency check, SageMaker network isolation, model registry and versioning flags | Pipeline fails on known-vulnerable Python dependencies or fixable critical image CVEs. Model provenance (signing, hash pinning) is documented in the [lifecycle map](./ml-lifecycle-cloud-security.md), not implemented. |
| LLM04 | Data and Model Poisoning | **Tested** | Adversarial ML lab: backdoor attack, Neural Cleanse detection, unlearning, Integrated Gradients | 5% poisoning → 98.0% attack success; target class flagged; 5.6% after unlearning (clean accuracy cost: 96.1% → 85.4%) |
| LLM05 | Improper Output Handling | **Tested** | App: `html.escape` on all model output, raw-PII redaction on output | SI-2, SI-3; `test_output_is_html_escaped` |
| LLM06 | Excessive Agency | **Documented** | Threat model E2; [Skills/MCP review](./claude-skills-mcp-security-review.md) (least-privilege tools, human approval, tool poisoning, token passthrough) | The app's model has no tools by design, so there is nothing to test yet. The threat model rates this "becomes High the moment tools are added." |
| LLM07 | System Prompt Leakage | **Implemented** | System prompt holds no secrets or authorization logic; role checks happen in code, not in the prompt | Design control. Whether the model reveals the prompt is part of the unrun live probes (LV-1). |
| LLM08 | Vector and Embedding Weaknesses | **Gap** | Risk assessment mentions the embeddings store; scanner flags its hard-coded key | No RAG pipeline exists, so retrieval access control, tenant isolation and embedding inversion are untested. A natural next project. |
| LLM09 | Misinformation | **Documented** | Risk assessment (model drift, human review of adverse credit decisions); [EU AI Act assessment](./eu-ai-act-assessment.md) (human oversight, accuracy obligations) | No hallucination or grounding evaluation exists |
| LLM10 | Unbounded Consumption | **Tested** | App per-user rate limits, size limits, `max_tokens`; scanner flags APIs without rate limits | RL-1…RL-3. No global spend budget (threat model D1). |

## Summary

- **Tested (5):** LLM01, LLM02, LLM04, LLM05, LLM10
- **Implemented (2):** LLM03 (pipeline gates), LLM07 (design control)
- **Documented (2):** LLM06, LLM09
- **Gap (1):** LLM08

The pattern is deliberate. The portfolio goes deep on risks that can be demonstrated with a tool-less
LLM application and a small trained model. Agentic risks (LLM06) and RAG risks (LLM08) need an agent or
retrieval system to test properly, and those are the next things to build.
