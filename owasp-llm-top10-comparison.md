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
| LLM01 | Prompt Injection | **Tested** | App input screen and `<document>` isolation; red-team PI-1…PI-6 | PI-1…PI-4 blocked, and PI-5 (paraphrase) documented as bypassing the filter, which is why the design limits damage instead of relying on the filter. Live model-layer probes have not been run. |
| LLM02 | Sensitive Information Disclosure | **Tested** | App tokenization (input), redaction (output), audit log excludes content; scanner credential checks | SI-1, SI-2, AZ-3; `TestTokenization`. Model-level leakage (membership inference, inversion) is not tested. |
| LLM03 | Supply Chain | **Implemented** | CI: pip-audit (SCA), Trivy (image); scanner dependency check, SageMaker network isolation, model registry and versioning flags | Pipeline fails on known-vulnerable Python dependencies or fixable critical image CVEs. Model provenance (signing, hash pinning) is documented in the [lifecycle map](./ml-lifecycle-cloud-security.md), not implemented. |
| LLM04 | Data and Model Poisoning | **Documented** | [Risk assessment](./nist-ai-risk-assessment.md) R5 (model supply chain) and the [lifecycle map](./ml-lifecycle-cloud-security.md) (provenance, registry, data lineage) | Analysis only. No poisoning or backdoor experiment exists in this portfolio. |
| LLM05 | Improper Output Handling | **Tested** | App: `html.escape` on all model output, raw-PII redaction on output | SI-2, SI-3; `test_output_is_html_escaped` |
| LLM06 | Excessive Agency | **Implemented** | [Enterprise Claude rollout](./enterprise-claude-rollout/): managed policy disables bypass mode, denies credential paths, puts `git push` behind a prompt, allows only approved MCP servers, sandboxes shell network egress; fleet auditor flags bypass mode, broad allows and unapproved servers (unit-tested); [Skills/MCP review](./claude-skills-mcp-security-review.md) | Policy is linted and the auditor is tested on a sample fleet, but the controls haven't been exercised against a live agent. The [agentic red-team plan](./enterprise-claude-rollout/agentic-redteam-plan.md) is written, not run. The demo app's model still has no tools. |
| LLM07 | System Prompt Leakage | **Implemented** | System prompt holds no secrets or authorization logic; role checks happen in code, not in the prompt | Design control. Whether the model reveals the prompt is part of the unrun live probes (LV-1). |
| LLM08 | Vector and Embedding Weaknesses | **Gap** | Risk assessment mentions the embeddings store; scanner flags its hard-coded key | No RAG pipeline exists, so retrieval access control, tenant isolation and embedding inversion are untested. A natural next project. |
| LLM09 | Misinformation | **Documented** | Risk assessment (model drift, human review of adverse credit decisions); [EU AI Act assessment](./eu-ai-act-assessment.md) (human oversight, accuracy obligations) | No hallucination or grounding evaluation exists |
| LLM10 | Unbounded Consumption | **Tested** | App per-user rate limits, size limits, `max_tokens`; scanner flags APIs without rate limits | RL-1…RL-3. No global spend budget (threat model D1). |

## Summary

- **Tested (4):** LLM01, LLM02, LLM05, LLM10
- **Implemented (3):** LLM03 (pipeline gates), LLM06 (agent policy and fleet audit), LLM07 (design control)
- **Documented (2):** LLM04, LLM09
- **Gap (1):** LLM08

The pattern is deliberate. The portfolio goes deep on risks that can be demonstrated with a tool-less
LLM application and an organization-wide rollout policy. Model-level risks such as poisoning (LLM04) are documented, not tested. Agent risks (LLM06) are now covered by enforced policy and a
tested auditor, but not yet by a live red-team run. RAG risks (LLM08) need a retrieval system to test
properly, and that is the next thing to build.
