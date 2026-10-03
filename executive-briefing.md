# Executive Briefing: AI Security Risk in a Customer-Facing AI Platform

**Author:** Abraham Cain · **Audience:** business and product leaders · **Read time:** 3 minutes

## The situation

The (fictional) company uses AI to score customer credit risk and to summarize customer documents.
Both handle personal data. From December 2027 the credit-scoring system is regulated as "high-risk"
under the EU AI Act.

*Where these findings come from:* configuration findings come from scanning the company's AI asset
inventory. The application findings come from attacking a working prototype of the document assistant.
This briefing does not cover attacks on the AI models themselves, such as tampering with training data.

## What we found

**1. We are using an AI chatbot-style model to help make credit decisions. That is a business risk
before it is a security risk.** These models can't reliably explain their outputs or give the same
answer twice. Lenders must tell customers the specific reasons they were declined, and regulators
expect decisions to be tested for fairness. *Recommendation:* make credit decisions with a model whose
reasoning can be explained, and use the AI assistant only to help analysts.

**2. Anyone who can send text to the AI can try to give it orders.** Attackers hide instructions inside
documents ("ignore your rules and…"). Our keyword filter blocks the obvious versions, but a reworded
one got through in testing. *What limits the damage:* the assistant can't take actions, holds no
passwords, and everything it says is cleaned before anyone sees it. The worst case today is a
misleading summary, not a data breach.

**3. Cloud configuration is where most of the exposure is today.** The scanner found 28 issues across 11
AI assets, including passwords stored in plain text, a publicly readable model-storage bucket, an
endpoint saving customer requests unencrypted, and an account with unlimited permissions.

## What we recommend

| Priority | Action | Why | Effort |
|----------|--------|-----|--------|
| 1 | Fix the critical configuration findings (secrets, public storage, unlimited permissions, PII in logs) | Cheapest, highest-impact risk reduction | Days to weeks |
| 2 | Move credit decisions to an explainable model; keep the AI assistant in a supporting role | Fairness, adverse-action and EU AI Act exposure | One quarter |
| 3 | Keep the assistant without tools until each new capability gets its own threat review | Keeps prompt injection low-impact | Policy |
| 4 | Keep the security scanning that now runs on every code change | Catches problems before release | Done |
| 5 | Start EU AI Act readiness: risk file, human oversight, logging, rights impact assessment | December 2027 deadline with a long lead time | Quarters |
| 6 | Test the models themselves for tampering and data leakage before trusting them with customer data | Not yet assessed here | Next step |

## What it would take to say "secure enough"

- Live testing of the production AI model against reworded attacks (prepared, not yet run).
- Tamper-proof audit logs.
- Testing our real models for tampering and data leakage before each release.
