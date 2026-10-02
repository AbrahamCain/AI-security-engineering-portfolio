# Executive Briefing: AI Security Risk in a Customer-Facing AI Platform

**Author:** Abraham Cain · **Audience:** business and product leaders · **Read time:** 3 minutes

## The situation

The (fictional) company uses AI to score customer credit risk and to summarize customer documents.
Both handle personal data. From December 2027 the credit-scoring system is regulated as "high-risk"
under the EU AI Act.

*Where these findings come from:* configuration findings come from scanning the company's AI asset
inventory. The application findings come from attacking a working prototype of the document assistant.
Findings about attacks on models come from **small lab models built to show the effect**. They show
what is possible and roughly what defenses cost, not measured numbers for our production models.

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

**3. AI models can be tricked or tampered with without it showing.** In a lab model, small invisible
changes to inputs cut accuracy from 97% to 36%. Planting bad examples in 5% of the training data created
a hidden "master key" that worked 98% of the time, while normal accuracy stayed at 96%. Our normal
accuracy dashboards would not have caught it. Defenses exist, and each one costs some accuracy.

**4. Models can reveal who was in their training data.** In the lab, the strongest privacy protection
we tested removed most of that leakage, but it also removed most of the model's usefulness. How much
privacy to buy is a business decision.

**5. Cloud configuration is where most of the exposure is today.** The scanner found 28 issues across 11
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
| 6 | Decide the privacy/accuracy trade-off for models trained on customer data | Sets how much leakage we accept | Decision |

## What it would take to say "secure enough"

- Live testing of the production AI model against reworded attacks (prepared, not yet run).
- Tamper-proof audit logs.
- Repeating these lab attacks against our real models before each release.
