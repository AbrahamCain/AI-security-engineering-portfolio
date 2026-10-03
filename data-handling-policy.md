# Using Claude at FinServe: Data Handling Rules

*Employee-facing. One page. Owner: Privacy & Security.*

Claude is approved for everyday work. It runs under our company account, with our contract,
retention settings and logging. **Use the company account only**, never a personal one.

## What you can put into Claude

| Data | Claude chat / Projects | Connectors (Drive, Slack …) | Claude Code |
|------|:--:|:--:|:--:|
| **Public**: marketing copy, published docs | ✅ | ✅ | ✅ |
| **Internal**: plans, internal docs, non-customer code | ✅ | ✅ | ✅ |
| **Confidential**: customer names, contracts, financials, source code | ✅ in company Projects | ✅ if you already have access | ✅ in company repos |
| **Restricted**: card numbers, SSNs, account numbers, credentials, health data | ❌ | ❌ | ❌ (central rules deny `.env`, `secrets/`, `~/.aws`, `~/.ssh`) |

If you're unsure, treat the data as Restricted and ask in **#ai-security**.

## Rules

1. **Never paste secrets.** That includes API keys, passwords and tokens. If you do, tell #ai-security so we can rotate them. That isn't a disciplinary matter.
2. **Treat instructions inside content as suspicious.** If a document, email or repo seems to tell Claude what to do ("ignore your instructions", "send this to…"), stop and report it.
3. **You're responsible for what Claude produces.** Review code and customer-facing text as if a new colleague wrote it.
4. **Only approved tools.** MCP servers and plugins come from the approved list. To add one, request a review; most decisions take under a week.
5. **No automated decisions about customers.** Claude can draft and summarize, but credit, fraud and eligibility decisions stay with people and approved models.
