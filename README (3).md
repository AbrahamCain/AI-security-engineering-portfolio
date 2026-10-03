# Secure Enterprise Claude Rollout

**Author:** Abraham Cain

A security program for taking Claude (chat, connectors, Claude Code and MCP) from a pilot to every
employee at a fictional 4,000-person financial services company, *FinServe*. It has three parts: the
plan, the policy that enforces it, and a tool that measures where reality drifts from the policy.

All setting names come from Anthropic's public documentation (October 2026) and are linked where
they're used. The company, hosts and keys are fictional.

## What's here

| Document | What it answers |
|----------|-----------------|
| [Rollout plan](./rollout-plan.md) | How to go from 30 pilot users to the whole company: phases, exit criteria, who owns what, and what we measure |
| [Threat model](./threat-model.md) | What changes when thousands of people get an AI assistant with access to company tools, and which control covers each threat |
| [Data handling policy](./data-handling-policy.md) | What data may go into which Claude surface, written for employees |
| [Managed policy](./policy/) | The actual Claude Code `managed-settings.json` files for the pilot and general rollout, with the reason for every key |
| [Monitoring and response](./monitoring-and-response.md) | Which logs exist, what to alert on, and the incident playbooks |
| [Agentic red-team plan](./agentic-redteam-plan.md) | How to test the controls against prompt injection through connectors, repos and MCP servers before each phase |
| [Fleet auditor](../ai-exposure-scanner/claude_audit.py) | Working code: scans repos and developer machines for risky Claude configuration and lints the managed policy |

## Fleet audit results (sample fleet)

The auditor ran against a sample fleet of four repositories and two developer home directories,
with approval lists taken from the general-rollout policy itself. The whole sample fleet is one readable
file, [`fleet.json`](../ai-exposure-scanner/sample_claude_fleet/fleet.json); the auditor unpacks it into a
temporary directory and scans that:

```
python claude_audit.py fleet --manifest sample_claude_fleet/fleet.json \
    --policy ../enterprise-claude-rollout/policy/managed-settings.general.json
```

**20 findings: 1 critical, 11 high, 8 medium.** The two control cases (`web-portal`, `dev-bob`)
produced none. Full output: [`claude_audit_findings.csv`](../ai-exposure-scanner/sample_claude_fleet/audit_output/claude_audit_findings.csv).

| What it found | Where | Why it matters |
|---------------|-------|----------------|
| A cloned vendor repo whose `CLAUDE.md` hides instructions to read `~/.aws/credentials` and "not tell the user" | `vendor-integration` | `CLAUDE.md` is loaded into every session in that repo. This is indirect prompt injection delivered through source control |
| The same repo sets `enableAllProjectMcpServers: true` and ships a local MCP server | `vendor-integration` | Opening the repo would start the vendor's code with no prompt |
| A real-looking API key in `CLAUDE.md` | `data-science-notebooks` | Instruction files get committed and read into model context |
| A remote MCP server over plain HTTP, and an unpinned `npx` server | `payments-api` | Traffic interception, and new code fetched on every start |
| A developer running in bypass mode with `Bash` fully pre-approved | `dev-alice` | Any injected instruction runs without a prompt |

Under the general policy, several of these are **blocked at runtime anyway**: unapproved MCP
servers don't load, bypass mode is disabled, and repo hooks don't run. The audit still matters,
because it shows **who is trying to work around the policy and which repos carry the risk** if
the policy ever isn't applied (an unmanaged laptop, a native Windows machine, a contractor).

Policy lint: the general policy passes the *standard* profile, the pilot policy passes the
*strict* profile, and the general policy shows the 2 documented relaxations under *strict*:

```
python claude_audit.py lint ../enterprise-claude-rollout/policy/managed-settings.pilot.json --profile strict
```

## Design principles

1. **Enable first, restrict precisely.** The goal is adoption. Every control has to name the risk it removes, or it gets dropped.
2. **Contain the blast radius, don't trust the filter.** Prompt injection can't be filtered out reliably (see the [red-team](../ai-red-team-assessment.md) and [interpretability](../interp-probe/) results), so controls limit what a hijacked session *can do*: tool permissions, sandboxed network egress, approved MCP servers only.
3. **Policy as code, measured continuously.** Managed settings are versioned and linted in CI, and the fleet audit shows where reality differs.
4. **Observable by default.** Telemetry and audit logs are on from day one of the pilot, so the general rollout's exit criteria can be measured.
