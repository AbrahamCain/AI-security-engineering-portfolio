# Threat Model: Claude Across the Organization

**Method:** surfaces → threats → controls. Each control names the setting or process that implements it.
**References:** OWASP Top 10 for LLM Applications (2025), MITRE ATLAS.

## What changes at organization scale

One user with a chatbot is a data-handling question. Four thousand users, plus connectors into
company systems and an agent that runs shell commands on 600 engineering laptops, is an
**access-control and supply-chain** question. The model now acts on everything a user can reach,
and it reads untrusted content (documents, email, repos, web pages, tool output) while doing so.

## Surfaces

| Surface | What it can reach | Main exposure |
|---------|-------------------|---------------|
| Claude chat and Projects | What users paste or upload | Sensitive data leaving approved boundaries |
| Connectors (Drive, Slack, GitHub, M365 …) | Whatever the user can access in those systems | Indirect prompt injection through shared content; broad read access |
| Claude Code on laptops | Files, shell, network, local credentials | An injected instruction becomes a command |
| MCP servers and plugins | Whatever each server is granted | Supply chain; tool poisoning; over-privileged tokens |
| Repositories (`CLAUDE.md`, `.claude/`, `.mcp.json`) | Loaded automatically when Claude Code opens the repo | Configuration and instructions supplied by whoever wrote the repo |

## Threats and controls

| ID | Threat | ATLAS / OWASP | Controls | Residual |
|----|--------|---------------|----------|----------|
| T1 | **Indirect prompt injection through a connector.** A shared doc or Slack message tells Claude to send data elsewhere | AML.T0051.001 · LLM01 | Connectors enabled per department; no write or send connectors for regulated teams until red-team case RT-1 passes; user training on suspicious instructions; egress limited by the sandbox for Claude Code | **Medium.** Can't be filtered reliably, so impact is limited instead |
| T2 | **Injection through a repository.** `CLAUDE.md` or a README in a cloned repo carries instructions | AML.T0051.001 · LLM01 | Fleet audit `IN01` in CI and weekly; managed deny rules for credential paths (`Read(~/.aws/**)`, `Read(~/.ssh/**)`); sandbox network allowlist; `git push` in `ask` | Medium |
| T3 | **Repo-supplied code execution.** `.mcp.json` servers or hooks run when a repo is opened and trusted | AML.T0010 · LLM03 | `allowManagedMcpServersOnly` + exact `allowedMcpServers`; `allowManagedHooksOnly`; audit checks `CC02`/`CC04` | Low |
| T4 | **Shadow or malicious MCP servers and plugins** (unreviewed, unpinned, tool definitions changed after approval) | AML.T0010 · LLM03/LLM06 | Approval process using the [review guide](../claude-skills-mcp-security-review.md); allowlist matched by URL or command, **never by name**; pinned versions; `strictKnownMarketplaces`; audit `MC01`/`MC03`/`CC05` | Low–Medium |
| T5 | **Agent takes destructive or exfiltrating actions** | LLM06 | Bypass mode disabled (`disableBypassPermissionsMode`); destructive and network commands in `ask`/`deny`; sandbox with `failIfUnavailable` and no unsandboxed retry | Low |
| T6 | **Secrets exposed to the model or committed** in instruction files, MCP config or prompts | AML.T0055 · LLM02 | Central `Read` deny rules; secret scanning of repos, including `CLAUDE.md` and `.mcp.json` (audit `SC01`); training | Medium |
| T7 | **Regulated data entered into an unapproved surface** | LLM02 | [Data handling policy](./data-handling-policy.md); Enterprise custom retention; Compliance API reviews; per-department connector scoping | Medium (depends on behavior) |
| T8 | **Personal accounts used for company work** (outside SSO, retention and audit) | — | `forceLoginMethod: "claudeai"` + `forceLoginOrgUUID`; SSO with SCIM deprovisioning | Low |
| T9 | **Policy not applied** (unmanaged device, native Windows, stale client) | — | MDM coverage report; `requiredMinimumVersion`; `/status` / `claude doctor` checks; the fleet audit finds drift even where policy isn't applied | Medium until MDM coverage is 100% |
| T10 | **Detection gaps.** Misuse that nobody sees | — | Audit logs and Compliance API to the SIEM; Claude Code OpenTelemetry; [detections](./monitoring-and-response.md) | Medium |
| T11 | **Unbounded cost or usage** | LLM10 | Enterprise spend limits per organization and user; usage dashboards | Low |

## What is deliberately not controlled

- **Prompt content isn't blocked by keyword filters.** The portfolio's own red team and interpretability results show filters miss paraphrases (0% caught on reworded attacks). Effort goes into limiting what an injected instruction can do.
- **Users can still paste data they shouldn't.** Policy, training and after-the-fact review cover this. A DLP inline block is a Phase 4 option once false-positive rates are known.
