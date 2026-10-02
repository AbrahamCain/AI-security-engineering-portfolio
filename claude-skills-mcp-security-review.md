# Security Review Guide: Claude Skills and MCP Servers

**Author:** Abraham Cain · **References:** MCP specification (authorization), OWASP Top 10 for LLM
Applications (2025), MITRE ATLAS

This is the review a security team should run before approving a Skill or an MCP server for company
use. Once a model can call tools, prompt injection stops being "bad text" and becomes "unauthorized
action". That is why the [threat model](./enterprise-ai-threat-model.md) rates excessive agency (E2) as
High the moment tools are added.

## How to use this guide

For each server or Skill, answer the questions below and record the evidence. Any **Blocker** answered
"no" means do not approve it. Everything else becomes a tracked risk with an owner.

## 1. What can it do? (blast radius)

| # | Question | Why it matters | Severity |
|---|----------|----------------|----------|
| 1.1 | List every tool. Which ones **write, send, delete, pay or execute**? | These turn an injection into real-world action (LLM06, AML.T0051) | Blocker if unlisted |
| 1.2 | Do write and send actions require human confirmation? | The only reliable stop for a hijacked session | Blocker for destructive or external actions |
| 1.3 | Are file, network and command access scoped (directory allowlist, egress allowlist, no shell)? | Limits what an attacker can reach through a tool | High |
| 1.4 | Does a local (stdio) server run as the user? Can it run in a container or as a restricted account? | A local server inherits all of the user's privileges | High |

## 2. What does it trust? (injection paths)

| # | Question | Why it matters | Severity |
|---|----------|----------------|----------|
| 2.1 | Which tools return **external content** (web pages, email, tickets, documents)? | Tool output is the main indirect-injection path (AML.T0051.001) | High |
| 2.2 | Have tool **names and descriptions** been reviewed as untrusted text? | Descriptions go straight into the model's context, so a malicious one can carry instructions (tool poisoning) | Blocker |
| 2.3 | Are tool definitions **pinned and fingerprinted** at approval, with an alert if they change? | A server can change its definitions after approval (a "rug pull") | High |
| 2.4 | With several servers connected, are there duplicate or look-alike tool names? | Tool shadowing: one server impersonates another's tool | Medium |

**Definition pinning (sketch):**

```python
import hashlib, json

def fingerprint_tools(tools: list[dict]) -> str:
    """Stable hash of tool names, descriptions and input schemas."""
    canonical = json.dumps(
        sorted(({"name": t["name"], "description": t.get("description", ""),
                 "inputSchema": t.get("inputSchema", {})} for t in tools),
               key=lambda t: t["name"]),
        sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()

def check_server(server_id: str, tools: list[dict], approved: dict[str, str]) -> bool:
    """Refuse to expose tools whose definitions changed since approval."""
    if approved.get(server_id) != fingerprint_tools(tools):
        log_security_event("mcp_tool_definitions_changed", server_id)
        return False
    return True
```

## 3. Whose identity does it use? (authorization)

| # | Question | Why it matters | Severity |
|---|----------|----------------|----------|
| 3.1 | Does the server forward the client's token to downstream APIs? | **Token passthrough** is prohibited by the MCP authorization spec. It creates a confused deputy and breaks audit trails | Blocker |
| 3.2 | Are tokens short-lived, audience-scoped and least-privilege (OAuth 2.1), not long-lived static API keys? | Limits the damage from a stolen token | High |
| 3.3 | Where are secrets stored? Are any in Skill files, prompts or server config in the repo? | Secrets in prompts or config leak (AML.T0055, LLM07) | Blocker |
| 3.4 | Does every action run with the **end user's** permissions, not a shared service account? | Otherwise any user can reach any data the service can | High |

## 4. Where does the data go? (data protection)

| # | Question | Why it matters | Severity |
|---|----------|----------------|----------|
| 4.1 | What data classes flow through the tools (PII, credentials, source code, customer data)? | Determines the required controls and any regulatory scope | High |
| 4.2 | Which third parties receive data, and under what retention terms? | Vendor risk and data residency | High |
| 4.3 | Are tool inputs and outputs logged with sensitive values masked? | Investigation needs logs; logs must not become a leak (LLM02) | Medium |

## 5. Can we trust the code? (supply chain)

MCP itself does not define package signing, so provenance has to come from how servers are sourced
and deployed (LLM03, AML.T0010).

| # | Question | Severity |
|---|----------|----------|
| 5.1 | Is the publisher known, with source available and the code reviewed (at least the tool handlers and network egress)? | High |
| 5.2 | Is the version pinned to an exact release or commit hash, with no auto-update? | High |
| 5.3 | Are dependencies scanned (SCA) and is the server re-reviewed on every upgrade? | Medium |

## 6. Can we see and stop it? (operations)

| # | Question | Severity |
|---|----------|----------|
| 6.1 | Is every tool call logged with user, tool, arguments (masked) and result? | High |
| 6.2 | Are there per-user and per-tool rate limits and timeouts? (LLM10) | Medium |
| 6.3 | Can a single server be disabled for all users immediately (a kill switch)? | High |
| 6.4 | Is there an incident playbook: disable the server, revoke its tokens, preserve the logs, review recent actions? | Medium |

## Approval outcomes

| Outcome | Criteria |
|---------|----------|
| **Approve** | No blockers; high items have controls in place |
| **Approve with conditions** | No blockers; high items have owners and dates |
| **Reject** | Any blocker answered "no" |

## Mapping

| OWASP LLM (2025) | Sections | MITRE ATLAS |
|------------------|----------|-------------|
| LLM01 Prompt Injection | 2 | AML.T0051 |
| LLM02 Sensitive Information Disclosure | 4 | AML.T0057 |
| LLM03 Supply Chain | 5 | AML.T0010 |
| LLM06 Excessive Agency | 1, 3 | — |
| LLM07 System Prompt Leakage | 3.3 | AML.T0056 |
| LLM10 Unbounded Consumption | 6.2 | AML.T0034 |
