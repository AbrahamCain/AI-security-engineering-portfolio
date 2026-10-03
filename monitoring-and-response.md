# Monitoring and Response

## Data sources

| Source | What it gives | Notes |
|--------|---------------|-------|
| **Audit logs** (Enterprise) | Authentication, SSO and domain changes, project and file activity, user invitations, data exports | Exported from Organization settings; each export covers the past 180 days; chat titles and content aren't included, only IDs ([docs](https://support.claude.com/en/articles/9970975-access-audit-logs)) |
| **Compliance API** (Enterprise) | Activity events, chat data and file content, programmatically | Enabled by the Primary Owner; covers Claude apps including Cowork and Claude Code on supported platforms, but not cloud sessions, Bedrock or Vertex ([docs](https://support.claude.com/en/articles/13015708-access-the-compliance-api)) |
| **Claude Code OpenTelemetry** | Events such as `claude_code.user_prompt`, `claude_code.tool_decision`, `claude_code.tool_result`, `claude_code.api_request`, plus metrics | Enabled through the managed `env` block. Prompt text is redacted unless `OTEL_LOG_USER_PROMPTS=1`; we leave it off ([docs](https://code.claude.com/docs/en/monitoring-usage)) |
| **Fleet audit** ([`claude_audit.py`](../ai-exposure-scanner/claude_audit.py)) | Configuration drift across repos and devices | In CI on every repo, plus a weekly endpoint run through MDM |
| **MDM / endpoint** | Whether the managed policy file is present; Claude Code version | Feeds the "policy applied" metric |

Event names should be checked against the deployed Claude Code version, because telemetry evolves between releases.

## Detections (initial set)

| ID | Detects | Logic (source) | Severity |
|----|---------|----------------|----------|
| D1 | Burst of rejected tool calls in one session | Many `tool_decision` rejects within minutes (OTel). Often an injected instruction trying again and again | Medium |
| D2 | Attempts to reach unapproved hosts | `WebFetch` tool decisions for domains outside the allowlist (OTel), plus egress-proxy or EDR denials from Claude Code processes, per user per day | Medium |
| D3 | Secret in an instruction or config file | Fleet audit `SC01`, or secret scanner hit on `CLAUDE.md` / `.mcp.json` (CI) | High |
| D4 | New MCP server attempted | Tool names beginning with an unapproved `mcp__<server>__` prefix (OTel), or fleet audit `MC01` | Medium |
| D5 | Unusual export or bulk access | Data-export events, or bulk file activity outside a user's baseline (audit logs / Compliance API) | High |
| D6 | Policy drift | Device without the managed policy, or below `requiredMinimumVersion` (MDM) | Medium |
| D7 | Restricted data in chat | Compliance API content scanned for card numbers, SSNs and credentials. Detective, not blocking | High |

## Playbooks

**P1. Suspected prompt injection** (D1, D2, or a user report)
1. Get the session's events from OTel and the Compliance API. Identify the content source (doc, repo, email).
2. Quarantine the content: restrict sharing on the doc, or flag the repo in the fleet audit.
3. Check for impact: tool results and egress attempts after the injection point.
4. Add the payload to the red-team set as a regression case.

**P2. Secret exposed to Claude or committed** (D3, D7)
1. Rotate the secret. Do that first.
2. Remove it from the file and from Git history if it was committed.
3. Find where else it was used (Compliance API search).
4. Close with the owner. This is blameless unless the same thing keeps happening.

**P3. Malicious or compromised MCP server or plugin**
1. Add it to `deniedMcpServers` (matched by URL or command) or `blockedMarketplaces`, and push the policy.
2. Revoke any tokens issued to the server.
3. Review the tool calls it received (OTel `tool_result` for `mcp__<server>__*`).
4. Notify the requesting team and log the reason in the approval register.

**P4. Policy not applied on a device** (D6)
1. Re-push through MDM. If the device is unmanaged, suspend Claude Code access for that user until it's enrolled.
