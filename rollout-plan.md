# Rollout Plan

**Scope:** Claude chat (with Projects and connectors) for all employees; Claude Code for about 600
engineers; MCP servers and plugins from an approved list. **Plan:** Claude Enterprise.

## Phases

| Phase | Who | Duration | Policy | Goal |
|-------|-----|----------|--------|------|
| 0. Foundations | Security, IT, Legal | 3–4 weeks | — | Contract and data terms, SSO/SCIM, retention, logging pipeline, policies written |
| 1. Security pilot | ~30 people: security, platform, 2 product teams | 4 weeks | [Pilot policy](./policy/managed-settings.pilot.json) (strict) | Find what breaks; measure real usage; red-team the controls |
| 2. Engineering expansion | All engineers (~600) | 6 weeks, team by team | [General policy](./policy/managed-settings.general.json) | Scale Claude Code safely; MCP approval process running |
| 3. Company-wide | All employees | 4 weeks, department by department | General policy + connector set per department | Chat and connectors for everyone |
| 4. Steady state | — | Ongoing | Versioned policy, quarterly review | Measure, tune, add capabilities through review |

## Phase 0: Foundations (before anyone gets access)

**Identity**
- SSO through the company IdP, SCIM provisioning so leavers lose access automatically, and domain verification.
- Claude Code logins pinned to the organization (`forceLoginMethod`, `forceLoginOrgUUID`), so personal accounts can't be used for company work.

**Data and contracts**
- Legal and procurement review the data-processing terms.
- Set a **custom retention** period.
- Decide which data classes are allowed (see the [data handling policy](./data-handling-policy.md)).

**Logging**
- Audit-log export and the Compliance API flow into the SIEM.
- Claude Code OpenTelemetry goes to the collector.

See [monitoring and response](./monitoring-and-response.md).

**Policy**
- Pilot and general `managed-settings.json` live in Git and are linted in CI ([`claude_audit.py lint`](../ai-exposure-scanner/claude_audit.py)).
- **Delivery decision:** server-managed settings from the admin console are the simplest route, but they [don't support per-group policy yet](https://code.claude.com/docs/en/managed-settings). Because pilot and general groups need different policies, use **MDM / file-based delivery per device group** during Phases 1–2, and move to console delivery once everyone is on the general policy.

**Windows**
- The sandbox runs on macOS, Linux and WSL2. It doesn't run on native Windows.
- With `failIfUnavailable: true`, Claude Code will refuse to start on native Windows. That's deliberate: Windows engineers use Claude Code inside WSL2, and IT packages that setup in Phase 0.

**Exit criteria:** SSO works, test users are provisioned and deprovisioned by SCIM, a test event reaches the SIEM end to end, and policy lint is green.

## Phase 1: Security pilot

- Deploy the **strict** policy, with egress locked to managed domains and only managed permission rules.
- Run the [agentic red-team plan](./agentic-redteam-plan.md) against the pilot configuration.
- Run the fleet audit weekly on pilot machines and repos.
- Collect friction: every blocked action someone needed becomes either a policy change or a documented "no".

**Exit criteria**
- No open critical or high red-team findings.
- At least 70% of pilot users active each week.
- Fewer than 5 policy-friction tickets per week by week 4.
- Every relaxation from strict to general written down with a reason.

## Phase 2: Engineering expansion

- Deploy the **general** policy one team at a time, about 50 engineers a week.
- **MCP / plugin approval process opens.** A team requests a server, security reviews it using the [Skills & MCP review guide](../claude-skills-mcp-security-review.md), and an approval adds an exact `serverUrl` / `serverCommand` entry to the policy through a pull request. Target: decision within 5 business days.
- **Repo hygiene:** the fleet audit runs in CI on every repo, and new findings comment on the pull request. Critical findings, such as a secret in `CLAUDE.md` or `enableAllProjectMcpServers` in a repo, block merge.

**Exit criteria**
- 100% of engineering devices report the managed policy in `/status`.
- Zero critical fleet-audit findings open longer than 7 days.
- The MCP request backlog is under 2 weeks.

## Phase 3: Company-wide

- Enable chat for every department, with **connectors per department**: Drive and Slack for everyone; CRM only for Sales; no email connector for regulated teams until the Phase 1 injection tests on email pass.
- Short required training, about 20 minutes: what data goes where, how to spot a suspicious instruction in a document, and how to report.

**Exit criteria:** monthly active usage on target, and no data-handling incident above "low".

## Phase 4: Steady state

- Quarterly policy review: drop controls nobody needs, and tighten where incidents happened.
- Every new capability (a new connector type, agent features, new MCP servers) goes through a threat review before it's enabled.

## Who owns what (RACI)

| Activity | Security | IT / Endpoint | Legal / Privacy | Engineering leads | AI program owner |
|----------|:--:|:--:|:--:|:--:|:--:|
| Managed policy content | **A/R** | C | C | C | I |
| Policy delivery (MDM / console) | C | **A/R** | — | I | I |
| Data handling policy | R | I | **A** | C | C |
| MCP / plugin approvals | **A/R** | I | C | R (request) | I |
| Training and communication | C | C | C | C | **A/R** |
| Monitoring and incident response | **A/R** | C | C (if data) | I | I |
| Rollout schedule and adoption targets | C | C | I | C | **A/R** |

## What we measure

| Type | Metric | Target |
|------|--------|--------|
| Adoption | Weekly active users / licensed users | ≥ 60% by end of Phase 3 |
| Adoption | Median time to approve an MCP request | ≤ 5 business days |
| Control | Devices with the managed policy applied | 100% of engineering devices |
| Control | Critical fleet-audit findings open longer than 7 days | 0 |
| Risk | Secret-scanning hits in prompts, instruction files or configs | Trending down; each one triaged |
| Risk | Blocked egress attempts per 1,000 sessions | Baseline in Phase 1, investigate spikes |
| Risk | Prompt-injection red-team cases passing | 100% of release-blocking cases |
