# Managed Policy for Claude Code

Two `managed-settings.json` files, kept in Git and linted in CI:

| File | Used in | Lint profile |
|------|---------|--------------|
| [`managed-settings.pilot.json`](./managed-settings.pilot.json) | Phase 1 security pilot | `strict`: 0 gaps |
| [`managed-settings.general.json`](./managed-settings.general.json) | Phases 2–4 | `standard`: 0 gaps (2 documented relaxations under `strict`) |

```bash
python ../../ai-exposure-scanner/claude_audit.py lint managed-settings.pilot.json --profile strict
```

Key names and shapes follow Anthropic's [settings reference](https://code.claude.com/docs/en/settings-reference),
[managed settings](https://code.claude.com/docs/en/managed-settings) and
[managed MCP](https://code.claude.com/docs/en/managed-mcp) documentation (October 2026). JSON doesn't allow
comments, so the reasoning is here.

## Every key, and why

| Key | Value | Why |
|-----|-------|-----|
| `forceLoginMethod`, `forceLoginOrgUUID` | `"claudeai"`, org UUID | Company accounts only, so SSO, retention and audit always apply (threat T8) |
| `permissions.deny` | `.env`, `.env.*`, `secrets/**`, `~/.aws/**`, `~/.ssh/**` | Credentials are the main prize for an injected instruction (T2, T6). The pilot also denies `curl` and `wget`, which pushes network access through approved paths |
| `permissions.ask` | `git push *` | Pushing code is the step that turns a local mistake into a shared one (T5, RT-7) |
| `permissions.disableBypassPermissionsMode` | `"disable"` | Nobody can switch off permission prompts (T5, RT-5) |
| `allowedMcpServers` | URL patterns + one exact command | Approved servers only, matched by URL or command. Names aren't used, because a user can call any server `github` (T4, RT-9) |
| `allowManagedMcpServersOnly` | `true` | Only this list counts; servers in users' or repos' config don't load (T3) |
| `strictKnownMarketplaces` | the company marketplace | Plugins come from one reviewed source |
| `allowManagedHooksOnly` | `true` | Repos can't run commands on teammates' machines through hooks (T3) |
| `sandbox.enabled`, `failIfUnavailable`, `allowUnsandboxedCommands: false` | | Shell commands get OS-level file and network limits, Claude Code won't start without them, and a blocked command can't retry outside (T5, RT-4) |
| `sandbox.network.allowedDomains` | package registries, GitHub, company domains | Egress only where engineering work needs it |
| `sandbox.network.allowManagedDomainsOnly` | pilot only | **Relaxation in general:** other domains prompt instead of being blocked, so teams aren't stuck waiting on a policy change |
| `allowManagedPermissionRulesOnly` | pilot only | **Relaxation in general:** teams may add their own `allow` rules (e.g. `Bash(npm run *)`). Central `deny` and `ask` rules still apply, and the fleet audit flags broad allows (`CC03`) |
| `requiredMinimumVersion` | `2.1.283` | Older clients lack some policy enforcement (T9) |
| `cleanupPeriodDays` | 14 (pilot 7) | Local transcripts on laptops are sensitive |
| `env` (OpenTelemetry) | exporter to the company collector | Detections D1, D2 and D4. Prompt text stays redacted (`OTEL_LOG_USER_PROMPTS` not set) |
| `companyAnnouncements` | link to the data rules | Shown at startup, so the rules are one click away |

## Deployment notes

- **Paths:** macOS `/Library/Application Support/ClaudeCode/managed-settings.json`; Linux and WSL `/etc/claude-code/managed-settings.json`; Windows `C:\Program Files\ClaudeCode\managed-settings.json`.
- **Per-group policy:** server-managed settings from the admin console don't support per-group policy yet, so the pilot and general groups receive different files through MDM.
- **Native Windows:** the sandbox isn't available, and with `failIfUnavailable` Claude Code refuses to start. Windows engineers run Claude Code in WSL2.
- **Verify:** `/status` shows the managed source under "Setting sources", and `claude doctor` lists any entry the client dropped as invalid.
