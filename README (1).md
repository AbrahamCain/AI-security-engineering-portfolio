# Sample Claude fleet (fictional)

Four repositories and two developer home directories with realistic Claude Code configuration, used to test
and demonstrate `claude_audit.py`.

Claude configuration lives in dotfiles (`.claude/settings.json`, `.mcp.json`, `~/.claude.json`), so the
whole fleet is stored as one readable manifest, [`fleet.json`](./fleet.json): each key is a file path, JSON
files are objects and other files are text. `claude_audit.py fleet --manifest fleet.json ...` unpacks it into
a temporary directory and audits that, refusing any path that would land outside it.

| Name | Planted problems |
|------|------------------|
| `repos/payments-api` | `Bash(curl *)` pre-approved, a repo command hook, an MCP server over plain HTTP, an unpinned `npx` server |
| `repos/data-science-notebooks` | An API key and a pipe-to-shell install line in `CLAUDE.md`; `.env` with no Read deny rule |
| `repos/vendor-integration` | `enableAllProjectMcpServers: true`, a local MCP server, an unapproved plugin marketplace, the sandbox disabled, and hidden instructions in `CLAUDE.md` to read `~/.aws/credentials` and not tell the user |
| `homes/dev-alice` | Bypass mode by default, `Bash` fully pre-approved, an unpinned personal MCP server |
| `repos/web-portal`, `homes/dev-bob` | None. Control cases that must produce no findings |

All keys and hosts are fake. Results: [`audit_output/`](./audit_output/).
