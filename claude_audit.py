#!/usr/bin/env python3
"""
Claude deployment exposure auditor.

Two jobs for an organization rolling out Claude Code:

1. Fleet audit: scan repositories and developer home directories for Claude
   configuration that widens exposure: unapproved or unpinned MCP servers,
   auto-approval of repo-supplied servers, bypass mode, broad allow rules,
   project hooks, unapproved plugin marketplaces, weakened sandboxes, secrets
   in config, and prompt-injection-style instructions in CLAUDE.md.

2. Policy lint: check an organization's managed-settings.json against a
   baseline before it is deployed.

The approved MCP servers and marketplaces are read from the organization's own
managed-settings.json, so the audit answers "where does reality drift from
policy?". Matching follows the documented allowlist semantics: `serverUrl`
entries match with `*` wildcards, `serverCommand` entries match the command and
arguments exactly, and `serverName` entries are not treated as a control.

Usage:
    python claude_audit.py fleet --repos /path/to/repos --homes /path/to/homes \\
        --policy ../enterprise-claude-rollout/policy/managed-settings.general.json
    python claude_audit.py fleet --manifest sample_claude_fleet/fleet.json \\
        --policy ../enterprise-claude-rollout/policy/managed-settings.general.json
    python claude_audit.py lint ../enterprise-claude-rollout/policy/managed-settings.pilot.json --profile strict

Scope note: this reads files only. It does not run Claude Code, contact MCP
servers, or read anything outside the directories it is given.
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import json
import re
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class AuditFinding:
    location: str
    check_id: str
    title: str
    severity: str
    detail: str
    remediation: str
    references: str


def _mask(value: str) -> str:
    return value[:6] + "*" * min(max(len(value) - 6, 4), 12)


def _load_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


# ---------------------------------------------------------------------------
# Approved lists (from the organization's managed settings)
# ---------------------------------------------------------------------------

@dataclass
class Approved:
    urls: List[str]
    commands: List[List[str]]
    marketplaces: List[Dict[str, Any]]

    @classmethod
    def from_policy(cls, policy: Dict[str, Any]) -> "Approved":
        urls, commands = [], []
        for entry in policy.get("allowedMcpServers", []) or []:
            if isinstance(entry, dict) and "serverUrl" in entry:
                urls.append(entry["serverUrl"])
            elif isinstance(entry, dict) and "serverCommand" in entry:
                commands.append(list(entry["serverCommand"]))
        return cls(urls, commands, list(policy.get("strictKnownMarketplaces", []) or []))

    def server_allowed(self, server: Dict[str, Any]) -> bool:
        url = server.get("url")
        if url:
            return any(fnmatch.fnmatchcase(url, pattern) for pattern in self.urls)
        command = [server.get("command", "")] + list(server.get("args", []) or [])
        return command in self.commands

    def marketplace_allowed(self, source: Dict[str, Any]) -> bool:
        return any(all(source.get(k) == v for k, v in approved.items()) for approved in self.marketplaces)


# ---------------------------------------------------------------------------
# Content checks
# ---------------------------------------------------------------------------

SECRET_PATTERNS = {
    "Anthropic API key": re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    "AWS access key ID": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "Slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    "Credential assignment": re.compile(
        r"""(?i)\b(?:api[_-]?key|secret|token|password)\b["']?\s*[:=]\s*["']?([^\s"'$<{][^\s"']{11,})"""),
}

UNSAFE_INSTRUCTION_PATTERNS = {
    "pipe-to-shell install": re.compile(r"(?i)\b(curl|wget)\b[^\n|]*\|\s*(ba|z)?sh\b"),
    "permission bypass": re.compile(r"(?i)--dangerously-skip-permissions|\bbypassPermissions\b"),
    "instruction override": re.compile(
        r"(?i)\b(ignore|disregard)\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)\s+instructions"),
    "concealment": re.compile(r"(?i)\bdo\s+not\s+(tell|inform|mention\s+(this\s+)?to)\s+the\s+user"),
    "credential access": re.compile(r"(?i)(~/\.aws/credentials|~/\.ssh/id_|\.netrc|/etc/shadow)"),
    "sandbox disable": re.compile(r"(?i)\b(disable|turn\s+off)\s+(the\s+)?sandbox"),
}

BROAD_ALLOW = {
    "Bash": "HIGH", "Bash(*)": "HIGH", "WebFetch": "HIGH", "WebFetch(domain:*)": "HIGH",
    "Write": "MEDIUM", "Edit": "MEDIUM",
}
RISKY_COMMAND_PREFIXES = ("curl", "wget", "sudo", "rm", "ssh", "scp", "nc", "git push", "aws", "kubectl", "terraform")

PACKAGE_RUNNERS = {"npx", "bunx", "uvx", "pipx"}


def _is_pinned(runner: str, package: str) -> bool:
    if runner in {"uvx", "pipx"}:
        return "==" in package or "@" in package
    # npm: "@scope/pkg@1.2.3" or "pkg@1.2.3"
    name = package[1:] if package.startswith("@") else package
    return "@" in name and not name.endswith("@latest")


# ---------------------------------------------------------------------------
# Auditor
# ---------------------------------------------------------------------------

class ClaudeFleetAuditor:
    def __init__(self, approved: Approved, root_label: str = ""):
        self.approved = approved
        self.findings: List[AuditFinding] = []
        self.root_label = root_label
        self.inventory = {"repos": 0, "homes": 0, "mcp_servers": 0, "settings_files": 0, "instruction_files": 0}

    def add(self, location: Path, check_id: str, title: str, severity: str, detail: str, fix: str, refs: str):
        self.findings.append(AuditFinding(str(location), check_id, title, severity, detail, fix, refs))

    # -- settings ----------------------------------------------------------
    def check_settings(self, path: Path, scope: str) -> None:
        data = _load_json(path)
        if data is None:
            return
        self.inventory["settings_files"] += 1
        perms = data.get("permissions", {}) or {}

        if perms.get("defaultMode") == "bypassPermissions":
            sev = "HIGH" if scope == "user" else "LOW"
            note = ("skips permission prompts in every session unless managed policy disables bypass mode"
                    if scope == "user" else
                    "ignored in project/local files by current Claude Code versions, but signals intent; remove it")
            self.add(path, "CC01", "Permission bypass as default mode", sev, f"defaultMode=bypassPermissions ({scope}): {note}",
                     "Set permissions.disableBypassPermissionsMode to \"disable\" in managed settings.",
                     "OWASP LLM06 · CWE-250")

        if data.get("enableAllProjectMcpServers") is True:
            self.add(path, "CC02", "Auto-approval of repository MCP servers", "HIGH",
                     "enableAllProjectMcpServers=true starts every server a cloned repo's .mcp.json declares, "
                     "without a prompt: a malicious repo gets code execution",
                     "Remove the key; rely on the managed allowedMcpServers list with allowManagedMcpServersOnly.",
                     "OWASP LLM03/LLM06 · ATLAS AML.T0010 · CWE-829")

        for rule in perms.get("allow", []) or []:
            if rule in BROAD_ALLOW:
                self.add(path, "CC03", "Overly broad allow rule", BROAD_ALLOW[rule],
                         f"'{rule}' auto-approves every use of the tool ({scope} settings)",
                         "Replace with narrow rules (e.g. Bash(npm run *)) or move to 'ask'.", "OWASP LLM06 · CWE-250")
            else:
                m = re.fullmatch(r"Bash\((.+)\)", rule)
                if m and m.group(1).startswith(RISKY_COMMAND_PREFIXES):
                    self.add(path, "CC03", "Network or destructive command auto-approved", "MEDIUM",
                             f"'{rule}' runs without a prompt ({scope} settings); an injected instruction can use it",
                             "Move to 'ask' or 'deny'; use WebFetch(domain:...) plus the sandbox network allowlist for network access.",
                             "OWASP LLM06 · ATLAS AML.T0051")

        for event, matchers in (data.get("hooks", {}) or {}).items():
            for matcher in matchers or []:
                for hook in matcher.get("hooks", []) or []:
                    if hook.get("type") == "http":
                        self.add(path, "CC04", "Hook sends data to an external URL", "HIGH",
                                 f"{event} hook posts to {hook.get('url', '?')}: tool inputs can leave the machine",
                                 "Allow only managed hooks (allowManagedHooksOnly) and allowlist hook URLs (allowedHttpHookUrls).",
                                 "OWASP LLM02 · CWE-200")
                    elif hook.get("type") == "command" and scope == "project":
                        self.add(path, "CC04", "Repository-defined command hook", "MEDIUM",
                                 f"{event} hook runs `{hook.get('command', '?')}` on every teammate who trusts this repo",
                                 "Review the script; consider allowManagedHooksOnly and deploying approved hooks centrally.",
                                 "OWASP LLM03 · CWE-829")

        for name, spec in (data.get("extraKnownMarketplaces", {}) or {}).items():
            source = (spec or {}).get("source", {})
            if not self.approved.marketplace_allowed(source):
                self.add(path, "CC05", "Unapproved plugin marketplace", "MEDIUM",
                         f"marketplace '{name}' ({source.get('repo') or source.get('url', '?')}) is not in strictKnownMarketplaces",
                         "Add it to the approved list after review, or remove it.", "OWASP LLM03 · ATLAS AML.T0010")

        sandbox = data.get("sandbox", {}) or {}
        if sandbox.get("enabled") is False or sandbox.get("allowUnsandboxedCommands") is True:
            self.add(path, "CC06", "Sandbox weakened", "MEDIUM",
                     f"sandbox.enabled={sandbox.get('enabled')} allowUnsandboxedCommands={sandbox.get('allowUnsandboxedCommands')} ({scope})",
                     "Enforce sandbox.enabled and allowUnsandboxedCommands=false from managed settings.", "CWE-693")

        self.check_secrets(path, json.dumps(data.get("env", {})))

    # -- MCP ---------------------------------------------------------------
    def check_mcp(self, path: Path, servers: Dict[str, Any]) -> None:
        for name, server in (servers or {}).items():
            if not isinstance(server, dict):
                continue
            self.inventory["mcp_servers"] += 1
            url = server.get("url")
            label = url or " ".join([server.get("command", "")] + list(server.get("args", []) or []))
            if not self.approved.server_allowed(server):
                sev = "MEDIUM" if url else "HIGH"
                kind = "remote" if url else "local (stdio, runs code on the machine)"
                self.add(path, "MC01", "MCP server not on the approved list", sev,
                         f"'{name}' → {label} [{kind}]; matched by URL/command, not by name",
                         "Review it with the Skills & MCP guide; add an exact serverUrl/serverCommand entry or remove it.",
                         "OWASP LLM03/LLM06 · ATLAS AML.T0010")
            if url and url.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1)", url):
                self.add(path, "MC02", "Remote MCP server over plaintext HTTP", "HIGH",
                         f"'{name}' → {url}", "Use HTTPS.", "CWE-319")
            command = server.get("command", "")
            args = [a for a in (server.get("args", []) or []) if not str(a).startswith("-")]
            if command in PACKAGE_RUNNERS and args and not _is_pinned(command, str(args[0])):
                self.add(path, "MC03", "Unpinned MCP package", "MEDIUM",
                         f"'{name}' runs `{command} {args[0]}` with no version: every start can fetch new code",
                         "Pin an exact version and review upgrades.", "OWASP LLM03 · ATLAS AML.T0010")
            self.check_secrets(path, json.dumps({k: server.get(k) for k in ("env", "headers")}))

    # -- content -----------------------------------------------------------
    def check_secrets(self, path: Path, text: str) -> None:
        for label, pattern in SECRET_PATTERNS.items():
            for m in pattern.finditer(text):
                value = m.group(m.lastindex) if m.lastindex else m.group(0)
                self.add(path, "SC01", "Secret in Claude configuration or instructions", "CRITICAL",
                         f"{label}: {_mask(value)} (files here are read into model context and often committed)",
                         "Rotate it; load secrets from the environment or a secrets manager; add the file to Read deny rules.",
                         "OWASP LLM02 · ATLAS AML.T0055 · CWE-798")

    def check_instructions(self, path: Path) -> None:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return
        self.inventory["instruction_files"] += 1
        for label, pattern in UNSAFE_INSTRUCTION_PATTERNS.items():
            for m in pattern.finditer(text):
                line = text[: m.start()].count("\n") + 1
                self.add(path, "IN01", f"Risky instruction in CLAUDE.md ({label})", "HIGH",
                         f"line {line}: “{m.group(0)[:80]}”. CLAUDE.md is loaded into every session in this repo",
                         "Remove it; review instruction files in code review like code.",
                         "OWASP LLM01 · ATLAS AML.T0051.001")
        self.check_secrets(path, text)

    # -- walkers -----------------------------------------------------------
    def audit_repo(self, repo: Path) -> None:
        self.inventory["repos"] += 1
        for rel, scope in ((".claude/settings.json", "project"), (".claude/settings.local.json", "local")):
            if (repo / rel).exists():
                self.check_settings(repo / rel, scope)
        mcp = _load_json(repo / ".mcp.json") if (repo / ".mcp.json").exists() else None
        if mcp:
            self.check_mcp(repo / ".mcp.json", mcp.get("mcpServers", {}))
        for rel in ("CLAUDE.md", ".claude/CLAUDE.md"):
            if (repo / rel).exists():
                self.check_instructions(repo / rel)
        project = _load_json(repo / ".claude/settings.json") or {}
        denies = " ".join((project.get("permissions", {}) or {}).get("deny", []) or [])
        for secret_file in (".env", "secrets"):
            if (repo / secret_file).exists() and secret_file not in denies:
                self.add(repo / secret_file, "SC02", "Secret file readable by Claude", "MEDIUM",
                         f"'{secret_file}' exists and the project has no Read deny rule for it",
                         f"Add Read(./{secret_file}{'/**' if secret_file == 'secrets' else ''}) to deny rules (or deny centrally).",
                         "OWASP LLM02 · CWE-200")

    def audit_home(self, home: Path) -> None:
        self.inventory["homes"] += 1
        if (home / ".claude/settings.json").exists():
            self.check_settings(home / ".claude/settings.json", "user")
        user_cfg = _load_json(home / ".claude.json") if (home / ".claude.json").exists() else None
        if user_cfg:
            self.check_mcp(home / ".claude.json", user_cfg.get("mcpServers", {}))
        if (home / ".claude/CLAUDE.md").exists():
            self.check_instructions(home / ".claude/CLAUDE.md")

    def run(self, repos_dir: Optional[Path], homes_dir: Optional[Path]) -> List[AuditFinding]:
        for base, fn in ((repos_dir, self.audit_repo), (homes_dir, self.audit_home)):
            if base and base.is_dir():
                for child in sorted(p for p in base.iterdir() if p.is_dir()):
                    fn(child)
        self.findings.sort(key=lambda f: (SEV_RANK[f.severity], f.location, f.check_id))
        return self.findings


# ---------------------------------------------------------------------------
# Policy lint
# ---------------------------------------------------------------------------

def lint_policy(policy: Dict[str, Any], profile: str = "standard") -> List[AuditFinding]:
    """Check a managed-settings document against the baseline for a profile ('standard' or 'strict')."""
    out: List[AuditFinding] = []

    def gap(check_id, title, sev, detail, fix, refs="Claude Code managed settings"):
        out.append(AuditFinding("managed-settings.json", check_id, title, sev, detail, fix, refs))

    perms = policy.get("permissions", {}) or {}
    sandbox = policy.get("sandbox", {}) or {}
    network = sandbox.get("network", {}) or {}

    if policy.get("forceLoginMethod") != "claudeai" or not policy.get("forceLoginOrgUUID"):
        gap("PL01", "Logins not pinned to the organization", "HIGH",
            "personal accounts could be used, outside SSO, retention and audit controls",
            'Set forceLoginMethod "claudeai" and forceLoginOrgUUID.')
    if perms.get("disableBypassPermissionsMode") != "disable":
        gap("PL02", "Bypass mode not disabled", "HIGH", "users can skip every permission prompt",
            'Set permissions.disableBypassPermissionsMode to "disable".')
    allowed = policy.get("allowedMcpServers", []) or []
    if policy.get("allowManagedMcpServersOnly") is not True or not allowed:
        gap("PL03", "MCP allowlist not enforced", "HIGH", "any user- or repo-added MCP server can load",
            "Set allowManagedMcpServersOnly true with a reviewed allowedMcpServers list.")
    if any(isinstance(e, dict) and set(e) == {"serverName"} for e in allowed):
        gap("PL04", "serverName used as an allowlist control", "MEDIUM",
            "a user can give any server an approved name", "Use serverUrl or serverCommand entries.")
    deny = " ".join(perms.get("deny", []) or [])
    if "Read(./.env" not in deny or "secrets" not in deny:
        gap("PL05", "Secret files not denied centrally", "MEDIUM", "Claude's file tools can read .env and secrets/",
            "Add Read(./.env), Read(./.env.*), Read(./secrets/**) to permissions.deny.")
    if sandbox.get("enabled") is not True or sandbox.get("failIfUnavailable") is not True:
        gap("PL06", "Sandbox not required", "MEDIUM", "shell commands may run without OS-level limits",
            "Set sandbox.enabled and sandbox.failIfUnavailable to true (Windows users need WSL2).")
    if not policy.get("strictKnownMarketplaces"):
        gap("PL07", "Plugin sources unrestricted", "MEDIUM", "plugins can be installed from any marketplace",
            "Set strictKnownMarketplaces to the approved marketplace(s).")
    if policy.get("allowManagedHooksOnly") is not True:
        gap("PL08", "Repository and user hooks allowed", "MEDIUM", "repos can run commands via hooks on trust",
            "Set allowManagedHooksOnly true and deploy approved hooks centrally.")
    if not policy.get("requiredMinimumVersion"):
        gap("PL09", "No minimum Claude Code version", "LOW", "older clients may lack newer policy enforcement",
            "Set requiredMinimumVersion.")
    if not isinstance(policy.get("cleanupPeriodDays"), int) or policy["cleanupPeriodDays"] > 30:
        gap("PL10", "Local transcripts kept longer than 30 days", "LOW", "transcripts on laptops may hold sensitive data",
            "Set cleanupPeriodDays to 30 or less.")
    if profile == "strict":
        if policy.get("allowManagedPermissionRulesOnly") is not True:
            gap("PL11", "Local permission rules allowed (strict profile)", "MEDIUM",
                "users and repos can add allow rules", "Set allowManagedPermissionRulesOnly true.")
        if network.get("allowManagedDomainsOnly") is not True or sandbox.get("allowUnsandboxedCommands") is not False:
            gap("PL12", "Network egress not locked (strict profile)", "MEDIUM",
                "commands may reach unapproved hosts or retry outside the sandbox",
                "Set sandbox.network.allowManagedDomainsOnly true and sandbox.allowUnsandboxedCommands false.")
    out.sort(key=lambda f: SEV_RANK[f.severity])
    return out


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def summarize(findings: Iterable[AuditFinding]) -> Dict[str, int]:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] += 1
    return counts


def materialize_fleet(manifest: Dict[str, Any], dest: Path) -> None:
    """Unpack a fleet manifest ({"repos": {name: {relpath: content}}, "homes": ...}) under dest.

    The sample fleet is stored this way because Claude configuration lives in
    dotfiles (.claude/, .mcp.json), which are awkward to keep as fixtures.
    Paths that are absolute or climb out of their directory are refused.
    """
    for kind in ("repos", "homes"):
        for name, files in (manifest.get(kind) or {}).items():
            base = (dest / kind / name).resolve()
            for rel, content in files.items():
                target = (base / rel).resolve()
                if Path(rel).is_absolute() or ".." in Path(rel).parts or base not in target.parents:
                    raise ValueError(f"unsafe path in manifest: {kind}/{name}/{rel}")
                target.parent.mkdir(parents=True, exist_ok=True)
                text = content if isinstance(content, str) else json.dumps(content, indent=2)
                target.write_text(text, encoding="utf-8")


def _relative(findings: List[AuditFinding], root: Path) -> None:
    for f in findings:
        try:
            f.location = Path(f.location).resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            pass


def write_outputs(findings: List[AuditFinding], inventory: Dict[str, int], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = [asdict(f) for f in findings]
    with open(out_dir / "claude_audit_findings.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(AuditFinding.__dataclass_fields__))
        writer.writeheader()
        writer.writerows(rows)
    (out_dir / "claude_audit_findings.json").write_text(
        json.dumps({"inventory": inventory, "summary": summarize(findings), "findings": rows}, indent=2), encoding="utf-8")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    fleet = sub.add_parser("fleet", help="audit repositories and home directories")
    fleet.add_argument("--repos", type=Path)
    fleet.add_argument("--homes", type=Path)
    fleet.add_argument("--manifest", type=Path, help="fleet manifest JSON (e.g. sample_claude_fleet/fleet.json)")
    fleet.add_argument("--policy", type=Path, required=True, help="organization managed-settings.json")
    fleet.add_argument("--out", type=Path, default=Path("claude_audit_output"))
    lint = sub.add_parser("lint", help="check a managed-settings.json against the baseline")
    lint.add_argument("policy", type=Path)
    lint.add_argument("--profile", choices=["standard", "strict"], default="standard")
    args = ap.parse_args(argv)

    if args.cmd == "lint":
        policy = _load_json(args.policy)
        if policy is None:
            print(f"Cannot read {args.policy}", file=sys.stderr)
            return 2
        gaps = lint_policy(policy, args.profile)
        print(f"{args.policy.name} ({args.profile} profile): {len(gaps)} gap(s)")
        for g in gaps:
            print(f"  [{g.severity}] {g.check_id} {g.title}: {g.remediation}")
        return 1 if any(g.severity in ("CRITICAL", "HIGH") for g in gaps) else 0

    policy = _load_json(args.policy)
    if policy is None:
        print(f"Cannot read {args.policy}", file=sys.stderr)
        return 2
    auditor = ClaudeFleetAuditor(Approved.from_policy(policy))
    if args.manifest:
        manifest = _load_json(args.manifest)
        if manifest is None:
            print(f"Cannot read {args.manifest}", file=sys.stderr)
            return 2
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            materialize_fleet(manifest, root)
            findings = auditor.run(root / "repos", root / "homes")
            _relative(findings, root)
    else:
        findings = auditor.run(args.repos, args.homes)
        _relative(findings, Path.cwd())
    write_outputs(findings, auditor.inventory, args.out)
    counts = summarize(findings)
    inv = auditor.inventory
    print(f"Scanned {inv['repos']} repos, {inv['homes']} home dirs, {inv['settings_files']} settings files, "
          f"{inv['mcp_servers']} MCP servers, {inv['instruction_files']} CLAUDE.md files")
    print("Findings: " + ", ".join(f"{k} {v}" for k, v in counts.items()))
    for f in findings[:10]:
        print(f"  [{f.severity}] {f.check_id} {f.title} — {f.location}")
    print(f"Wrote {args.out}/claude_audit_findings.csv and .json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
