#!/usr/bin/env python3
"""
Build the AI security posture dashboard from the result files in this repository.

Every number on the dashboard is read from a committed result file (or computed
by the repo's own policy linter). Nothing is typed in by hand, so the dashboard
can't drift from the evidence: rerun the projects, rerun this script.

    python dashboard/build_dashboard.py          # writes dashboard/dashboard.html
    python dashboard/build_dashboard.py --png    # also the PNG images (needs: pip install playwright)

Standard library only for the HTML. All environments shown are fictional samples.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, OrderedDict
from datetime import datetime, timezone
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = Path(__file__).resolve().parent

SOURCES = {
    "fleet": "ai-exposure-scanner/sample_claude_fleet/audit_output/claude_audit_findings.json",
    "assets": "ai-exposure-scanner/findings.csv",
    "inventory": "ai-exposure-scanner/sample_assets.json",
    "redteam": "claude-enterprise-app/redteam/results.json",
    "interp": "interp-probe/results/results.json",
    "lab": "adversarial-ml-lab/results/results.json",
    "owasp": "owasp-llm-top10-comparison.md",
    "policy_general": "enterprise-claude-rollout/policy/managed-settings.general.json",
    "policy_pilot": "enterprise-claude-rollout/policy/managed-settings.pilot.json",
}

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# Fleet audit check IDs grouped into the control areas a CISO reports on.
CONTROL_AREAS = OrderedDict([
    ("MCP servers", ("MC01", "MC02", "MC03")),
    ("Repo-supplied config", ("CC02", "CC04", "CC05", "CC06")),
    ("Permissions and modes", ("CC01", "CC03")),
    ("Secrets reachable by Claude", ("SC01", "SC02")),
    ("Injected instructions", ("IN01",)),
])
AREA_DETAIL = {
    "MCP servers": "unapproved, plain HTTP, unpinned",
    "Repo-supplied config": "auto-approve, hooks, plugins, sandbox",
    "Permissions and modes": "bypass mode, broad allow rules",
    "Secrets reachable by Claude": "keys in CLAUDE.md, unprotected .env",
    "Injected instructions": "hidden directives in CLAUDE.md",
}

REDTEAM_GROUPS = OrderedDict([
    ("PI", "Prompt injection"), ("SI", "Sensitive data"), ("AU", "Authentication"),
    ("AZ", "Authorization"), ("RL", "Rate and size limits"), ("EH", "Error handling"),
    ("AL", "Audit logging"),
])


# --------------------------------------------------------------------------- data

def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _json(rel: str):
    return json.loads(_read(rel))


def load_data() -> dict:
    sys.path.insert(0, str(ROOT / "ai-exposure-scanner"))
    from claude_audit import lint_policy  # the repo's own linter

    fleet = _json(SOURCES["fleet"])
    with open(ROOT / SOURCES["assets"], newline="", encoding="utf-8") as fh:
        asset_rows = list(csv.DictReader(fh))
    inventory = _json(SOURCES["inventory"])["assets"]
    redteam = _json(SOURCES["redteam"])
    interp = _json(SOURCES["interp"])
    lab = _json(SOURCES["lab"])

    # OWASP coverage: parse the status column of the comparison table.
    owasp = []
    for m in re.finditer(r"^\| (LLM\d\d) \| ([^|]+?) \| \*\*(\w+)\*\* \|", _read(SOURCES["owasp"]), re.M):
        owasp.append({"id": m.group(1), "name": m.group(2).strip(), "status": m.group(3)})
    if len(owasp) != 10:
        raise SystemExit(f"Expected 10 OWASP rows in {SOURCES['owasp']}, parsed {len(owasp)}")

    lint = {}
    for name in ("general", "pilot"):
        policy = _json(SOURCES[f"policy_{name}"])
        for profile in ("standard", "strict"):
            lint[(name, profile)] = [g.check_id for g in lint_policy(policy, profile)]

    # Fleet findings by control area.
    by_check = Counter(f["check_id"] for f in fleet["findings"])
    areas = []
    for area, ids in CONTROL_AREAS.items():
        sev = Counter(f["severity"] for f in fleet["findings"] if f["check_id"] in ids)
        areas.append({"area": area, "detail": AREA_DETAIL[area], "count": sum(by_check[i] for i in ids),
                      "ids": [i for i in ids if by_check[i]], "sev": sev})

    # Top actions: highest severity first, then most occurrences.
    grouped = OrderedDict()
    for f in fleet["findings"]:
        g = grouped.setdefault(f["check_id"], {"check_id": f["check_id"], "title": f["title"], "severity": f["severity"],
                                               "fix": f["remediation"], "where": []})
        if SEVERITIES.index(f["severity"]) < SEVERITIES.index(g["severity"]):
            g["severity"] = f["severity"]
        unit = "/".join(f["location"].split("/")[:2])
        if unit not in g["where"]:
            g["where"].append(unit)
    actions = sorted(grouped.values(), key=lambda g: (SEVERITIES.index(g["severity"]), -len(g["where"])))

    ev = next(e for e in lab["evasion"]["by_eps"] if abs(e["eps"] - 0.1) < 1e-9)
    pois = lab["poisoning"]
    probe = interp["probe_at_selected_layer"]

    return {
        "fleet_summary": fleet["summary"],
        "fleet_inventory": fleet["inventory"],
        "fleet_total": len(fleet["findings"]),
        "fleet_units": sorted({"/".join(f["location"].split("/")[:2]) for f in fleet["findings"]}),
        "areas": sorted(areas, key=lambda a: -a["count"]),
        "actions": actions,
        "asset_summary": Counter(r["risk_level"] for r in asset_rows),
        "asset_total": len(asset_rows),
        "asset_count": len(inventory),
        "redteam": redteam,
        "owasp": owasp,
        "lint": lint,
        "interp": {
            "regex_tpr": interp["regex_baseline"]["test_unseen"]["tpr"],
            "probe_tpr": probe["unseen_tpr"],
            "probe_fpr": probe["unseen_fpr"],
            "layer": probe["layer"],
            "n_unseen": interp["sizes"]["test_unseen"],
            "model": interp["model"],
        },
        "lab": {
            "eps": ev["eps"],
            "pgd_standard": ev["standard_pgd"],
            "pgd_adv": ev["adv_trained_pgd"],
            "asr_backdoor": pois["backdoored"]["asr"],
            "asr_after": pois["after_unlearning"]["asr"],
            "clean_backdoor": pois["backdoored"]["clean_acc"],
            "clean_after": pois["after_unlearning"]["clean_acc"],
        },
    }


# --------------------------------------------------------------------------- rendering helpers

def pct(x: float) -> str:
    return f"{x * 100:.0f}%"


def tip(value: str, label: str) -> str:
    """Attributes for a hoverable/focusable mark. Escaped here, inserted as text by the script."""
    return f'tabindex="0" data-tip-value="{escape(value)}" data-tip-label="{escape(label)}"'


def table(headers, rows) -> str:
    head = "".join(f"<th>{escape(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{escape(str(c))}</td>" for c in r) + "</tr>" for r in rows)
    return (f'<details class="tv"><summary>Table view</summary><table><thead><tr>{head}</tr></thead>'
            f"<tbody>{body}</tbody></table></details>")


def hbars(items, max_value, color_var, width=520, label_w=200, row_h=30, bar_h=18, value_fmt=str):
    """Horizontal bar chart: items = [(label, sublabel, value, tip_label, color_var or None)]."""
    plot_w = width - label_w - 44
    h = len(items) * row_h + 6
    out = [f'<svg class="chart" viewBox="0 0 {width} {h}" width="100%" role="img">']
    for i, (label, sub, value, tlabel, cvar) in enumerate(items):
        y = i * row_h + 4
        w = 0 if max_value == 0 else max(value / max_value * plot_w, 0)
        cy = y + bar_h / 2
        out.append(f'<text x="0" y="{cy - (5 if sub else 0) + 4:.1f}" class="lbl">{escape(label)}</text>')
        if sub:
            out.append(f'<text x="0" y="{cy + 11:.1f}" class="sub">{escape(sub)}</text>')
        x0 = label_w
        if w > 0:
            r = min(4, w)
            path = (f"M{x0},{y} H{x0 + w - r} Q{x0 + w},{y} {x0 + w},{y + r} V{y + bar_h - r} "
                    f"Q{x0 + w},{y + bar_h} {x0 + w - r},{y + bar_h} H{x0} Z")
            out.append(f'<path d="{path}" fill="var({cvar or color_var})" class="mark"/>')
        out.append(f'<text x="{x0 + w + 6:.1f}" y="{cy + 4:.1f}" class="val">{escape(value_fmt(value))}</text>')
        out.append(f'<rect x="0" y="{y - 4}" width="{width}" height="{row_h}" fill="transparent" class="hit" '
                   f'{tip(value_fmt(value), tlabel)}/>')
    out.append(f'<line x1="{label_w}" y1="0" x2="{label_w}" y2="{h}" class="axis"/>')
    out.append("</svg>")
    return "".join(out)


# --------------------------------------------------------------------------- panels

def kpis(d) -> str:
    fs = d["fleet_summary"]
    lint_ok = int(not d["lint"][("pilot", "strict")]) + int(not d["lint"][("general", "standard")])
    rt = Counter(r["verdict"] for r in d["redteam"])
    ow = Counter(o["status"] for o in d["owasp"])
    evidenced = ow["Tested"] + ow["Implemented"]
    tiles = [
        ("Claude fleet findings", str(d["fleet_total"]),
         f"{fs['CRITICAL']} critical · {fs['HIGH']} high · {fs['MEDIUM']} medium",
         f"{d['fleet_inventory']['repos']} repos and {d['fleet_inventory']['homes']} laptops (sample); controls clean"),
        ("Managed policies passing lint", f"{lint_ok} of 2", "pilot: strict profile",
         f"general: standard profile, {len(d['lint'][('general', 'strict')])} documented relaxations"),
        ("Red-team cases passed", f"{rt['PASS']} of {len(d['redteam'])}",
         f"{rt['LIMITATION']} documented limitation", "reworded injection, contained by design"),
        ("OWASP risks with evidence", f"{evidenced} of {len(d['owasp'])}",
         f"{ow['Tested']} tested · {ow['Implemented']} implemented",
         f"{ow['Documented']} documented · {ow['Gap']} gap"),
        ("AI asset findings", str(d["asset_total"]),
         f"{d['asset_summary']['CRITICAL']} critical · {d['asset_summary']['HIGH']} high",
         f"across {d['asset_count']} sample assets"),
    ]
    cells = "".join(
        f'<div class="tile"><div class="tlabel">{escape(a)}</div><div class="tvalue">{escape(b)}</div>'
        f'<div class="tsub">{escape(c)}</div><div class="tnote">{escape(e)}</div></div>'
        for a, b, c, e in tiles)
    return f'<section class="kpis">{cells}</section>'


def panel(title, subtitle, body, source, wide=False) -> str:
    return (f'<section class="card{" wide" if wide else ""}"><h2>{escape(title)}</h2>'
            f'<p class="subtitle">{escape(subtitle)}</p>{body}'
            f'<p class="source">Source: <code>{escape(source)}</code></p></section>')


def areas_panel(d) -> str:
    items = [(a["area"], a["detail"], a["count"],
              f"{a['area']} · {', '.join(a['ids']) or 'none'} · "
              + ", ".join(f"{a['sev'][s]} {s.lower()}" for s in SEVERITIES if a["sev"][s]), None)
             for a in d["areas"]]
    body = hbars(items, max(a["count"] for a in d["areas"]), "--series-1", label_w=240, row_h=38)
    body += table(["Control area", "Checks", "Findings"],
                  [(a["area"], ", ".join(a["ids"]), a["count"]) for a in d["areas"]])
    return panel("Where the Claude fleet drifts from policy",
                 "Fleet audit findings by control area, sample fleet audited against the general-rollout policy",
                 body, SOURCES["fleet"])


def severity_panel(d) -> str:
    groups = [("Claude fleet", d["fleet_summary"]), ("AI asset inventory", d["asset_summary"])]
    sev_var = {"CRITICAL": "--status-critical", "HIGH": "--status-serious", "MEDIUM": "--status-warning",
               "LOW": "--status-low"}
    max_v = max(g[s] for _, g in groups for s in SEVERITIES)
    body = '<div class="sev-groups">'
    for name, counts in groups:
        items = [(f"{SEV_ICON[s]} {s.title()}", None, counts.get(s, 0), f"{name} · {s.lower()}", sev_var[s])
                 for s in SEVERITIES]
        body += f'<div><h3>{escape(name)}</h3>{hbars(items, max_v, "--series-1", width=250, label_w=92, row_h=26)}</div>'
    body += "</div>"
    body += table(["Source"] + [s.title() for s in SEVERITIES],
                  [(n, *[c.get(s, 0) for s in SEVERITIES]) for n, c in groups])
    return panel("Findings by severity", "Two separate sample environments, shown side by side, not summed",
                 body, f"{SOURCES['fleet']}, {SOURCES['assets']}")


SEV_ICON = {"CRITICAL": "◆", "HIGH": "▲", "MEDIUM": "■", "LOW": "●"}


def redteam_panel(d) -> str:
    cases = d["redteam"]
    size, gap = 26, 4
    rows = []
    for prefix, label in REDTEAM_GROUPS.items():
        group = [c for c in cases if c["id"].split("-")[0] == prefix]
        if group:
            rows.append((label, group))
    label_w, width = 150, 520
    h = len(rows) * (size + 8) + 4
    out = [f'<svg class="chart" viewBox="0 0 {width} {h}" width="100%" role="img">']
    for i, (label, group) in enumerate(rows):
        y = i * (size + 8) + 2
        out.append(f'<text x="0" y="{y + size / 2 + 4}" class="lbl">{escape(label)}</text>')
        for j, c in enumerate(group):
            x = label_w + j * (size + gap)
            ok = c["verdict"] == "PASS"
            var = "--status-good" if ok else "--status-warning"
            glyph = "✓" if ok else "!"
            ink = "#ffffff" if ok else "#0b0b0b"
            out.append(f'<g class="hit" {tip(c["verdict"].title(), c["id"] + " · " + c["category"] + " · " + c["attempt"][:70])}>'
                       f'<rect x="{x}" y="{y}" width="{size}" height="{size}" rx="4" fill="var({var})" class="mark"/>'
                       f'<text x="{x + size / 2}" y="{y + size / 2 + 5}" class="glyph" fill="{ink}">{glyph}</text></g>')
        out.append(f'<text x="{label_w + len(group) * (size + gap) + 4}" y="{y + size / 2 + 4}" class="val">'
                   f'{sum(c["verdict"] == "PASS" for c in group)}/{len(group)}</text>')
    out.append("</svg>")
    lim = [c for c in cases if c["verdict"] != "PASS"]
    note = "".join(f'<p class="note"><b>{escape(c["id"])}</b>: {escape(c["category"])}. {escape(c["notes"] or c["observed"])[:220]}</p>'
                   for c in lim)
    legend = ('<div class="legend"><span><i class="sw" style="background:var(--status-good)"></i>✓ Pass</span>'
              '<span><i class="sw" style="background:var(--status-warning)"></i>! Documented limitation</span></div>')
    body = legend + "".join(out) + note + table(["Case", "Category", "Verdict"], [(c["id"], c["category"], c["verdict"]) for c in cases])
    return panel("Application red team", f"{len(cases)} attack cases against the Claude enterprise app; each square is one case",
                 body, SOURCES["redteam"])


def interp_panel(d) -> str:
    i = d["interp"]
    items = [("Keyword filter", "regex on known phrasings", i["regex_tpr"], "Keyword filter · caught", None),
             ("Activation probe", f"{i['model'].upper()} layer {i['layer']}, chosen on validation", i["probe_tpr"],
              f"Activation probe · caught (false positives {pct(i['probe_fpr'])})", None)]
    body = hbars(items, 1.0, "--series-1", label_w=220, row_h=42, value_fmt=pct)
    body += (f'<p class="note">The probe flags {pct(i["probe_fpr"])} of benign prompts. Neither is good enough to rely on, '
             "which is why the rollout limits what an injected instruction can do instead of trying to filter it.</p>")
    body += table(["Detector", "Reworded injections caught", "False-positive rate"],
                  [("Keyword filter", pct(i["regex_tpr"]), "0%"), ("Activation probe", pct(i["probe_tpr"]), pct(i["probe_fpr"]))])
    return panel("Filters miss reworded prompt injections",
                 f"Share of injections caught on a held-out set of unseen phrasings ({i['n_unseen']} prompts)",
                 body, SOURCES["interp"])


def lab_panel(d) -> str:
    L = d["lab"]
    rows = [
        ("Accuracy under attack", f"PGD, ε = {L['eps']} · higher is better", L["pgd_standard"], L["pgd_adv"],
         "standard model", "adversarially trained"),
        ("Backdoor attack success", "lower is better", L["asr_backdoor"], L["asr_after"], "backdoored", "after unlearning"),
        ("Clean accuracy", "the cost of unlearning", L["clean_backdoor"], L["clean_after"], "backdoored", "after unlearning"),
    ]
    width, label_w, row_h = 520, 215, 50
    plot_w = width - label_w - 30
    h = len(rows) * row_h + 22
    out = [f'<svg class="chart" viewBox="0 0 {width} {h}" width="100%" role="img">']
    for k in (0, 0.5, 1.0):
        x = label_w + k * plot_w
        out.append(f'<line x1="{x}" y1="0" x2="{x}" y2="{h - 18}" class="grid"/>'
                   f'<text x="{x}" y="{h - 4}" class="tick" text-anchor="middle">{pct(k)}</text>')
    for i, (label, sub, a, b, la, lb) in enumerate(rows):
        cy = i * row_h + 18
        xa, xb = label_w + a * plot_w, label_w + b * plot_w
        out.append(f'<text x="0" y="{cy - 1}" class="lbl">{escape(label)}</text>'
                   f'<text x="0" y="{cy + 13}" class="sub">{escape(sub)}</text>'
                   f'<line x1="{xa}" y1="{cy}" x2="{xb}" y2="{cy}" class="conn"/>')
        for x, v, lab_, var in ((xa, a, la, "--before"), (xb, b, lb, "--after")):
            above = (x == xa) == (xa < xb)
            out.append(f'<g class="hit" {tip(pct(v), label + " · " + lab_)}>'
                       f'<circle cx="{x}" cy="{cy}" r="12" fill="transparent"/>'
                       f'<circle cx="{x}" cy="{cy}" r="6" fill="var({var})" class="dot"/></g>'
                       f'<text x="{x}" y="{cy + (-11 if above else 20)}" class="val" text-anchor="middle">{pct(v)}</text>')
    out.append("</svg>")
    legend = ('<div class="legend"><span><i class="sw round" style="background:var(--before)"></i>Before the defense</span>'
              '<span><i class="sw round" style="background:var(--after)"></i>After the defense</span></div>')
    body = legend + "".join(out) + table(["Measure", "Before", "After"], [(r[0], pct(r[2]), pct(r[3])) for r in rows])
    return panel("Adversarial ML defenses, measured", "Small image classifier in the lab; each row is one attack and its defense",
                 body, SOURCES["lab"])


def owasp_panel(d) -> str:
    fill = {"Tested": "--ord-3", "Implemented": "--ord-2", "Documented": "--ord-1", "Gap": "--surface-1"}
    ink = {"Tested": "--on-ord-3", "Implemented": "--on-ord-2", "Documented": "--on-ord-1", "Gap": "--text-secondary"}
    cells = "".join(
        f'<div class="ow {o["status"].lower()}" style="background:var({fill[o["status"]]});color:var({ink[o["status"]]})" '
        f'{tip(o["status"], o["id"] + " " + o["name"])}><b>{escape(o["id"])}</b><span>{escape(o["name"])}</span>'
        f'<em>{escape(o["status"])}</em></div>' for o in d["owasp"])
    legend = "".join(f'<span><i class="sw" style="background:var({fill[s]})"></i>{s}</span>'
                     for s in ("Tested", "Implemented", "Documented", "Gap"))
    body = f'<div class="legend">{legend}</div><div class="owgrid">{cells}</div>'
    body += table(["Risk", "Name", "Status"], [(o["id"], o["name"], o["status"]) for o in d["owasp"]])
    return panel("OWASP Top 10 for LLM Applications (2025)",
                 "Tested = attacked and measured · Implemented = working control, not yet attacked live", body, SOURCES["owasp"])


def actions_panel(d) -> str:
    rows = []
    for a in d["actions"][:6]:
        s = a["severity"]
        rows.append(f'<tr><td><span class="sev sev-{s.lower()}">{SEV_ICON[s]} {s.title()}</span></td>'
                    f'<td><b>{escape(a["title"])}</b> <span class="cid">{escape(a["check_id"])}</span></td>'
                    f'<td>{escape(", ".join(w.split("/")[1] for w in a["where"]))}</td><td>{escape(a["fix"])}</td></tr>')
    body = ('<table class="actions"><thead><tr><th>Severity</th><th>Issue</th><th>Where</th><th>Fix</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table>')
    return panel("Next actions from the fleet audit", "Highest severity first; the full list is in the CSV", body,
                 SOURCES["fleet"].replace(".json", ".csv"), wide=True)


# --------------------------------------------------------------------------- page

CSS = """
.viz-root{color-scheme:light;--page:#f9f9f7;--surface-1:#fcfcfb;--text-primary:#0b0b0b;--text-secondary:#52514e;
--muted:#898781;--grid:#e1e0d9;--axis:#c3c2b7;--border:rgba(11,11,11,.10);--series-1:#2a78d6;
--status-good:#0ca30c;--status-warning:#fab219;--status-serious:#ec835a;--status-critical:#d03b3b;--status-low:#898781;
--ord-1:#86b6ef;--ord-2:#2a78d6;--ord-3:#184f95;--on-ord-1:#0b0b0b;--on-ord-2:#ffffff;--on-ord-3:#ffffff;
--before:#86b6ef;--after:#184f95}
@media (prefers-color-scheme:dark){:root:where(:not([data-theme="light"])) .viz-root{color-scheme:dark;--page:#0d0d0d;
--surface-1:#1a1a19;--text-primary:#ffffff;--text-secondary:#c3c2b7;--grid:#2c2c2a;--axis:#383835;
--border:rgba(255,255,255,.10);--series-1:#3987e5;--ord-1:#184f95;--ord-2:#2a78d6;--ord-3:#86b6ef;
--on-ord-1:#ffffff;--on-ord-2:#ffffff;--on-ord-3:#0b0b0b;--before:#184f95;--after:#86b6ef}}
:root[data-theme="dark"] .viz-root{color-scheme:dark;--page:#0d0d0d;--surface-1:#1a1a19;--text-primary:#ffffff;
--text-secondary:#c3c2b7;--grid:#2c2c2a;--axis:#383835;--border:rgba(255,255,255,.10);--series-1:#3987e5;
--ord-1:#184f95;--ord-2:#2a78d6;--ord-3:#86b6ef;--on-ord-1:#ffffff;--on-ord-2:#ffffff;--on-ord-3:#0b0b0b;
--before:#184f95;--after:#86b6ef}
*{box-sizing:border-box}
html,body{margin:0}
body{background:#f9f9f7}
@media (prefers-color-scheme:dark){body{background:#0d0d0d}}
.viz-root{background:var(--page);color:var(--text-primary);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;
padding:28px 16px 40px;min-height:100vh}
.wrap{max-width:1180px;margin:0 auto}
header h1{font-size:26px;margin:0 0 4px;font-weight:650}
header p{margin:0;color:var(--text-secondary)}
.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:20px 0}
.tile,.card{background:var(--surface-1);border:1px solid var(--border);border-radius:10px}
.tile{padding:14px 16px}
.tlabel{color:var(--text-secondary);font-size:13px}
.tvalue{font-size:34px;font-weight:650;margin:2px 0}
.tsub{font-size:13px}
.tnote{font-size:12px;color:var(--muted)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.card{padding:16px 18px 12px;min-width:0}
.card.wide{grid-column:1/-1}
.card h2{font-size:16px;margin:0;font-weight:620}
.card h3{font-size:13px;margin:4px 0 6px;color:var(--text-secondary);font-weight:600}
.subtitle{margin:2px 0 12px;color:var(--text-secondary);font-size:13px}
.source{margin:10px 0 0;font-size:11.5px;color:var(--muted)}
.source code,footer code{font-size:11.5px;overflow-wrap:anywhere;word-break:break-all}
.chart{display:block;overflow:visible}
.chart text{font-family:inherit}
.lbl{font-size:13px;fill:var(--text-primary)}
.sub{font-size:11.5px;fill:var(--muted)}
.val{font-size:13px;fill:var(--text-primary);font-variant-numeric:tabular-nums;font-weight:600}
.tick{font-size:11px;fill:var(--muted);font-variant-numeric:tabular-nums}
.axis{stroke:var(--axis);stroke-width:1}
.grid{stroke:var(--grid);stroke-width:1}
.conn{stroke:var(--axis);stroke-width:2;stroke-linecap:round}
.dot{stroke:var(--surface-1);stroke-width:2}
.glyph{font-size:14px;font-weight:700;text-anchor:middle}
.hit{cursor:default;outline:none}
.hit:hover .mark,.hit:focus .mark,.hit:hover+.mark{opacity:.85}
.hit:focus{outline:2px solid var(--series-1);outline-offset:1px}
.sev-groups{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.legend{display:flex;flex-wrap:wrap;gap:14px;font-size:12.5px;color:var(--text-secondary);margin:0 0 8px}
.legend span{display:inline-flex;align-items:center;gap:6px}
.sw{display:inline-block;width:12px;height:12px;border-radius:3px;border:1px solid var(--border)}
.sw.round{border-radius:50%}
.note{font-size:12.5px;color:var(--text-secondary);margin:8px 0 0}
.owgrid{display:grid;grid-template-columns:repeat(5,1fr);gap:4px}
.ow{border-radius:6px;padding:8px 8px 7px;min-height:84px;display:flex;flex-direction:column;gap:2px;outline:none}
.ow.gap{border:1px solid var(--axis)}
.ow b{font-size:13px}
.ow span{font-size:11.5px;line-height:1.25}
.ow em{font-style:normal;font-size:11px;margin-top:auto;opacity:.9}
.ow:focus{outline:2px solid var(--series-1);outline-offset:1px}
table{border-collapse:collapse;width:100%;font-size:12.5px}
th{text-align:left;color:var(--text-secondary);font-weight:600;border-bottom:1px solid var(--axis);padding:6px 8px}
td{border-bottom:1px solid var(--grid);padding:7px 8px;vertical-align:top}
.actions td:nth-child(4){color:var(--text-secondary)}
.cid{color:var(--muted);font-size:11.5px}
.sev{white-space:nowrap;font-weight:600}
.sev::before{content:"";display:inline-block;width:4px;height:12px;border-radius:2px;margin-right:6px;vertical-align:-1px;background:var(--c)}
.sev-critical{--c:var(--status-critical)}.sev-high{--c:var(--status-serious)}.sev-medium{--c:var(--status-warning)}.sev-low{--c:var(--status-low)}
details.tv{margin-top:8px;font-size:12.5px}
details.tv summary{cursor:pointer;color:var(--text-secondary)}
footer{margin-top:16px;font-size:12px;color:var(--muted);overflow-wrap:anywhere}
#tt{position:fixed;pointer-events:none;background:var(--surface-1);border:1px solid var(--border);border-radius:8px;
padding:7px 10px;box-shadow:0 4px 14px rgba(0,0,0,.12);font-size:12.5px;max-width:320px;display:none;z-index:10}
#tt strong{display:block;font-size:15px}
#tt span{color:var(--text-secondary)}
@media (max-width:900px){.kpis{grid-template-columns:repeat(2,1fr)}.grid2{grid-template-columns:1fr}.owgrid{grid-template-columns:repeat(2,1fr)}}
@media (max-width:520px){.sev-groups{grid-template-columns:1fr}.actions td:nth-child(4),.actions th:nth-child(4){display:none}}
"""

JS = """
(function(){var tt=document.getElementById('tt');
function show(el,x,y){tt.textContent='';var s=document.createElement('strong');s.textContent=el.getAttribute('data-tip-value');
var l=document.createElement('span');l.textContent=el.getAttribute('data-tip-label');tt.appendChild(s);tt.appendChild(l);
tt.style.display='block';var w=tt.offsetWidth,h=tt.offsetHeight;
tt.style.left=Math.min(x+14,window.innerWidth-w-8)+'px';tt.style.top=Math.max(8,y-h-10)+'px';}
document.querySelectorAll('[data-tip-value]').forEach(function(el){
el.addEventListener('pointermove',function(e){show(el,e.clientX,e.clientY);});
el.addEventListener('pointerleave',function(){tt.style.display='none';});
el.addEventListener('focus',function(){var r=el.getBoundingClientRect();show(el,r.left+r.width/2,r.top);});
el.addEventListener('blur',function(){tt.style.display='none';});});})();
"""


def render(d: dict) -> str:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    files = ", ".join(sorted({v for v in SOURCES.values()}))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Security Posture</title><style>{CSS}</style></head>
<body><div class="viz-root"><div class="wrap">
<header><h1>AI Security Posture</h1>
<p>Built {generated} from the result files in this repository. All environments are fictional samples.</p></header>
{kpis(d)}
<div class="grid2">
{areas_panel(d)}
{severity_panel(d)}
{redteam_panel(d)}
{owasp_panel(d)}
{interp_panel(d)}
{lab_panel(d)}
{actions_panel(d)}
</div>
<footer>Generated by <code>dashboard/build_dashboard.py</code> from: {escape(files)}. Policy lint results are computed by
<code>claude_audit.py</code> at build time.</footer>
</div></div><div id="tt" role="tooltip"></div><script>{JS}</script></body></html>
"""


def write_png(html_path: Path, png_path: Path, summary_path: Path) -> None:
    """Full-page image, plus a summary image (KPIs and the first row of panels) for the README."""
    from playwright.sync_api import sync_playwright  # optional dependency
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1240, "height": 900}, device_scale_factor=2, color_scheme="light")
        page.goto(html_path.resolve().as_uri())
        page.screenshot(path=str(png_path), full_page=True)
        bottom = page.evaluate("document.querySelectorAll('.card')[1].getBoundingClientRect().bottom + window.scrollY")
        page.screenshot(path=str(summary_path), clip={"x": 0, "y": 0, "width": 1240, "height": bottom + 8})
        browser.close()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--png", action="store_true",
                    help="also render dashboard.png and dashboard_summary.png (requires playwright)")
    args = ap.parse_args(argv)
    data = load_data()
    html_path = OUT_DIR / "dashboard.html"
    html_path.write_text(render(data), encoding="utf-8")
    print(f"Wrote {html_path.relative_to(ROOT)}")
    if args.png:
        write_png(html_path, OUT_DIR / "dashboard.png", OUT_DIR / "dashboard_summary.png")
        print("Wrote dashboard/dashboard.png and dashboard/dashboard_summary.png")
    return 0


if __name__ == "__main__":
    sys.exit(main())
