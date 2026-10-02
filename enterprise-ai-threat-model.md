# Enterprise AI Threat Model

**System:** Secure Claude Enterprise Application ([`claude-enterprise-app/`](./claude-enterprise-app/))
**Method:** STRIDE per element, plus LLM-specific threats
**References:** OWASP Top 10 for LLM Applications (2025), CWE, NIST AI RMF (MAP)
**Author:** Abraham Cain

---

## 1. Summary

This model covers the current (v2) application: signed short-lived tokens, a server-side role
lookup, input screening, PII redaction in both directions, output encoding, rate limits, and a
local SQLite audit log. It identifies **15 threats**. Where a control exists, the threat is linked
to the red-team case or unit test that exercises it (see [`ai-red-team-assessment.md`](./ai-red-team-assessment.md)).

| Residual rating | Count | Threats |
|-----------------|-------|---------|
| High | 1 | T1 (prompt injection past the filter, model behavior untested) |
| Medium | 6 | S2, T2, R1, I1, D1, E2 |
| Low | 8 | S1, S3, T3, I2, I3, I4, D2, E1 |

The single most important design decision: **the model has no tools, no secrets in context, and
its output is treated as untrusted.** That turns prompt injection from "system compromise" into
"the requesting user gets a distorted analysis."

---

## 2. System overview

```
                 ┌──────────── Trust boundary: internet ────────────┐
  Analyst/Admin ─┤ HTTPS (TLS terminated at reverse proxy — assumed) │
                 └──────────────────────────┬────────────────────────┘
                                            │
┌───────────────────────── Flask application (single process) ───────────────────────────┐
│  POST /auth/login ──► LoginThrottle ──► password check (scrypt) ──► TokenService.issue │
│                                                                                        │
│  Protected routes:                                                                     │
│   bearer token ──► TokenService.verify (HMAC, expiry) ──► user store (role lookup)     │
│        ──► RateLimiter ──► RBAC permission check ──► handler                           │
│                                                                                        │
│  /analyze handler:                                                                     │
│   InputValidator (size, injection phrases) ──► PII redaction (non-admin)               │
│        ──► ClaudeClient (system prompt + <document> wrapper) ─────────┐                │
│   response ◄── html.escape ◄── PII redaction on output (non-admin) ◄──┘                │
│                                                                                        │
│  AuditLogger ──► audit.db (SQLite, local file)                                         │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ HTTPS, API key from environment
                              ┌─────────────▼─────────────┐
                              │  Anthropic Messages API   │  ◄── Trust boundary: third party
                              └───────────────────────────┘
```

### Assets

| Asset | Where it lives | Why it matters |
|-------|----------------|----------------|
| Anthropic API key | Process environment | Billing abuse, quota exhaustion |
| Token signing key (`SECRET_KEY`) | Process environment | Forging any user's session |
| User password hashes | In-memory user store (demo) | Account takeover |
| Customer documents and PII | Request bodies, model prompts | Privacy and regulatory exposure |
| Audit log | `audit.db` on local disk | Investigations, accountability |

### Assumptions

- TLS is terminated by a reverse proxy in front of Flask. The app does not enforce HTTPS itself.
- One process. Rate limits and lockouts are in memory.
- The demo user store is loaded from environment variables. A real deployment would use an IdP.
- Anthropic's API is trusted to process the data sent to it under the organization's agreement.

---

## 3. Threats

Ratings use Likelihood × Impact (Low / Medium / High). "Residual" is the rating with current controls in place.

### Spoofing

**S1. Forged or replayed bearer token**
- *Attack:* craft a token, edit an existing one, or reuse an expired one.
- *Controls:* HMAC-SHA256 over the payload with constant-time compare; 15-minute expiry; subject must exist in the user store.
- *Evidence:* AU-2, AU-4, AU-5, AU-6; `test_tampered_token_rejected`, `test_expired_token_rejected`.
- *Gap:* a stolen token works until it expires, and there is no revocation (see S3).
- *CWE:* CWE-347, CWE-613 · *Residual:* **Low**

**S2. Password guessing / credential stuffing**
- *Attack:* repeated login attempts against known usernames.
- *Controls:* salted scrypt hashes; lockout after 5 failures per username+IP in 5 minutes; same error and code path for unknown users.
- *Evidence:* AU-7; `test_login_lockout_after_repeated_failures`.
- *Gap:* the lockout key includes the IP, so attempts spread across many IPs are not slowed. No MFA.
- *CWE:* CWE-307 (Improper Restriction of Excessive Authentication Attempts) · *Residual:* **Medium**

**S3. Session survives credential change**
- *Attack:* after a password reset or account removal, an attacker keeps using an already-issued token.
- *Controls:* removed users fail the store lookup (AU-5). A changed password does **not** invalidate existing tokens.
- *Fix:* `jti` denylist or a per-user token version.
- *CWE:* CWE-613 · *Residual:* **Low** (15-minute window)

### Tampering

**T1. Prompt injection via document content**
- *Attack:* the document contains instructions aimed at the model, such as "ignore previous instructions" or text that breaks out of the `<document>` wrapper.
- *Controls:* phrase screen on input; closing-tag neutralization; a fixed system prompt that declares the document untrusted. Most importantly, the model has no tools, nothing secret in context, and its output is redacted and escaped.
- *Evidence:* PI-1 to PI-4 blocked. **PI-5 (paraphrase) passes the filter**, which is expected. The model's response to such input has not been tested (live probes LV-1 to LV-3 have not been run).
- *Impact if successful:* the requesting user receives manipulated analysis text. No privilege change, data access, or action is possible through this path.
- *Refs:* LLM01, LLM07, CWE-1427 · *Residual:* **High** until live testing, because effectiveness is unmeasured; impact stays bounded.

**T2. Audit log modification**
- *Attack:* anyone with filesystem access to `audit.db`, including a compromised app process, can edit or delete rows.
- *Controls:* none beyond OS file permissions.
- *Fix:* ship events to append-only central storage (e.g. a SIEM, or object storage with object lock).
- *CWE:* CWE-732 · *Residual:* **Medium**

**T3. Role tampering**
- *Attack:* change the role claim to gain admin.
- *Controls:* tokens carry no role. The role is looked up server-side on every request.
- *Evidence:* AZ-1, AZ-2, AU-6.
- *CWE:* CWE-269 (Improper Privilege Management) · *Residual:* **Low**

### Repudiation

**R1. Disputed privileged action**
- *Attack:* an admin denies having triggered key rotation or reading the audit log.
- *Controls:* every login, auth failure, authorization failure, analysis, and rotation request is logged with user, role, IP, and UTC timestamp.
- *Gap:* the log itself is mutable (T2). Shared demo accounts would break attribution.
- *CWE:* CWE-778 · *Residual:* **Medium**

### Information disclosure

**I1. PII exposure to the model provider or in responses**
- *Attack:* an analyst submits or extracts customer PII; the model echoes PII from its input.
- *Controls:* for non-admin roles, email, phone, SSN and card numbers are **tokenized** before the model call (Fernet-encrypted vault, admin-only audited detokenization) and any raw PII is **redacted on output**. Audit entries record only counts and types, never text.
- *Evidence:* SI-1, SI-2, AZ-3; `TestTokenization`; `test_document_text_and_pii_not_written_to_audit_log`.
- *Gap:* names, addresses, and non-US identifiers are not detected ("Jane Roe" reached the model in SI-1). Admins send raw PII to the provider by design.
- *Refs:* LLM02, CWE-359 · *Residual:* **Medium**

**I2. API key or signing key exposure**
- *Attack:* keys leak through source control, logs, or error messages.
- *Controls:* keys are read only from the environment; `.env` is git-ignored; no default key in source (an ephemeral random key is generated with a warning). Error responses are generic.
- *Evidence:* EH-1.
- *Fix:* a secrets manager with rotation, plus pre-commit secret scanning.
- *CWE:* CWE-798, CWE-532 · *Residual:* **Low**

**I3. Error-message leakage**
- *Controls:* JSON error handlers for 404, 405, 413, and 500; upstream exceptions mapped to a generic 502 with a random error id; stack traces go only to server logs.
- *Evidence:* EH-1, EH-2.
- *CWE:* CWE-209 · *Residual:* **Low**

**I4. Username enumeration**
- *Attack:* tell valid from invalid usernames by response or timing.
- *Controls:* identical error body; unknown users are checked against a dummy hash so they take the same code path.
- *CWE:* CWE-204 · *Residual:* **Low**

### Denial of service

**D1. Rate-limit bypass and cost exhaustion**
- *Attack:* many accounts or many processes drive up API spend or quota use.
- *Controls:* per-user sliding window (analyst 3/min, admin 10/min); `max_tokens=500` per call.
- *Evidence:* RL-1.
- *Gap:* limits are per process and per user. There is no global budget and no per-IP limit before authentication.
- *Refs:* LLM10, CWE-770 · *Residual:* **Medium**

**D2. Oversized input**
- *Controls:* 200,000-character document limit; 1 MB request body limit (413).
- *Evidence:* RL-2, RL-3.
- *CWE:* CWE-400 · *Residual:* **Low**

### Elevation of privilege

**E1. Missing authorization on an endpoint**
- *Controls:* every protected route uses one decorator with an explicit permission; RBAC is deny-by-default (unknown roles and permissions are false).
- *Evidence:* AZ-1, AZ-2, `test_rbac_table`.
- *CWE:* CWE-285 · *Residual:* **Low**

**E2. Model-mediated privilege escalation (excessive agency)**
- *Attack:* injection causes the model to take actions on the user's behalf.
- *Controls:* not applicable today because the model has no tools. **This threat becomes High the moment tools or retrieval are added** without per-tool authorization and human approval.
- *Refs:* LLM06 · *Residual:* **Medium** (architectural tripwire)


---

## 4. Prioritized actions

| Priority | Action | Threats |
|----------|--------|---------|
| 1 | Run `redteam/run_redteam.py --live` and grade the model-layer probes; expand the probe set | T1 |
| 2 | Ship audit events to append-only central storage | T2, R1 |
| 3 | Token revocation (`jti` denylist / token version) and MFA via an IdP | S2, S3 |
| 4 | Shared rate-limit store (Redis), global spend budget, per-IP pre-auth limits | D1, S2 |
| 5 | NER-based PII detection; policy for what admins may send to the provider | I1 |
| 6 | Gate any future tool/retrieval feature behind its own threat model | E2 |

---

## 5. Framework mapping

**OWASP LLM Top 10 (2025)**

| Risk | Threats | Status |
|------|---------|--------|
| LLM01 Prompt Injection | T1 | Partially controlled; model layer untested |
| LLM02 Sensitive Information Disclosure | I1, I2 | Controlled for common US PII patterns |
| LLM03 Supply Chain | — | Out of scope here; see the scanner project for dependency checks |
| LLM05 Improper Output Handling | T1 | Output escaped and redacted (SI-2, SI-3) |
| LLM06 Excessive Agency | E2 | Not applicable while the model has no tools |
| LLM07 System Prompt Leakage | T1 | System prompt holds no secrets by design |
| LLM10 Unbounded Consumption | D1, D2 | Per-user limits; no global budget |

**NIST AI RMF:** MAP 4/5 (risks and impacts identified and characterized), MEASURE 2 (controls evaluated through the harness), MANAGE 1 (actions prioritized above).

---

**Model date:** 2026-10-02 · **Review trigger:** any new endpoint, tool, data source, or change to the auth design.
