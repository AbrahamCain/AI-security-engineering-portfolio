# DevSecOps Pipeline

Every push runs `.github/workflows/tests.yml` (workflow name **ci**), which has four jobs:

| Job | Stage | Tool | Gate |
|-----|-------|------|------|
| tests | Unit and security tests | pytest (scanner, app), red-team harness | Any failing test or failing red-team case |
| ml | ML security tests | pytest (adversarial ML lab, interpretability pipeline) | Any failing test |
| sast-sca-secrets | SAST | Bandit | Medium or high severity in non-test code |
| | SAST | Semgrep (`p/python`, `p/flask`) | Report only |
| | SCA | pip-audit | Any known-vulnerable dependency in the app or scanner |
| | Secrets | Gitleaks with [`gitleaks.toml`](./gitleaks.toml) | Any secret outside the allowlisted test fixtures |
| container-dast | Build | Docker ([`Dockerfile`](../claude-enterprise-app/Dockerfile)) | Build failure |
| | Image scan | Trivy | Critical CVE with an available fix |
| | Runtime checks | curl / docker inspect | Container must run as UID 10001 and send security headers |
| | DAST | OWASP ZAP baseline with [`zap-rules.tsv`](./zap-rules.tsv) | Report only (results in the job summary and artifact) |

`interp-probe.yml` is started by hand. It runs the GPT-2 interpretability experiment and commits the results.

## Tuning decisions

- **Gitleaks allowlist.** The scanner's test inventory and the red-team fixtures contain deliberately fake keys. They are allowlisted by path rather than by pattern, so a real key added anywhere else still fails the build.
- **ZAP rule 10049** ("non-storable content") is ignored because the API sends `Cache-Control: no-store` on purpose.
- **Semgrep and ZAP are report-only** while baselines are established. Promoting them to gates is a one-line change once the existing findings are triaged.
- **Bandit low-severity findings** (test fixtures, the harness's demo passwords, `random` used for dataset shuffling) are visible in the log but don't block. None of them are security-relevant.
