# AI Exposure Management Security Scanner

**Author:** Abraham Cain

A Python configuration-review scanner for an AI asset inventory. It reads a JSON description of
models, APIs, identities, data stores, and dependencies, then reports exposures ranked by risk,
each mapped to a CWE and a remediation.

All data in `sample_assets.json` is fictional. The scanner never connects to the systems it describes.

## What it checks

| Module | Looks for | CWE |
|--------|-----------|-----|
| `CredentialScanner` | API keys, passwords, credentials in connection strings, AWS access key IDs, private key blocks in config. Values like `${VAR}` are treated as references, not secrets. Evidence is masked. | CWE-798 |
| `PermissionAnalyzer` | Wildcard actions, wildcard resources, roles assumable without MFA | CWE-250, CWE-732, CWE-308 |
| `APIConfigAnalyzer` | No authentication, plaintext HTTP, no rate limiting, no request logging | CWE-306, CWE-319, CWE-770, CWE-778 |
| `StorageConfigAnalyzer` | Public access, no encryption at rest, no access logging, no object versioning | CWE-732, CWE-311, CWE-778, CWE-494 |
| `DependencyVulnerabilityScanner` | Packages older than the first fixed version in a small demo advisory table | CWE-1395 |
| `AWSAIServiceAnalyzer` | SageMaker endpoints (KMS, unencrypted data capture, network isolation, VPC), SageMaker notebooks (direct internet access, root access), Bedrock (guardrails, model invocation logging, VPC endpoint) | CWE-311, CWE-312, CWE-668, CWE-250, CWE-1427, CWE-778 |
| `SecurityConfigAnalyzer` | Model without versioning, input validation, or monitoring | CWE-20, CWE-778 (versioning is listed as a governance control, no CWE) |

The dependency table has three entries (requests / CVE-2023-32681, Flask / CVE-2023-30861,
Django / CVE-2019-14232) and exists only to show the version-comparison logic. For real dependency
scanning, use pip-audit, OSV-Scanner, or Dependabot.

## Run it

```bash
cd ai-exposure-scanner
pip install -r requirements.txt     # only pytest; the scanner is stdlib-only
python scanner.py sample_assets.json
pytest tests -v
```

Outputs:
- `findings.csv`: one row per finding, sorted CRITICAL → LOW
- `remediation_recommendations.json`: findings grouped by risk level

Both files are committed as example output from the sample inventory.

## Results on the sample inventory

11 assets → **28 findings: 7 critical, 10 high, 10 medium, 1 low.**

| Asset | Findings |
|-------|----------|
| Customer Risk Prediction Model | Hard-coded API key, credentials in DB connection string, no versioning, no input validation, no monitoring |
| Risk Scoring API: `POST /api/v1/score` | No auth, plaintext HTTP, no rate limit, no logging |
| Risk Scoring API: `GET /health` | None (control case) |
| ML Pipeline Execution Role | Wildcard actions, wildcard resources, no MFA |
| Data Scientist Role | None (control case: scoped, MFA required) |
| Customer Portal | requests 2.25.0, Flask 1.1.2, Django 2.2.0 below fixed versions |
| Customer Data Warehouse | Plaintext password, unencrypted backups, no access logging |
| Embeddings Store | Hard-coded API key |
| Model Artifacts S3 | Public access, no encryption, no versioning |
| Risk Model SageMaker Endpoint | Unencrypted data capture of inference payloads, no customer-managed KMS key, no network isolation, not VPC-attached |
| Data Science Notebook | Direct internet access, root access |
| Customer Support Assistant (Bedrock) | None (control case: guardrail, invocation logging, VPC endpoint) |

The three control cases matter: they show the scanner doesn't flag everything. The test suite asserts both are clean.

## Tests

35 tests (`pytest tests -v`):

| Class | Tests | Covers |
|-------|-------|--------|
| `TestCredentialScanner` | 6 | Key and password detection, connection strings, masking, env-reference exclusion |
| `TestPermissionAnalyzer` | 4 | Wildcards, MFA, least-privilege policy is clean |
| `TestAPIConfigAnalyzer` | 4 | Each misconfiguration, secure config is clean |
| `TestStorageConfigAnalyzer` | 3 | Public/unencrypted bucket, secure bucket, unrelated config |
| `TestDependencyVulnerabilityScanner` | 4 | Vulnerable versions flagged, patched versions not flagged |
| `TestSecurityConfigAnalyzer` | 3 | Model governance flags |
| `TestAIExposureScanner` | 5 | Load, scan, ordering, CSV and JSON export |
| `TestSampleInventory` | 1 | End-to-end assertions on the shipped inventory |
| `TestAWSAIServiceAnalyzer` | 5 | Insecure and hardened SageMaker endpoint, notebook, Bedrock |

## Limitations

- Rule-based: it finds what the rules describe and nothing else. Regex secret detection produces both false positives and false negatives; tools like gitleaks or trufflehog use far larger rule sets plus entropy checks.
- The inventory format is invented for this project. A real implementation would pull from cloud APIs (IAM, S3, API Gateway) or IaC.
- No exploitation, network scanning, or live checks.

## Framework alignment

- **NIST AI RMF:** MAP (inventory and risk identification) and MEASURE (repeatable, prioritized findings).
- **OWASP LLM Top 10 (2025):** LLM03 Supply Chain (dependencies, unversioned model artifacts in public storage), LLM02 Sensitive Information Disclosure (exposed credentials and data stores), LLM10 Unbounded Consumption (APIs without rate limits).
