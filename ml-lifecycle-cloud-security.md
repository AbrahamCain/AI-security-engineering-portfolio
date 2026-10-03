# ML Lifecycle Security Map (AWS)

**Author:** Abraham Cain

The ML lifecycle in six stages. For each stage: what can go wrong, the AWS controls that address it,
and where this portfolio demonstrates it. The AWS service names and settings are the real ones; the
scanner's [AWS AI checks](./ai-exposure-scanner/) use the same parameter names.

| Stage | Main threats | AWS controls | In this portfolio |
|-------|--------------|--------------|-------------------|
| **1. Data collection and storage** | PII over-collection; public buckets; unencrypted data; poisoned sources | S3 Block Public Access, SSE-KMS with customer-managed keys, Macie for PII discovery, Lake Formation for column/row access, CloudTrail data events | Scanner: public storage, encryption at rest, access logging. App: tokenization and masking |
| **2. Data preparation and labeling** | Label flipping and backdoor triggers in data; leakage of raw PII into feature stores | Data lineage (SageMaker ML Lineage Tracking), Ground Truth labeler access restrictions, Glue data-quality rules, feature-store encryption | Not covered in code (documented only) |
| **3. Training** | Malicious dependencies or base models; training jobs with internet egress; membership leakage from overfitting | SageMaker training with `EnableNetworkIsolation`, VPC-only subnets, encrypted inter-container traffic, least-privilege execution roles, private package mirror (CodeArtifact) | CI: pip-audit. Scanner: wildcard IAM roles |
| **4. Model registry and artifacts** | Tampered or swapped model artifacts; unversioned models; pickle deserialization | SageMaker Model Registry with approval status, S3 Object Lock and versioning, KMS on artifacts, artifact hashes in the pipeline, safetensors over pickle | Scanner: no model versioning, unversioned artifact bucket, public artifact storage |
| **5. Deployment and inference** | Prompt injection; evasion inputs; data capture storing PII; public endpoints; unbounded cost | SageMaker endpoint `KmsKeyId` and encrypted `DataCaptureConfig`; VPC endpoints (PrivateLink); Bedrock Guardrails (prompt-attack and PII filters); API Gateway throttling; WAF | App: auth, RBAC, rate limits, output encoding. Scanner: SageMaker/Bedrock checks. Red team: injection testing |
| **6. Monitoring and incident response** | Silent drift; undetected abuse; no audit trail for model calls | SageMaker Model Monitor (data and model quality), Bedrock model invocation logging, CloudTrail, GuardDuty, CloudWatch alarms on cost and invocation anomalies | App audit log. Scanner: missing invocation logging, missing monitoring |

## Cross-cutting controls

- **Identity:** separate execution roles per pipeline stage. No `*` actions. MFA for human roles. SCPs that deny disabling CloudTrail or making buckets public.
- **Secrets:** Secrets Manager with rotation for model API keys. No keys in notebooks. The scanner and Gitleaks check for this.
- **Network:** notebooks with `DirectInternetAccess=Disabled`, endpoints inside VPCs, interface endpoints for Bedrock and SageMaker APIs.
- **Encryption:** KMS customer-managed keys for data, artifacts, endpoints, data capture and logs. Key policies scoped to the roles that need them.

## Data protection choices

| Technique | Reversible | Keeps joins/references | Use when | In this portfolio |
|-----------|------------|------------------------|----------|-------------------|
| Encryption (KMS / Fernet) | Yes, with key | No | Data at rest or in transit that systems must read back | Token vault stores originals as Fernet ciphertext |
| Tokenization | Yes, through a vault | Yes (same value → same token) | Downstream systems (or an LLM) need to tell records apart without seeing the values | App tokenizes PII before the model call; admin-only detokenize |
| Masking / redaction | No | No | Display, logs, model output | App redacts raw PII in model output; audit log stores counts only |

Other clouds have equivalents: Azure ML / Azure OpenAI with Private Link and Content Safety, and Vertex AI with VPC Service Controls and Model Armor.
