#!/usr/bin/env python3
"""
AI Exposure Management Security Scanner

Evaluates a (fictional) enterprise AI asset inventory for credential exposure,
over-permissive identities, insecure API and storage configuration, vulnerable
dependencies, and missing model-governance controls.

All input data is synthetic. This is a configuration-review tool: it reads a
JSON inventory and never connects to the systems it describes.
"""

import csv
import json
import re
import sys
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class RiskLevel(Enum):
    """Risk severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


RISK_ORDER = {level.value: idx for idx, level in enumerate(RiskLevel)}


@dataclass
class Finding:
    """Security finding from scanner"""
    asset_id: str
    asset_name: str
    asset_type: str
    finding_type: str
    description: str
    risk_level: str
    cwe_id: str
    remediation: str
    evidence: str


def _mask(secret: str) -> str:
    """Mask a secret for evidence output: keep first 4 chars only."""
    if len(secret) <= 4:
        return "****"
    return secret[:4] + "*" * min(len(secret) - 4, 12)


class CredentialScanner:
    """Detect credentials embedded in configuration (CWE-798)."""

    # Configuration is serialized to JSON before matching, so key names are
    # followed by a closing quote: "api_key": "value". Values starting with
    # "$" or "{" are treated as environment/secret-manager references.
    PATTERNS = {
        "hardcoded_api_key": re.compile(
            r"""api[_-]?key["']?\s*[:=]\s*["']([^"'${\s][^"'\s]{11,})["']""", re.IGNORECASE),
        "hardcoded_password": re.compile(
            r"""(?:password|passwd|pwd)["']?\s*[:=]\s*["']([^"'${\s][^"']{7,})["']""", re.IGNORECASE),
        "connection_string_credentials": re.compile(
            r"""(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mssql)(?:\+[a-z0-9]+)?://([^:/\s"']+):([^@\s"']+)@""",
            re.IGNORECASE),
        "aws_access_key_id": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "private_key_block": re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY"),
    }

    @staticmethod
    def scan_config(config_data: Dict[str, Any],
                    asset_id: Optional[str] = None,
                    asset_name: Optional[str] = None) -> List[Finding]:
        findings = []
        asset_id = asset_id or config_data.get("id", "unknown")
        asset_name = asset_name or config_data.get("name", "unknown")
        config_str = json.dumps(config_data)

        for pattern_name, pattern in CredentialScanner.PATTERNS.items():
            for match in pattern.finditer(config_str):
                secret = match.group(match.lastindex) if match.lastindex else match.group(0)
                findings.append(Finding(
                    asset_id=asset_id,
                    asset_name=asset_name,
                    asset_type="Configuration",
                    finding_type="Credential Exposure",
                    description=f"Credential stored in plaintext configuration ({pattern_name})",
                    risk_level=RiskLevel.CRITICAL.value,
                    cwe_id="CWE-798",
                    remediation="Rotate the credential, then load it at runtime from a secrets manager "
                                "(e.g. AWS Secrets Manager, HashiCorp Vault) instead of configuration.",
                    evidence=f"{pattern_name}: {_mask(secret)}",
                ))
        return findings


class PermissionAnalyzer:
    """Analyze IAM-style permission policies."""

    @staticmethod
    def analyze_permissions(permissions: Dict[str, Any],
                            asset_id: Optional[str] = None) -> List[Finding]:
        findings = []
        principal = permissions.get("principal", "unknown")
        asset_id = asset_id or principal
        name = f"Role: {principal}"

        if "*" in permissions.get("actions", []):
            findings.append(Finding(
                asset_id, name, "IAM Policy", "Excessive Permissions",
                "Policy grants wildcard ('*') actions",
                RiskLevel.HIGH.value, "CWE-250",
                "Apply least privilege: enumerate only required actions (e.g. s3:GetObject).",
                "actions: ['*']"))

        if "*" in permissions.get("resources", []):
            findings.append(Finding(
                asset_id, name, "IAM Policy", "Excessive Permissions",
                "Policy applies to all resources ('*')",
                RiskLevel.HIGH.value, "CWE-732",
                "Scope resources to specific ARNs (e.g. arn:aws:s3:::my-bucket/*).",
                "resources: ['*']"))

        if not permissions.get("mfa_required", False):
            findings.append(Finding(
                asset_id, name, "IAM Policy", "Missing Authentication Control",
                "Role can be assumed without multi-factor authentication",
                RiskLevel.MEDIUM.value, "CWE-308",
                "Require MFA via policy condition aws:MultiFactorAuthPresent=true for human-assumable roles.",
                "mfa_required: false"))

        return findings


class APIConfigAnalyzer:
    """Analyze API endpoint security configuration."""

    @staticmethod
    def analyze_api(api_config: Dict[str, Any]) -> List[Finding]:
        findings = []
        aid = api_config.get("id", "unknown")
        name = api_config.get("name", "unknown")

        if api_config.get("authentication") == "none":
            findings.append(Finding(
                aid, name, "API Endpoint", "Missing Authentication",
                "API endpoint accepts unauthenticated requests",
                RiskLevel.CRITICAL.value, "CWE-306",
                "Require authentication (OAuth 2.0 / OIDC, mTLS, or rotated API keys).",
                "authentication: none"))

        if api_config.get("protocol") == "http":
            findings.append(Finding(
                aid, name, "API Endpoint", "Unencrypted Communication",
                "API served over plaintext HTTP",
                RiskLevel.CRITICAL.value, "CWE-319",
                "Serve over HTTPS with TLS 1.2+ and redirect or refuse plaintext HTTP.",
                "protocol: http"))

        if not api_config.get("rate_limiting_enabled", False):
            findings.append(Finding(
                aid, name, "API Endpoint", "Denial of Service Risk",
                "API endpoint does not enforce rate limiting",
                RiskLevel.MEDIUM.value, "CWE-770",
                "Enforce per-client rate limits at the gateway or application.",
                "rate_limiting_enabled: false"))

        if not api_config.get("logging_enabled", False):
            findings.append(Finding(
                aid, name, "API Endpoint", "Missing Audit Logging",
                "API requests are not logged",
                RiskLevel.MEDIUM.value, "CWE-778",
                "Enable request/audit logging with PII masking and central retention.",
                "logging_enabled: false"))

        return findings


class StorageConfigAnalyzer:
    """Analyze data store / object storage configuration flags."""

    @staticmethod
    def analyze_storage(config: Dict[str, Any], asset_id: str, asset_name: str) -> List[Finding]:
        findings = []

        if config.get("public_access") is True:
            findings.append(Finding(
                asset_id, asset_name, "Storage", "Public Exposure",
                "Storage location allows public access",
                RiskLevel.CRITICAL.value, "CWE-732",
                "Block public access and grant read access only to specific principals.",
                "public_access: true"))

        for key in ("encryption", "backup_encryption"):
            if config.get(key) is False:
                findings.append(Finding(
                    asset_id, asset_name, "Storage", "Missing Encryption at Rest",
                    f"Data at rest is not encrypted ({key})",
                    RiskLevel.HIGH.value, "CWE-311",
                    "Enable encryption at rest with a managed KMS key.",
                    f"{key}: false"))

        if config.get("access_logging") is False:
            findings.append(Finding(
                asset_id, asset_name, "Storage", "Missing Audit Logging",
                "Data access is not logged",
                RiskLevel.MEDIUM.value, "CWE-778",
                "Enable access logging and ship logs to central storage.",
                "access_logging: false"))

        if config.get("versioning_enabled") is False:
            findings.append(Finding(
                asset_id, asset_name, "Storage", "No Object Versioning",
                "Stored artifacts can be overwritten without history (model tampering risk)",
                RiskLevel.MEDIUM.value, "CWE-494",
                "Enable versioning and integrity checks (hash/signature) for model artifacts.",
                "versioning_enabled: false"))

        return findings


class AWSAIServiceAnalyzer:
    """
    Review AWS AI/ML service settings expressed in the inventory.

    Field names follow the corresponding AWS API parameters (e.g. SageMaker
    EndpointConfig KmsKeyId / DataCaptureConfig, Model EnableNetworkIsolation,
    NotebookInstance DirectInternetAccess / RootAccess, Bedrock guardrails and
    model invocation logging).
    """

    @staticmethod
    def analyze(cfg: Dict[str, Any], asset_id: str, asset_name: str) -> List[Finding]:
        service = cfg.get("service")
        f: List[Finding] = []

        def add(ftype, desc, risk, cwe, fix, evidence):
            f.append(Finding(asset_id, asset_name, f"AWS {service}", ftype, desc, risk, cwe, fix, evidence))

        if service == "sagemaker_endpoint":
            if not cfg.get("kms_key_id"):
                add("Missing Encryption at Rest", "Endpoint storage volume not encrypted with a customer-managed KMS key",
                    RiskLevel.MEDIUM.value, "CWE-311", "Set KmsKeyId on the EndpointConfig.", "kms_key_id: null")
            capture = cfg.get("data_capture", {})
            if capture.get("enabled") and not capture.get("kms_key_id"):
                add("Sensitive Data Capture", "Data capture stores raw inference requests/responses (likely PII) without KMS encryption",
                    RiskLevel.HIGH.value, "CWE-312",
                    "Set DataCaptureConfig.KmsKeyId, restrict the S3 prefix, and set a retention policy.",
                    "data_capture.enabled: true, kms_key_id: null")
            if not cfg.get("enable_network_isolation"):
                add("No Network Isolation", "Model container can make outbound network calls (exfiltration path for a malicious model)",
                    RiskLevel.MEDIUM.value, "CWE-668", "Set EnableNetworkIsolation=true on the Model.",
                    "enable_network_isolation: false")
            if not cfg.get("vpc_config"):
                add("Not VPC-Attached", "Endpoint is not attached to a private VPC",
                    RiskLevel.LOW.value, "CWE-668", "Provide VpcConfig with private subnets and restrictive security groups.",
                    "vpc_config: null")

        elif service == "sagemaker_notebook":
            if cfg.get("direct_internet_access") == "Enabled":
                add("Direct Internet Access", "Notebook has direct internet access, bypassing VPC egress controls",
                    RiskLevel.HIGH.value, "CWE-668", "Set DirectInternetAccess=Disabled and route egress through the VPC.",
                    "direct_internet_access: Enabled")
            if cfg.get("root_access") == "Enabled":
                add("Root Access Enabled", "Notebook users have root on the instance",
                    RiskLevel.MEDIUM.value, "CWE-250", "Set RootAccess=Disabled.", "root_access: Enabled")

        elif service == "bedrock":
            if not cfg.get("guardrail_id"):
                add("No Guardrail", "Model invocations are not routed through a Bedrock guardrail (no prompt-attack or PII filters)",
                    RiskLevel.MEDIUM.value, "CWE-1427",
                    "Attach a guardrail with prompt-attack and sensitive-information filters.", "guardrail_id: null")
            if not cfg.get("model_invocation_logging"):
                add("Missing Audit Logging", "Model invocation logging is disabled",
                    RiskLevel.MEDIUM.value, "CWE-778",
                    "Enable model invocation logging to an encrypted, access-restricted destination.",
                    "model_invocation_logging: false")
            if not cfg.get("vpc_endpoint"):
                add("Public Endpoint Path", "Bedrock is reached over the public endpoint instead of a VPC interface endpoint",
                    RiskLevel.LOW.value, "CWE-668", "Use an interface VPC endpoint (PrivateLink) with an endpoint policy.",
                    "vpc_endpoint: false")
        return f


def _parse_version(version: str) -> Tuple[int, ...]:
    parts = []
    for piece in version.split("."):
        digits = re.match(r"\d+", piece)
        parts.append(int(digits.group(0)) if digits else 0)
    return tuple(parts)


class DependencyVulnerabilityScanner:
    """
    Flag dependencies older than a known fixed version.

    The advisory table is a small, hand-maintained DEMO list. Real scanning
    should use pip-audit, OSV-Scanner, Dependabot, or similar.
    """

    ADVISORIES = {
        # package: (first fixed version, advisory id)
        "requests": ("2.31.0", "CVE-2023-32681"),
        "flask": ("2.2.5", "CVE-2023-30861"),
        "django": ("2.2.4", "CVE-2019-14232"),
    }

    @staticmethod
    def scan_dependencies(dependencies: List[Dict[str, str]]) -> List[Finding]:
        findings = []
        for dep in dependencies:
            pkg = dep.get("name", "").lower()
            version = dep.get("version", "")
            if pkg not in DependencyVulnerabilityScanner.ADVISORIES or not version:
                continue
            fixed_in, advisory = DependencyVulnerabilityScanner.ADVISORIES[pkg]
            if _parse_version(version) < _parse_version(fixed_in):
                findings.append(Finding(
                    f"dep-{pkg}", f"{pkg}=={version}", "Dependency", "Vulnerable Package",
                    f"{pkg} {version} is affected by {advisory}",
                    RiskLevel.HIGH.value, "CWE-1395",
                    f"Upgrade {pkg} to >= {fixed_in} (or latest) and review {advisory}.",
                    f"installed {version} < fixed {fixed_in}"))
        return findings


class SecurityConfigAnalyzer:
    """Review AI model governance/security configuration."""

    @staticmethod
    def analyze_model_security(model_config: Dict[str, Any]) -> List[Finding]:
        findings = []
        mid = model_config.get("id", "unknown")
        name = model_config.get("name", "unknown")

        if not model_config.get("version_control_enabled", False):
            findings.append(Finding(
                mid, name, "ML Model", "No Model Versioning",
                "Model versions are not tracked, so a tampered or regressed model cannot be detected or rolled back",
                RiskLevel.MEDIUM.value, "N/A (governance control)",
                "Track models in a registry (e.g. MLflow) with immutable versions and artifact hashes.",
                "version_control_enabled: false"))

        if not model_config.get("input_validation_enabled", False):
            findings.append(Finding(
                mid, name, "ML Model", "Missing Input Validation",
                "Model endpoint does not validate inputs before inference",
                RiskLevel.HIGH.value, "CWE-20",
                "Validate type, schema, size, and ranges before inference; isolate untrusted text from instructions.",
                "input_validation_enabled: false"))

        if not model_config.get("monitoring_enabled", False):
            findings.append(Finding(
                mid, name, "ML Model", "No Performance Monitoring",
                "Model performance and drift are not monitored",
                RiskLevel.MEDIUM.value, "CWE-778",
                "Monitor accuracy/drift and alert on threshold breaches.",
                "monitoring_enabled: false"))

        return findings


class AIExposureScanner:
    """Main scanner orchestrating all security checks"""

    def __init__(self, assets_file: str):
        self.assets_file = assets_file
        self.findings: List[Finding] = []
        self.assets: List[Dict[str, Any]] = []

    def load_assets(self) -> bool:
        try:
            with open(self.assets_file, "r") as f:
                data = json.load(f)
        except FileNotFoundError:
            print(f"Error: assets file not found: {self.assets_file}", file=sys.stderr)
            return False
        except json.JSONDecodeError as exc:
            print(f"Error: invalid JSON in {self.assets_file}: {exc}", file=sys.stderr)
            return False
        self.assets = data.get("assets", [])
        return True

    def scan_all_assets(self) -> List[Finding]:
        self.findings = []
        for asset in self.assets:
            aid = asset.get("id", "unknown")
            aname = asset.get("name", "unknown")
            atype = asset.get("type")

            if "config" in asset:
                self.findings.extend(CredentialScanner.scan_config(asset["config"], aid, aname))
                self.findings.extend(StorageConfigAnalyzer.analyze_storage(asset["config"], aid, aname))

            if "aws_ai_config" in asset:
                self.findings.extend(AWSAIServiceAnalyzer.analyze(asset["aws_ai_config"], aid, aname))

            if "permissions" in asset:
                self.findings.extend(PermissionAnalyzer.analyze_permissions(asset["permissions"], aid))

            for endpoint in asset.get("endpoints", []):
                self.findings.extend(APIConfigAnalyzer.analyze_api(endpoint))

            if "dependencies" in asset:
                self.findings.extend(DependencyVulnerabilityScanner.scan_dependencies(asset["dependencies"]))

            if atype == "Model" or "model_config" in asset:
                model_config = {"id": aid, "name": aname, **asset.get("model_config", {})}
                self.findings.extend(SecurityConfigAnalyzer.analyze_model_security(model_config))

        return self.findings

    def prioritize_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: RISK_ORDER.get(f.risk_level, len(RISK_ORDER)))

    def risk_counts(self) -> Dict[str, int]:
        counts = {level.value: 0 for level in RiskLevel}
        for finding in self.findings:
            counts[finding.risk_level] += 1
        return counts

    def generate_remediation_recommendations(self) -> Dict[str, Any]:
        recommendations: Dict[str, List[Dict[str, str]]] = {level.value: [] for level in RiskLevel}
        for finding in self.prioritize_findings():
            recommendations[finding.risk_level].append({
                "asset": finding.asset_name,
                "issue": finding.finding_type,
                "remediation": finding.remediation,
                "cwe": finding.cwe_id,
            })
        return recommendations

    def export_findings_csv(self, output_file: str) -> bool:
        fieldnames = list(Finding.__dataclass_fields__.keys())
        try:
            with open(output_file, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for finding in self.prioritize_findings():
                    writer.writerow(asdict(finding))
            return True
        except OSError as exc:
            print(f"Error writing CSV: {exc}", file=sys.stderr)
            return False

    def export_recommendations_json(self, output_file: str) -> bool:
        try:
            with open(output_file, "w") as f:
                json.dump(self.generate_remediation_recommendations(), f, indent=2)
            return True
        except OSError as exc:
            print(f"Error writing JSON: {exc}", file=sys.stderr)
            return False

    def print_summary(self, top_n: int = 5) -> None:
        counts = self.risk_counts()
        print("\n" + "=" * 70)
        print("AI EXPOSURE MANAGEMENT SECURITY SCANNER - SUMMARY")
        print("=" * 70)
        print(f"\nAssets scanned: {len(self.assets)}")
        print(f"Total findings: {len(self.findings)}")
        for level in RiskLevel:
            print(f"  {level.value:<9}{counts[level.value]}")
        print(f"\nTop {top_n} findings:")
        for i, finding in enumerate(self.prioritize_findings()[:top_n], 1):
            print(f"\n{i}. [{finding.risk_level}] {finding.finding_type} ({finding.cwe_id})")
            print(f"   Asset: {finding.asset_name}")
            print(f"   Issue: {finding.description}")
            print(f"   Fix:   {finding.remediation}")
        print("\n" + "=" * 70 + "\n")


def main() -> int:
    assets_file = sys.argv[1] if len(sys.argv) > 1 else "sample_assets.json"
    if assets_file in ("-h", "--help"):
        print("usage: python scanner.py [assets.json]")
        return 0

    scanner = AIExposureScanner(assets_file)
    if not scanner.load_assets():
        return 1

    scanner.scan_all_assets()
    scanner.print_summary()

    ok = scanner.export_findings_csv("findings.csv") and \
        scanner.export_recommendations_json("remediation_recommendations.json")
    if ok:
        print("Findings exported to findings.csv and remediation_recommendations.json")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
