"""
Unit tests for AI Exposure Management Security Scanner
"""

import pytest
import json
import tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner import (
    CredentialScanner,
    PermissionAnalyzer,
    APIConfigAnalyzer,
    DependencyVulnerabilityScanner,
    SecurityConfigAnalyzer,
    StorageConfigAnalyzer,
    AWSAIServiceAnalyzer,
    AIExposureScanner,
    RiskLevel,
)


class TestCredentialScanner:
    """Test credential exposure detection"""

    def test_detect_hardcoded_api_key(self):
        """Should detect hardcoded API keys"""
        config = {
            "id": "test-001",
            "name": "test-app",
            "api_key": "sk-proj-0123456789abcdefghij"
        }
        findings = CredentialScanner.scan_config(config)
        assert len(findings) > 0
        assert findings[0].finding_type == "Credential Exposure"
        assert findings[0].risk_level == RiskLevel.CRITICAL.value

    def test_detect_database_password(self):
        """Should detect hardcoded database passwords"""
        config = {
            "id": "test-001",
            "name": "app-db",
            "connection_string": "postgresql://admin:MySecret123@db.example.com:5432/appdb"
        }
        findings = CredentialScanner.scan_config(config)
        assert len(findings) > 0

    def test_evidence_is_masked(self):
        """Evidence must not echo the full secret back into reports"""
        config = {"id": "t", "name": "t", "api_key": "sk-proj-0123456789abcdefghij"}
        findings = CredentialScanner.scan_config(config)
        assert findings
        for f in findings:
            assert "0123456789abcdefghij" not in f.evidence

    def test_detect_hardcoded_password_field(self):
        """Should detect a plaintext password field"""
        config = {"id": "db", "name": "db", "password": "CustomerDB@2024"}
        findings = CredentialScanner.scan_config(config)
        assert any("hardcoded_password" in f.description for f in findings)

    def test_password_env_reference_not_flagged(self):
        """Environment variable references are not credentials"""
        config = {"id": "db", "name": "db", "password": "${DB_PASSWORD}"}
        assert CredentialScanner.scan_config(config) == []

    def test_clean_config_no_findings(self):
        """Clean config should have no credential findings"""
        config = {
            "id": "test-001",
            "name": "clean-app",
            "database_url": "${DB_URL}",
            "api_key": "${API_KEY}"
        }
        findings = CredentialScanner.scan_config(config)
        # Should not find credentials in environment variable references
        credential_findings = [f for f in findings if f.finding_type == "Credential Exposure"]
        assert len(credential_findings) == 0


class TestPermissionAnalyzer:
    """Test IAM permission analysis"""

    def test_detect_wildcard_actions(self):
        """Should detect wildcard actions in IAM policy"""
        permissions = {
            "principal": "test-role",
            "actions": ["*"],
            "resources": ["arn:aws:s3:::bucket/*"],
        }
        findings = PermissionAnalyzer.analyze_permissions(permissions)
        assert len(findings) > 0
        assert findings[0].finding_type == "Excessive Permissions"
        assert findings[0].risk_level == RiskLevel.HIGH.value

    def test_detect_wildcard_resources(self):
        """Should detect wildcard resources"""
        permissions = {
            "principal": "test-role",
            "actions": ["s3:GetObject"],
            "resources": ["*"],
        }
        findings = PermissionAnalyzer.analyze_permissions(permissions)
        assert len(findings) > 0
        assert any(f.finding_type == "Excessive Permissions" for f in findings)

    def test_detect_missing_mfa(self):
        """Should detect roles without MFA requirement"""
        permissions = {
            "principal": "test-role",
            "actions": ["iam:CreateAccessKey"],
            "resources": ["*"],
            "mfa_required": False,
        }
        findings = PermissionAnalyzer.analyze_permissions(permissions)
        assert len(findings) > 0
        assert any(f.finding_type == "Missing Authentication Control" for f in findings)

    def test_least_privilege_policy(self):
        """Least privilege policy should have minimal findings"""
        permissions = {
            "principal": "test-role",
            "actions": ["s3:GetObject"],
            "resources": ["arn:aws:s3:::my-bucket/*"],
            "mfa_required": True,
        }
        findings = PermissionAnalyzer.analyze_permissions(permissions)
        # Should only flag if MFA is still considered required, otherwise clean
        assert len(findings) == 0


class TestAPIConfigAnalyzer:
    """Test API security configuration analysis"""

    def test_detect_missing_authentication(self):
        """Should detect API without authentication"""
        api_config = {
            "id": "api-001",
            "name": "public-api",
            "authentication": "none",
            "protocol": "https",
        }
        findings = APIConfigAnalyzer.analyze_api(api_config)
        assert len(findings) > 0
        assert findings[0].finding_type == "Missing Authentication"
        assert findings[0].risk_level == RiskLevel.CRITICAL.value

    def test_detect_unencrypted_http(self):
        """Should detect HTTP without HTTPS"""
        api_config = {
            "id": "api-001",
            "name": "insecure-api",
            "authentication": "api_key",
            "protocol": "http",
        }
        findings = APIConfigAnalyzer.analyze_api(api_config)
        assert len(findings) > 0
        assert any(f.finding_type == "Unencrypted Communication" for f in findings)

    def test_detect_missing_rate_limiting(self):
        """Should detect API without rate limiting"""
        api_config = {
            "id": "api-001",
            "name": "api-no-limit",
            "authentication": "api_key",
            "protocol": "https",
            "rate_limiting_enabled": False,
        }
        findings = APIConfigAnalyzer.analyze_api(api_config)
        assert len(findings) > 0
        assert any(f.finding_type == "Denial of Service Risk" for f in findings)

    def test_secure_api_config(self):
        """Secure API config should have no findings"""
        api_config = {
            "id": "api-001",
            "name": "secure-api",
            "authentication": "oauth2",
            "protocol": "https",
            "rate_limiting_enabled": True,
            "logging_enabled": True,
        }
        findings = APIConfigAnalyzer.analyze_api(api_config)
        assert len(findings) == 0


class TestDependencyVulnerabilityScanner:
    """Test dependency vulnerability scanning"""

    def test_detect_vulnerable_requests(self):
        """Should detect vulnerable requests library"""
        dependencies = [
            {"name": "requests", "version": "2.25.0"}
        ]
        findings = DependencyVulnerabilityScanner.scan_dependencies(dependencies)
        assert len(findings) > 0
        assert findings[0].finding_type == "Vulnerable Package"
        assert findings[0].risk_level == RiskLevel.HIGH.value

    def test_detect_vulnerable_flask(self):
        """Should detect vulnerable Flask version"""
        dependencies = [
            {"name": "flask", "version": "1.1.2"}
        ]
        findings = DependencyVulnerabilityScanner.scan_dependencies(dependencies)
        assert len(findings) > 0

    def test_patched_version_not_flagged(self):
        """Versions at or above the fixed release must not be flagged"""
        dependencies = [
            {"name": "requests", "version": "2.32.3"},
            {"name": "flask", "version": "3.1.0"},
        ]
        assert DependencyVulnerabilityScanner.scan_dependencies(dependencies) == []

    def test_clean_dependencies(self):
        """Clean dependencies should have no findings"""
        dependencies = [
            {"name": "numpy", "version": "1.21.0"},
            {"name": "pandas", "version": "1.3.0"},
        ]
        findings = DependencyVulnerabilityScanner.scan_dependencies(dependencies)
        assert len(findings) == 0


class TestSecurityConfigAnalyzer:
    """Test AI model security configuration"""

    def test_detect_missing_versioning(self):
        """Should detect models without version control"""
        model_config = {
            "id": "model-001",
            "name": "risk-model",
            "version_control_enabled": False,
        }
        findings = SecurityConfigAnalyzer.analyze_model_security(model_config)
        assert len(findings) > 0
        assert findings[0].finding_type == "No Model Versioning"

    def test_detect_missing_input_validation(self):
        """Should detect models without input validation"""
        model_config = {
            "id": "model-001",
            "name": "risk-model",
            "input_validation_enabled": False,
        }
        findings = SecurityConfigAnalyzer.analyze_model_security(model_config)
        assert len(findings) > 0
        assert any(f.finding_type == "Missing Input Validation" for f in findings)

    def test_secure_model_config(self):
        """Secure model config should have minimal findings"""
        model_config = {
            "id": "model-001",
            "name": "risk-model",
            "version_control_enabled": True,
            "input_validation_enabled": True,
            "monitoring_enabled": True,
        }
        findings = SecurityConfigAnalyzer.analyze_model_security(model_config)
        assert len(findings) == 0


class TestStorageConfigAnalyzer:
    """Test storage configuration analysis"""

    def test_detect_public_unencrypted_bucket(self):
        config = {"public_access": True, "encryption": False, "versioning_enabled": False}
        findings = StorageConfigAnalyzer.analyze_storage(config, "s3-1", "bucket")
        types = {f.finding_type for f in findings}
        assert "Public Exposure" in types
        assert "Missing Encryption at Rest" in types
        assert "No Object Versioning" in types

    def test_secure_storage_no_findings(self):
        config = {"public_access": False, "encryption": True,
                  "access_logging": True, "versioning_enabled": True}
        assert StorageConfigAnalyzer.analyze_storage(config, "s3-1", "bucket") == []

    def test_unrelated_config_no_findings(self):
        """Configs without storage flags should not produce storage findings"""
        assert StorageConfigAnalyzer.analyze_storage({"model_path": "s3://x"}, "m", "m") == []


class TestSampleInventory:
    """End-to-end check against the shipped sample inventory"""

    def test_sample_assets_findings(self):
        path = Path(__file__).parent.parent / "sample_assets.json"
        scanner = AIExposureScanner(str(path))
        assert scanner.load_assets()
        findings = scanner.scan_all_assets()
        names = {(f.asset_id, f.finding_type) for f in findings}
        assert ("model-001", "Credential Exposure") in names
        assert ("db-001", "Credential Exposure") in names
        assert ("cloud-storage-001", "Public Exposure") in names
        assert ("iam-role-001", "Excessive Permissions") in names
        # The least-privilege role with MFA should be clean
        assert not any(f.asset_id == "iam-role-002" for f in findings)
        # The hardened health endpoint should be clean
        assert not any(f.asset_id == "api-001-health" for f in findings)


class TestAIExposureScanner:
    """Integration tests for full scanner"""

    @pytest.fixture
    def sample_assets_file(self):
        """Create temporary assets file for testing"""
        assets = {
            "assets": [
                {
                    "id": "test-001",
                    "name": "Test App",
                    "type": "Application",
                    "config": {
                        "id": "test-001",
                        "api_key": "sk-proj-secret123"
                    },
                    "dependencies": [
                        {"name": "requests", "version": "2.25.0"}
                    ]
                }
            ]
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(assets, f)
            f.flush()
            yield f.name
        Path(f.name).unlink()

    def test_load_assets(self, sample_assets_file):
        """Should load assets from file"""
        scanner = AIExposureScanner(sample_assets_file)
        assert scanner.load_assets()
        assert len(scanner.assets) == 1

    def test_scan_all_assets(self, sample_assets_file):
        """Should scan all assets and find findings"""
        scanner = AIExposureScanner(sample_assets_file)
        scanner.load_assets()
        findings = scanner.scan_all_assets()
        assert len(findings) > 0
        # Should find credential and vulnerable dependency
        assert any(f.finding_type == "Credential Exposure" for f in findings)
        assert any(f.finding_type == "Vulnerable Package" for f in findings)

    def test_prioritize_findings(self, sample_assets_file):
        """Should prioritize findings by risk level"""
        scanner = AIExposureScanner(sample_assets_file)
        scanner.load_assets()
        scanner.scan_all_assets()
        prioritized = scanner.prioritize_findings()

        # First finding should be CRITICAL or HIGH
        assert prioritized[0].risk_level in [
            RiskLevel.CRITICAL.value,
            RiskLevel.HIGH.value
        ]

        # Should maintain risk order
        risk_order = [RiskLevel.CRITICAL.value, RiskLevel.HIGH.value, RiskLevel.MEDIUM.value]
        for i in range(len(prioritized) - 1):
            curr_risk = prioritized[i].risk_level
            next_risk = prioritized[i + 1].risk_level
            curr_idx = risk_order.index(curr_risk) if curr_risk in risk_order else len(risk_order)
            next_idx = risk_order.index(next_risk) if next_risk in risk_order else len(risk_order)
            assert curr_idx <= next_idx

    def test_export_findings_csv(self, sample_assets_file):
        """Should export findings to CSV"""
        with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as f:
            csv_file = f.name

        scanner = AIExposureScanner(sample_assets_file)
        scanner.load_assets()
        scanner.scan_all_assets()
        assert scanner.export_findings_csv(csv_file)
        assert Path(csv_file).exists()
        assert Path(csv_file).stat().st_size > 0

        Path(csv_file).unlink()

    def test_export_recommendations_json(self, sample_assets_file):
        """Should export recommendations to JSON"""
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            json_file = f.name

        scanner = AIExposureScanner(sample_assets_file)
        scanner.load_assets()
        scanner.scan_all_assets()
        assert scanner.export_recommendations_json(json_file)
        assert Path(json_file).exists()

        with open(json_file) as f:
            recs = json.load(f)
            assert "CRITICAL" in recs
            assert "HIGH" in recs

        Path(json_file).unlink()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])


class TestAWSAIServiceAnalyzer:
    """Test AWS AI/ML service checks"""

    def test_insecure_sagemaker_endpoint(self):
        cfg = {"service": "sagemaker_endpoint", "kms_key_id": None,
               "data_capture": {"enabled": True, "kms_key_id": None},
               "enable_network_isolation": False, "vpc_config": None}
        types = {f.finding_type for f in AWSAIServiceAnalyzer.analyze(cfg, "e", "e")}
        assert {"Sensitive Data Capture", "No Network Isolation", "Missing Encryption at Rest"} <= types

    def test_hardened_sagemaker_endpoint_clean(self):
        cfg = {"service": "sagemaker_endpoint", "kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/x",
               "data_capture": {"enabled": True, "kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/x"},
               "enable_network_isolation": True, "vpc_config": {"subnets": ["subnet-1"]}}
        assert AWSAIServiceAnalyzer.analyze(cfg, "e", "e") == []

    def test_notebook_internet_and_root(self):
        cfg = {"service": "sagemaker_notebook", "direct_internet_access": "Enabled", "root_access": "Enabled"}
        risks = {f.finding_type: f.risk_level for f in AWSAIServiceAnalyzer.analyze(cfg, "n", "n")}
        assert risks["Direct Internet Access"] == RiskLevel.HIGH.value
        assert "Root Access Enabled" in risks

    def test_bedrock_without_guardrail_or_logging(self):
        cfg = {"service": "bedrock", "guardrail_id": None, "model_invocation_logging": False, "vpc_endpoint": False}
        types = {f.finding_type for f in AWSAIServiceAnalyzer.analyze(cfg, "b", "b")}
        assert {"No Guardrail", "Missing Audit Logging", "Public Endpoint Path"} == types

    def test_hardened_bedrock_in_sample_is_clean(self):
        path = Path(__file__).parent.parent / "sample_assets.json"
        scanner = AIExposureScanner(str(path))
        scanner.load_assets()
        findings = scanner.scan_all_assets()
        assert not any(f.asset_id == "bedrock-001" for f in findings)
        assert any(f.asset_id == "sm-endpoint-001" for f in findings)
