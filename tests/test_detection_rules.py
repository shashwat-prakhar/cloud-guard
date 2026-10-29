"""Tests for CloudGuard Dual-Layer Detection Engine & Signature Rules."""

from datetime import datetime, timezone
import pytest

from detection.engine import DetectionEngine, DetectionType, SecurityFinding
from detection.rules.base import Severity
from detection.rules.catalog import (
    CloudTrailLoggingDisabledRule,
    IAMPolicyWildcardAdminRule,
    IAMRootAccountUsageRule,
    IAMUserWithoutMFARule,
    S3BucketMadePublicRule,
    S3EncryptionDisabledRule,
    SecurityGroupOpenPort22Rule,
    SecurityGroupOpenPort3389Rule,
)
from ingestion.models import Actor, CanonicalCloudEvent, EventSourceType, ResourceTarget


def make_test_event(
    event_name: str,
    resource_name: str = "test-resource",
    resource_type: str = "aws:resource",
    user_type: str = "IAMUser",
    principal_id: str = "AIDAEXAMPLE",
    mfa_auth: bool = False,
    request_parameters: dict = None,
    source_ip: str = "192.0.2.1",
    status: str = "Success",
) -> CanonicalCloudEvent:
    """Helper to construct a strongly-typed CanonicalCloudEvent for testing."""
    return CanonicalCloudEvent(
        event_source=EventSourceType.CLOUDTRAIL,
        event_name=event_name,
        actor=Actor(
            principal_id=principal_id,
            user_type=user_type,
            mfa_authenticated=mfa_auth,
            account_id="123456789012"
        ),
        resource=ResourceTarget(
            name=resource_name,
            resource_type=resource_type,
            region="us-east-1"
        ),
        source_ip=source_ip,
        status=status,
        request_parameters=request_parameters or {},
        raw_event={"eventName": event_name}
    )


def test_s3_bucket_made_public_rule():
    """Verify detection of public S3 bucket modifications."""
    rule = S3BucketMadePublicRule()

    # Case 1: PutBucketAcl with AllUsers grant
    event_public = make_test_event(
        event_name="PutBucketAcl",
        resource_name="customer-uploads",
        resource_type="s3:bucket",
        request_parameters={"AccessControlPolicy": "Grantee URI: .../AllUsers, Permission: READ"}
    )
    result = rule.evaluate(event_public)
    assert result is not None
    assert result.matched is True
    assert result.rule_id == "RULE-S3-001"
    assert result.severity == Severity.CRITICAL
    assert result.mitre_attack.technique_id == "T1530"
    assert result.cis_benchmark == "CIS AWS 2.1.5"

    # Case 2: DeletePublicAccessBlock
    event_pab_delete = make_test_event(
        event_name="DeletePublicAccessBlock",
        resource_name="customer-uploads",
        resource_type="s3:bucket"
    )
    assert rule.evaluate(event_pab_delete).matched is True

    # Case 3: Private bucket PutBucketAcl (should NOT match)
    event_private = make_test_event(
        event_name="PutBucketAcl",
        resource_name="internal-backups",
        resource_type="s3:bucket",
        request_parameters={"AccessControlPolicy": "Grantee URI: .../BucketOwnerFullControl"}
    )
    assert rule.evaluate(event_private) is None


def test_s3_encryption_disabled_rule():
    """Verify detection when default bucket encryption is deleted."""
    rule = S3EncryptionDisabledRule()

    event = make_test_event(
        event_name="DeleteBucketEncryption",
        resource_name="secure-records",
        resource_type="s3:bucket"
    )
    res = rule.evaluate(event)
    assert res is not None
    assert res.matched is True
    assert res.severity == Severity.HIGH
    assert res.mitre_attack.technique_id == "T1485"


def test_security_group_open_port_22_rule():
    """Verify detection of Security Group ingress opening port 22 to 0.0.0.0/0."""
    rule = SecurityGroupOpenPort22Rule()

    # Wide-open SSH
    open_event = make_test_event(
        event_name="AuthorizeSecurityGroupIngress",
        resource_name="sg-12345",
        resource_type="ec2:security-group",
        request_parameters={"ipPermissions": [{"fromPort": 22, "toPort": 22, "ipRanges": [{"cidrIp": "0.0.0.0/0"}]}]}
    )
    res = rule.evaluate(open_event)
    assert res is not None
    assert res.matched is True
    assert res.rule_id == "RULE-SG-001"
    assert res.mitre_attack.technique_id == "T1021.004"

    # Restricted SSH to corporate CIDR (should NOT match)
    restricted_event = make_test_event(
        event_name="AuthorizeSecurityGroupIngress",
        resource_name="sg-12345",
        resource_type="ec2:security-group",
        request_parameters={"ipPermissions": [{"fromPort": 22, "toPort": 22, "ipRanges": [{"cidrIp": "10.0.0.0/16"}]}]}
    )
    assert rule.evaluate(restricted_event) is None


def test_security_group_open_port_3389_rule():
    """Verify detection of Security Group ingress opening RDP (3389) to 0.0.0.0/0."""
    rule = SecurityGroupOpenPort3389Rule()

    open_event = make_test_event(
        event_name="AuthorizeSecurityGroupIngress",
        resource_name="sg-99999",
        resource_type="ec2:security-group",
        request_parameters={"ipRanges": ["0.0.0.0/0"], "port": 3389}
    )
    res = rule.evaluate(open_event)
    assert res is not None
    assert res.matched is True
    assert res.mitre_attack.technique_id == "T1021.001"


def test_iam_root_account_usage_rule():
    """Verify detection of Root account API activity."""
    rule = IAMRootAccountUsageRule()

    root_event = make_test_event(
        event_name="CreateUser",
        user_type="Root",
        principal_id="root-account"
    )
    res = rule.evaluate(root_event)
    assert res is not None
    assert res.matched is True
    assert res.severity == Severity.CRITICAL
    assert res.mitre_attack.technique_id == "T1078.001"

    # Normal IAM user should not trigger root rule
    iam_event = make_test_event(event_name="CreateUser", user_type="IAMUser")
    assert rule.evaluate(iam_event) is None


def test_iam_policy_wildcard_admin_rule():
    """Verify detection of AdministratorAccess or wildcard policies."""
    rule = IAMPolicyWildcardAdminRule()

    admin_event = make_test_event(
        event_name="AttachUserPolicy",
        request_parameters={"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
    )
    res = rule.evaluate(admin_event)
    assert res is not None
    assert res.matched is True
    assert res.rule_id == "RULE-IAM-002"
    assert res.mitre_attack.technique_id == "T1098"


def test_iam_user_without_mfa_rule():
    """Verify detection of console logins without MFA."""
    rule = IAMUserWithoutMFARule()

    # Login without MFA
    no_mfa_event = make_test_event(
        event_name="ConsoleLogin",
        mfa_auth=False,
        status="Success"
    )
    res = rule.evaluate(no_mfa_event)
    assert res is not None
    assert res.matched is True
    assert res.severity == Severity.HIGH

    # Login with MFA (should NOT match)
    mfa_event = make_test_event(
        event_name="ConsoleLogin",
        mfa_auth=True,
        status="Success"
    )
    assert rule.evaluate(mfa_event) is None


def test_cloudtrail_logging_disabled_rule():
    """Verify detection of defense evasion via StopLogging or DeleteTrail."""
    rule = CloudTrailLoggingDisabledRule()

    stop_event = make_test_event(event_name="StopLogging", resource_name="main-trail")
    res = rule.evaluate(stop_event)
    assert res is not None
    assert res.matched is True
    assert res.mitre_attack.technique_id == "T1562.001"

    del_event = make_test_event(event_name="DeleteTrail", resource_name="audit-trail")
    assert rule.evaluate(del_event).matched is True


def test_detection_engine_end_to_end():
    """Verify DetectionEngine evaluates events and produces enriched SecurityFinding records."""
    engine = DetectionEngine()
    event = make_test_event(
        event_name="PutBucketAcl",
        resource_name="public-leaked-data",
        resource_type="s3:bucket",
        request_parameters={"x-amz-acl": "public-read"}
    )

    findings = engine.evaluate_event(event)
    assert len(findings) >= 1

    s3_finding = next(f for f in findings if f.rule_id == "RULE-S3-001")
    assert s3_finding.detection_type == DetectionType.RULE
    assert s3_finding.title == "S3 Bucket Made Public"
    assert s3_finding.affected_resource == "public-leaked-data"
    assert s3_finding.mitre_attack.technique_id == "T1530"
    assert s3_finding.cis_benchmark == "CIS AWS 2.1.5"
