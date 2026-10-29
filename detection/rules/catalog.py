"""Detection rules catalog for CloudGuard.

Implements 18 CIS Benchmark & MITRE ATT&CK mapped detection rules.
"""

from typing import Optional
from detection.rules.base import BaseRule, MitreAttackRef, RuleEvaluationResult, Severity
from ingestion.models import CanonicalCloudEvent


class S3BucketMadePublicRule(BaseRule):
    """Detects S3 bucket ACL or public access block modifications that expose data publicly."""
    id = "RULE-S3-001"
    name = "S3 Bucket Made Public"
    severity = Severity.CRITICAL
    description = "An S3 bucket public access block was deleted or bucket ACL was set to public-read/write."
    mitre_attack = MitreAttackRef(
        technique_id="T1530",
        technique_name="Data from Cloud Storage Object",
        tactic="Exfiltration",
        url="https://attack.mitre.org/techniques/T1530/"
    )
    cis_benchmark = "CIS AWS 2.1.5"
    remediation_suggestion = "Apply S3 Public Access Block configuration immediately to restrict public traffic."

    def evaluate(self, event: CanonicalCloudEvent) -> Optional[RuleEvaluationResult]:
        if event.event_name in ["PutBucketAcl", "PutBucketPolicy", "DeletePublicAccessBlock"]:
            req = event.request_parameters or {}
            # Check PutBucketAcl for public permissions
            acl_grant = str(req.get("AccessControlPolicy", "")).lower()
            acl_canned = str(req.get("x-amz-acl", "")).lower()
            if (
                event.event_name == "DeletePublicAccessBlock"
                or "allusers" in acl_grant
                or "authenticatedusers" in acl_grant
                or "public-read" in acl_canned
                or "public-read-write" in acl_canned
                or "AllowPublicAccess" in str(req)
            ):
                return RuleEvaluationResult(
                    matched=True,
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"Bucket '{event.resource.name}' was made publicly accessible by {event.actor.principal_id}.",
                    mitre_attack=self.mitre_attack,
                    cis_benchmark=self.cis_benchmark,
                    affected_resource=event.resource.name,
                    remediation_suggestion=self.remediation_suggestion,
                    event_context={"event_id": event.event_id, "actor": event.actor.model_dump(), "source_ip": event.source_ip},
                )
        return None


class S3EncryptionDisabledRule(BaseRule):
    """Detects deletion or disabling of default S3 bucket encryption."""
    id = "RULE-S3-002"
    name = "S3 Bucket Encryption Disabled"
    severity = Severity.HIGH
    description = "Default server-side encryption was removed or disabled on an S3 bucket."
    mitre_attack = MitreAttackRef(
        technique_id="T1485",
        technique_name="Data Destruction / Impair Defenses",
        tactic="Impact",
        url="https://attack.mitre.org/techniques/T1485/"
    )
    cis_benchmark = "CIS AWS 2.1.1"
    remediation_suggestion = "Re-enable default AES-256 or AWS KMS encryption on the S3 bucket."

    def evaluate(self, event: CanonicalCloudEvent) -> Optional[RuleEvaluationResult]:
        if event.event_name == "DeleteBucketEncryption":
            return RuleEvaluationResult(
                matched=True,
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                description=f"Encryption removed from S3 bucket '{event.resource.name}'.",
                mitre_attack=self.mitre_attack,
                cis_benchmark=self.cis_benchmark,
                affected_resource=event.resource.name,
                remediation_suggestion=self.remediation_suggestion,
                event_context={"event_id": event.event_id, "actor": event.actor.model_dump()},
            )
        return None


class SecurityGroupOpenPort22Rule(BaseRule):
    """Detects Security Group rules opening SSH (port 22) to the entire Internet."""
    id = "RULE-SG-001"
    name = "Security Group Opens SSH (Port 22) to 0.0.0.0/0"
    severity = Severity.HIGH
    description = "Inbound SSH port 22 access was granted to universal CIDR 0.0.0.0/0."
    mitre_attack = MitreAttackRef(
        technique_id="T1021.004",
        technique_name="Remote Services: SSH",
        tactic="Lateral Movement",
        url="https://attack.mitre.org/techniques/T1021/004/"
    )
    cis_benchmark = "CIS AWS 5.2"
    remediation_suggestion = "Revoke ingress rule allowing 0.0.0.0/0 on port 22 and restrict access to corporate VPN IP."

    def evaluate(self, event: CanonicalCloudEvent) -> Optional[RuleEvaluationResult]:
        if event.event_name in ["AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"]:
            req_str = str(event.request_parameters)
            if ("0.0.0.0/0" in req_str or "::/0" in req_str) and ("22" in req_str):
                return RuleEvaluationResult(
                    matched=True,
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"Security Group '{event.resource.name}' opened port 22 to 0.0.0.0/0.",
                    mitre_attack=self.mitre_attack,
                    cis_benchmark=self.cis_benchmark,
                    affected_resource=event.resource.name,
                    remediation_suggestion=self.remediation_suggestion,
                    event_context={"event_id": event.event_id, "parameters": event.request_parameters},
                )
        return None


class SecurityGroupOpenPort3389Rule(BaseRule):
    """Detects Security Group rules opening RDP (port 3389) to 0.0.0.0/0."""
    id = "RULE-SG-002"
    name = "Security Group Opens RDP (Port 3389) to 0.0.0.0/0"
    severity = Severity.HIGH
    description = "Inbound RDP port 3389 access was granted to universal CIDR 0.0.0.0/0."
    mitre_attack = MitreAttackRef(
        technique_id="T1021.001",
        technique_name="Remote Services: Remote Desktop Protocol",
        tactic="Lateral Movement",
        url="https://attack.mitre.org/techniques/T1021/001/"
    )
    cis_benchmark = "CIS AWS 5.3"
    remediation_suggestion = "Revoke ingress rule allowing 0.0.0.0/0 on port 3389 and limit to bastion hosts."

    def evaluate(self, event: CanonicalCloudEvent) -> Optional[RuleEvaluationResult]:
        if event.event_name in ["AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"]:
            req_str = str(event.request_parameters)
            if ("0.0.0.0/0" in req_str or "::/0" in req_str) and ("3389" in req_str):
                return RuleEvaluationResult(
                    matched=True,
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"Security Group '{event.resource.name}' opened RDP (port 3389) to 0.0.0.0/0.",
                    mitre_attack=self.mitre_attack,
                    cis_benchmark=self.cis_benchmark,
                    affected_resource=event.resource.name,
                    remediation_suggestion=self.remediation_suggestion,
                    event_context={"event_id": event.event_id, "parameters": event.request_parameters},
                )
        return None


class IAMRootAccountUsageRule(BaseRule):
    """Detects any usage of the AWS root account for interactive logins or API calls."""
    id = "RULE-IAM-001"
    name = "AWS Root Account Usage Detected"
    severity = Severity.CRITICAL
    description = "Root account credentials were used to perform cloud actions."
    mitre_attack = MitreAttackRef(
        technique_id="T1078.001",
        technique_name="Valid Accounts: Default Accounts",
        tactic="Initial Access / Privilege Escalation",
        url="https://attack.mitre.org/techniques/T1078/001/"
    )
    cis_benchmark = "CIS AWS 1.7"
    remediation_suggestion = "Lock root credentials, enforce hardware MFA, and delegate daily admin tasks to IAM Identity Center roles."

    def evaluate(self, event: CanonicalCloudEvent) -> Optional[RuleEvaluationResult]:
        if event.actor.user_type.lower() == "root":
            return RuleEvaluationResult(
                matched=True,
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                description=f"Root account executed '{event.event_name}' from IP {event.source_ip}.",
                mitre_attack=self.mitre_attack,
                cis_benchmark=self.cis_benchmark,
                affected_resource=f"RootAccount-{event.actor.account_id}",
                remediation_suggestion=self.remediation_suggestion,
                event_context={"event_id": event.event_id, "source_ip": event.source_ip},
            )
        return None


class IAMPolicyWildcardAdminRule(BaseRule):
    """Detects creation or attachment of policies granting wildcard (*:*) admin privileges."""
    id = "RULE-IAM-002"
    name = "Overly Permissive IAM Policy Attached (*:*)"
    severity = Severity.CRITICAL
    description = "An IAM policy granting full administrator privileges (Action: *, Resource: *) was created or attached."
    mitre_attack = MitreAttackRef(
        technique_id="T1098",
        technique_name="Account Manipulation",
        tactic="Persistence",
        url="https://attack.mitre.org/techniques/T1098/"
    )
    cis_benchmark = "CIS AWS 1.16"
    remediation_suggestion = "Detach full wildcard policy and implement principle of least privilege."

    def evaluate(self, event: CanonicalCloudEvent) -> Optional[RuleEvaluationResult]:
        if event.event_name in ["AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "CreatePolicy"]:
            req_str = str(event.request_parameters)
            if ("AdministratorAccess" in req_str) or ("'*'" in req_str and '"*"' in req_str) or ('"Action": "*"' in req_str):
                return RuleEvaluationResult(
                    matched=True,
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"Over-permissive wildcard policy granted by {event.actor.principal_id}.",
                    mitre_attack=self.mitre_attack,
                    cis_benchmark=self.cis_benchmark,
                    affected_resource=event.resource.name,
                    remediation_suggestion=self.remediation_suggestion,
                    event_context={"event_id": event.event_id, "parameters": event.request_parameters},
                )
        return None


class IAMUserWithoutMFARule(BaseRule):
    """Detects console logins or active sessions without Multi-Factor Authentication."""
    id = "RULE-IAM-003"
    name = "Console Login Without MFA"
    severity = Severity.HIGH
    description = "User logged into the AWS Management Console without providing MFA."
    mitre_attack = MitreAttackRef(
        technique_id="T1078.004",
        technique_name="Valid Accounts: Cloud Accounts",
        tactic="Initial Access",
        url="https://attack.mitre.org/techniques/T1078/004/"
    )
    cis_benchmark = "CIS AWS 1.5"
    remediation_suggestion = "Enforce MFA on user account and terminate non-MFA sessions."

    def evaluate(self, event: CanonicalCloudEvent) -> Optional[RuleEvaluationResult]:
        if event.event_name == "ConsoleLogin" and event.status == "Success":
            if not event.actor.mfa_authenticated:
                return RuleEvaluationResult(
                    matched=True,
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"User '{event.actor.principal_id}' logged in without MFA.",
                    mitre_attack=self.mitre_attack,
                    cis_benchmark=self.cis_benchmark,
                    affected_resource=event.actor.principal_id,
                    remediation_suggestion=self.remediation_suggestion,
                    event_context={"event_id": event.event_id, "source_ip": event.source_ip},
                )
        return None


class CloudTrailLoggingDisabledRule(BaseRule):
    """Detects disabling or deletion of CloudTrail trails (classic defense evasion)."""
    id = "RULE-CT-001"
    name = "CloudTrail Logging Disabled or Deleted"
    severity = Severity.CRITICAL
    description = "CloudTrail logging was stopped or the trail configuration was deleted."
    mitre_attack = MitreAttackRef(
        technique_id="T1562.001",
        technique_name="Impair Defenses: Disable Cloud Logs",
        tactic="Defense Evasion",
        url="https://attack.mitre.org/techniques/T1562/001/"
    )
    cis_benchmark = "CIS AWS 3.1"
    remediation_suggestion = "Start CloudTrail logging immediately and investigate the invoking identity."

    def evaluate(self, event: CanonicalCloudEvent) -> Optional[RuleEvaluationResult]:
        if event.event_name in ["StopLogging", "DeleteTrail"]:
            return RuleEvaluationResult(
                matched=True,
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                description=f"CloudTrail logging was disabled via '{event.event_name}' by {event.actor.principal_id}.",
                mitre_attack=self.mitre_attack,
                cis_benchmark=self.cis_benchmark,
                affected_resource=event.resource.name,
                remediation_suggestion=self.remediation_suggestion,
                event_context={"event_id": event.event_id, "actor": event.actor.model_dump()},
            )
        return None


class EBSUnencryptedVolumeRule(BaseRule):
    """Detects creation of unencrypted Elastic Block Store (EBS) volumes."""
    id = "RULE-EBS-001"
    name = "Unencrypted EBS Volume Created"
    severity = Severity.MEDIUM
    description = "An EBS storage volume was provisioned without default KMS encryption."
    mitre_attack = MitreAttackRef(
        technique_id="T1486",
        technique_name="Data Encrypted for Impact",
        tactic="Impact",
        url="https://attack.mitre.org/techniques/T1486/"
    )
    cis_benchmark = "CIS AWS 2.2.1"
    remediation_suggestion = "Enable account-level default EBS encryption and snapshot volume to encrypted copy."

    def evaluate(self, event: CanonicalCloudEvent) -> Optional[RuleEvaluationResult]:
        if event.event_name == "CreateVolume":
            encrypted = event.request_parameters.get("encrypted")
            if encrypted is False or str(encrypted).lower() == "false":
                return RuleEvaluationResult(
                    matched=True,
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"Volume '{event.resource.name}' created without encryption.",
                    mitre_attack=self.mitre_attack,
                    cis_benchmark=self.cis_benchmark,
                    affected_resource=event.resource.name,
                    remediation_suggestion=self.remediation_suggestion,
                    event_context={"event_id": event.event_id},
                )
        return None


class RDSPublicSnapshotRule(BaseRule):
    """Detects making an RDS database snapshot publicly restorable."""
    id = "RULE-RDS-001"
    name = "RDS Database Snapshot Shared Publicly"
    severity = Severity.CRITICAL
    description = "An Amazon RDS snapshot attribute was altered to grant public restore permissions ('all')."
    mitre_attack = MitreAttackRef(
        technique_id="T1530",
        technique_name="Data from Cloud Storage Object",
        tactic="Exfiltration",
        url="https://attack.mitre.org/techniques/T1530/"
    )
    cis_benchmark = "CIS AWS 2.3.1"
    remediation_suggestion = "Revoke public access attribute from RDS snapshot immediately."

    def evaluate(self, event: CanonicalCloudEvent) -> Optional[RuleEvaluationResult]:
        if event.event_name in ["ModifyDBSnapshotAttribute", "ModifyDBClusterSnapshotAttribute"]:
            req_str = str(event.request_parameters)
            if "valuesToAdd" in req_str and "all" in req_str.lower():
                return RuleEvaluationResult(
                    matched=True,
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"RDS snapshot '{event.resource.name}' was made publicly accessible.",
                    mitre_attack=self.mitre_attack,
                    cis_benchmark=self.cis_benchmark,
                    affected_resource=event.resource.name,
                    remediation_suggestion=self.remediation_suggestion,
                    event_context={"event_id": event.event_id},
                )
        return None


class ConsoleLoginUnusualGeoRule(BaseRule):
    """Detects console logins originating from flagged or high-risk geographical regions."""
    id = "RULE-GEO-001"
    name = "Console Login From Flagged Geolocation"
    severity = Severity.HIGH
    description = "Console login authenticated from an anomalous or untrusted geographic IP block."
    mitre_attack = MitreAttackRef(
        technique_id="T1078",
        technique_name="Valid Accounts",
        tactic="Initial Access",
        url="https://attack.mitre.org/techniques/T1078/"
    )
    cis_benchmark = "CIS AWS 1.3"
    remediation_suggestion = "Verify user travel logs, trigger password reset, and revoke active STS sessions."

    def evaluate(self, event: CanonicalCloudEvent) -> Optional[RuleEvaluationResult]:
        if event.event_name == "ConsoleLogin" and event.status == "Success":
            flagged_ips = ["185.220.", "194.26.", "45.154.", "91.240."]
            if any(event.source_ip.startswith(prefix) for prefix in flagged_ips):
                return RuleEvaluationResult(
                    matched=True,
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"Suspicious console login from IP {event.source_ip} for user {event.actor.principal_id}.",
                    mitre_attack=self.mitre_attack,
                    cis_benchmark=self.cis_benchmark,
                    affected_resource=event.actor.principal_id,
                    remediation_suggestion=self.remediation_suggestion,
                    event_context={"source_ip": event.source_ip, "actor": event.actor.model_dump()},
                )
        return None


class VpcFlowLogsDisabledRule(BaseRule):
    """Detects deletion of VPC flow logs."""
    id = "RULE-NET-001"
    name = "VPC Flow Logs Disabled"
    severity = Severity.HIGH
    description = "Flow logs for a VPC or network interface were deleted."
    mitre_attack = MitreAttackRef(
        technique_id="T1562.001",
        technique_name="Impair Defenses: Disable Cloud Logs",
        tactic="Defense Evasion",
        url="https://attack.mitre.org/techniques/T1562/001/"
    )
    cis_benchmark = "CIS AWS 3.9"
    remediation_suggestion = "Re-enable VPC Flow Logs forwarding to CloudWatch/S3."

    def evaluate(self, event: CanonicalCloudEvent) -> Optional[RuleEvaluationResult]:
        if event.event_name == "DeleteFlowLogs":
            return RuleEvaluationResult(
                matched=True,
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                description=f"VPC Flow Logs deleted by {event.actor.principal_id}.",
                mitre_attack=self.mitre_attack,
                cis_benchmark=self.cis_benchmark,
                affected_resource=event.resource.name,
                remediation_suggestion=self.remediation_suggestion,
                event_context={"event_id": event.event_id},
            )
        return None


class CloudWatchAlarmDeletedRule(BaseRule):
    """Detects deletion of security monitoring CloudWatch alarms."""
    id = "RULE-CW-001"
    name = "Security CloudWatch Alarm Deleted"
    severity = Severity.MEDIUM
    description = "A CloudWatch alarm monitoring security metrics was deleted."
    mitre_attack = MitreAttackRef(
        technique_id="T1562.001",
        technique_name="Impair Defenses",
        tactic="Defense Evasion",
        url="https://attack.mitre.org/techniques/T1562/001/"
    )
    cis_benchmark = "CIS AWS 3.14"
    remediation_suggestion = "Restore deleted CloudWatch metric alarms."

    def evaluate(self, event: CanonicalCloudEvent) -> Optional[RuleEvaluationResult]:
        if event.event_name == "DeleteAlarms":
            return RuleEvaluationResult(
                matched=True,
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                description=f"CloudWatch alarms deleted by {event.actor.principal_id}.",
                mitre_attack=self.mitre_attack,
                cis_benchmark=self.cis_benchmark,
                affected_resource=event.resource.name,
                remediation_suggestion=self.remediation_suggestion,
                event_context={"event_id": event.event_id},
            )
        return None


class KmsKeyScheduledDeletionRule(BaseRule):
    """Detects scheduling deletion of a KMS customer master key."""
    id = "RULE-KMS-001"
    name = "KMS Customer Key Scheduled for Deletion"
    severity = Severity.HIGH
    description = "A cryptographic KMS key was scheduled for permanent deletion."
    mitre_attack = MitreAttackRef(
        technique_id="T1485",
        technique_name="Data Destruction",
        tactic="Impact",
        url="https://attack.mitre.org/techniques/T1485/"
    )
    cis_benchmark = "CIS AWS 3.7"
    remediation_suggestion = "Cancel KMS key deletion before the waiting period expires."

    def evaluate(self, event: CanonicalCloudEvent) -> Optional[RuleEvaluationResult]:
        if event.event_name == "ScheduleKeyDeletion":
            return RuleEvaluationResult(
                matched=True,
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                description=f"KMS Key '{event.resource.name}' scheduled for deletion by {event.actor.principal_id}.",
                mitre_attack=self.mitre_attack,
                cis_benchmark=self.cis_benchmark,
                affected_resource=event.resource.name,
                remediation_suggestion=self.remediation_suggestion,
                event_context={"event_id": event.event_id},
            )
        return None


class Ec2ImdsV1EnabledRule(BaseRule):
    """Detects launching or modifying an EC2 instance with legacy IMDSv1 enabled."""
    id = "RULE-EC2-001"
    name = "EC2 Instance Permitting IMDSv1 (SSRF Risk)"
    severity = Severity.MEDIUM
    description = "EC2 instance launched without enforcing IMDSv2 token requirement, vulnerable to SSRF credential theft."
    mitre_attack = MitreAttackRef(
        technique_id="T1552.005",
        technique_name="Cloud Instance Metadata API",
        tactic="Credential Access",
        url="https://attack.mitre.org/techniques/T1552/005/"
    )
    cis_benchmark = "CIS AWS 5.4"
    remediation_suggestion = "Enforce HttpTokens=required (IMDSv2) on instance metadata options."

    def evaluate(self, event: CanonicalCloudEvent) -> Optional[RuleEvaluationResult]:
        if event.event_name in ["RunInstances", "ModifyInstanceMetadataOptions"]:
            req_str = str(event.request_parameters)
            if "HttpTokens" in req_str and "optional" in req_str:
                return RuleEvaluationResult(
                    matched=True,
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"EC2 Instance '{event.resource.name}' allows unauthenticated IMDSv1 calls.",
                    mitre_attack=self.mitre_attack,
                    cis_benchmark=self.cis_benchmark,
                    affected_resource=event.resource.name,
                    remediation_suggestion=self.remediation_suggestion,
                    event_context={"event_id": event.event_id},
                )
        return None


class S3MassDeleteRansomwareRule(BaseRule):
    """Detects rapid mass deletion of objects in an S3 bucket (potential cloud ransomware)."""
    id = "RULE-S3-003"
    name = "Anomalous S3 Mass Object Deletion"
    severity = Severity.CRITICAL
    description = "Batch DeleteObjects API invoked with bulk deletion list, potential ransomware or data wiper activity."
    mitre_attack = MitreAttackRef(
        technique_id="T1485",
        technique_name="Data Destruction",
        tactic="Impact",
        url="https://attack.mitre.org/techniques/T1485/"
    )
    cis_benchmark = "CIS AWS 2.1.3"
    remediation_suggestion = "Quarantine calling credentials and inspect S3 bucket object versioning status."

    def evaluate(self, event: CanonicalCloudEvent) -> Optional[RuleEvaluationResult]:
        if event.event_name == "DeleteObjects":
            req = event.request_parameters or {}
            delete_payload = req.get("Delete")
            delete_list = delete_payload.get("Object", []) if isinstance(delete_payload, dict) else []
            if isinstance(delete_list, list) and len(delete_list) >= 5:
                return RuleEvaluationResult(
                    matched=True,
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"Mass deletion of {len(delete_list)} objects in bucket '{event.resource.name}' by {event.actor.principal_id}.",
                    mitre_attack=self.mitre_attack,
                    cis_benchmark=self.cis_benchmark,
                    affected_resource=event.resource.name,
                    remediation_suggestion=self.remediation_suggestion,
                    event_context={"object_count": len(delete_list), "actor": event.actor.model_dump()},
                )
        return None


class IAMAccessKeyOld90DaysRule(BaseRule):
    """Detects active access keys created >90 days ago."""
    id = "RULE-IAM-004"
    name = "IAM Access Key Older Than 90 Days"
    severity = Severity.LOW
    description = "IAM user access key has not been rotated within the recommended 90-day window."
    mitre_attack = MitreAttackRef(
        technique_id="T1078.004",
        technique_name="Valid Accounts: Cloud Accounts",
        tactic="Persistence",
        url="https://attack.mitre.org/techniques/T1078/004/"
    )
    cis_benchmark = "CIS AWS 1.14"
    remediation_suggestion = "Rotate the active IAM access key and deactivate the legacy key."

    def evaluate(self, event: CanonicalCloudEvent) -> Optional[RuleEvaluationResult]:
        if event.event_name in ["GetAccessKeyLastUsed", "ListAccessKeys"]:
            req = event.request_parameters or {}
            if req.get("keyAgeDays", 0) > 90:
                return RuleEvaluationResult(
                    matched=True,
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"Access key for user '{event.actor.principal_id}' is older than 90 days ({req.get('keyAgeDays')} days).",
                    mitre_attack=self.mitre_attack,
                    cis_benchmark=self.cis_benchmark,
                    affected_resource=event.actor.principal_id,
                    remediation_suggestion=self.remediation_suggestion,
                    event_context={"key_age_days": req.get("keyAgeDays")},
                )
        return None


class IAMPasswordPolicyWeakRule(BaseRule):
    """Detects weakening of account password policy."""
    id = "RULE-IAM-005"
    name = "IAM Account Password Policy Weakened"
    severity = Severity.MEDIUM
    description = "IAM password policy was modified to reduce minimum length or disable symbol/number requirements."
    mitre_attack = MitreAttackRef(
        technique_id="T1078",
        technique_name="Valid Accounts",
        tactic="Defense Evasion",
        url="https://attack.mitre.org/techniques/T1078/"
    )
    cis_benchmark = "CIS AWS 1.8"
    remediation_suggestion = "Restore strong password requirements (min length 14, uppercase, lowercase, numbers, symbols)."

    def evaluate(self, event: CanonicalCloudEvent) -> Optional[RuleEvaluationResult]:
        if event.event_name == "UpdateAccountPasswordPolicy":
            req = event.request_parameters or {}
            min_length = req.get("minimumPasswordLength", 14)
            if min_length < 14:
                return RuleEvaluationResult(
                    matched=True,
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    description=f"IAM password policy minimum length reduced to {min_length}.",
                    mitre_attack=self.mitre_attack,
                    cis_benchmark=self.cis_benchmark,
                    affected_resource="IAMPasswordPolicy",
                    remediation_suggestion=self.remediation_suggestion,
                    event_context={"min_length": min_length},
                )
        return None


def get_default_rules():
    """Returns an instantiated list of all 18 detection rules."""
    return [
        S3BucketMadePublicRule(),
        S3EncryptionDisabledRule(),
        SecurityGroupOpenPort22Rule(),
        SecurityGroupOpenPort3389Rule(),
        IAMRootAccountUsageRule(),
        IAMPolicyWildcardAdminRule(),
        IAMUserWithoutMFARule(),
        CloudTrailLoggingDisabledRule(),
        EBSUnencryptedVolumeRule(),
        RDSPublicSnapshotRule(),
        ConsoleLoginUnusualGeoRule(),
        VpcFlowLogsDisabledRule(),
        CloudWatchAlarmDeletedRule(),
        KmsKeyScheduledDeletionRule(),
        Ec2ImdsV1EnabledRule(),
        S3MassDeleteRansomwareRule(),
        IAMAccessKeyOld90DaysRule(),
        IAMPasswordPolicyWeakRule(),
    ]
