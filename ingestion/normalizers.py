"""Normalizers for heterogeneous cloud audit events.

Converts vendor-specific formats into the CanonicalCloudEvent schema.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid
from dateutil import parser as date_parser

from ingestion.models import Actor, CanonicalCloudEvent, EventSourceType, ResourceTarget


class BaseNormalizer(ABC):
    """Abstract interface for multi-cloud event normalizers."""

    @abstractmethod
    def can_handle(self, raw_record: Dict[str, Any]) -> bool:
        """Determines if this normalizer can process the given raw record."""
        pass

    @abstractmethod
    def normalize(self, raw_record: Dict[str, Any]) -> CanonicalCloudEvent:
        """Transforms the raw record into a CanonicalCloudEvent."""
        pass


class CloudTrailNormalizer(BaseNormalizer):
    """Parses and normalizes AWS CloudTrail JSON events."""

    def can_handle(self, raw_record: Dict[str, Any]) -> bool:
        return "eventSource" in raw_record or "eventName" in raw_record or "userIdentity" in raw_record

    def normalize(self, raw_record: Dict[str, Any]) -> CanonicalCloudEvent:
        # Extract actor identity
        user_identity = raw_record.get("userIdentity") or {}
        principal_id = user_identity.get("principalId", "unknown")
        user_name = user_identity.get("userName")
        user_type = user_identity.get("type", "IAMUser")
        arn = user_identity.get("arn")
        account_id = user_identity.get("accountId", raw_record.get("recipientAccountId", "000000000000"))

        session_context = user_identity.get("sessionContext") or {}
        attributes = session_context.get("attributes") or {}
        mfa_auth = attributes.get("mfaAuthenticated", "false")
        mfa_bool = True if str(mfa_auth).lower() == "true" else False

        actor = Actor(
            principal_id=principal_id,
            arn=arn,
            account_id=account_id,
            user_type=user_type,
            user_name=user_name,
            mfa_authenticated=mfa_bool,
        )

        # Extract target resource
        resources = raw_record.get("resources", [])
        res_name = "unknown"
        res_arn = None
        res_type = "aws:resource"

        if resources and isinstance(resources, list) and len(resources) > 0:
            first_res = resources[0]
            if isinstance(first_res, dict):
                res_arn = first_res.get("ARN")
                res_type = first_res.get("type", "aws:resource")
                res_name = res_arn.split(":")[-1] if res_arn else first_res.get("accountId", "unknown")
        else:
            # Fallback to requestParameters inspection
            req_params = raw_record.get("requestParameters") or {}
            if "bucketName" in req_params:
                res_name = req_params["bucketName"]
                res_type = "s3:bucket"
                res_arn = f"arn:aws:s3:::{res_name}"
            elif "groupId" in req_params:
                res_name = req_params["groupId"]
                res_type = "ec2:security-group"
            elif "userName" in req_params:
                res_name = req_params["userName"]
                res_type = "iam:user"
            elif "policyArn" in req_params:
                res_arn = req_params["policyArn"]
                res_name = res_arn.split("/")[-1]
                res_type = "iam:policy"
            elif "instanceId" in req_params:
                res_name = req_params["instanceId"]
                res_type = "ec2:instance"

        region = raw_record.get("awsRegion", "us-east-1")
        resource = ResourceTarget(
            arn=res_arn,
            name=res_name,
            resource_type=res_type,
            region=region,
        )

        # Parse timestamp
        raw_ts = raw_record.get("eventTime")
        if raw_ts:
            try:
                ts = date_parser.parse(raw_ts)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except Exception:
                ts = datetime.now(timezone.utc)
        else:
            ts = datetime.now(timezone.utc)

        error_code = raw_record.get("errorCode")
        status = "Failure" if error_code else "Success"

        return CanonicalCloudEvent(
            event_id=raw_record.get("eventID", str(uuid.uuid4())),
            timestamp=ts,
            event_source=EventSourceType.CLOUDTRAIL,
            event_name=raw_record.get("eventName", "UnknownAPI"),
            actor=actor,
            resource=resource,
            source_ip=raw_record.get("sourceIPAddress", "0.0.0.0"),
            user_agent=raw_record.get("userAgent"),
            region=region,
            status=status,
            request_parameters=raw_record.get("requestParameters") or {},
            response_elements=raw_record.get("responseElements") or {},
            raw_event=raw_record,
        )


class VpcFlowLogNormalizer(BaseNormalizer):
    """Parses AWS VPC Flow Logs (e.g. from CloudWatch or S3)."""

    def can_handle(self, raw_record: Dict[str, Any]) -> bool:
        return "action" in raw_record and ("srcaddr" in raw_record or "source_ip" in raw_record)

    def normalize(self, raw_record: Dict[str, Any]) -> CanonicalCloudEvent:
        src_ip = raw_record.get("srcaddr", raw_record.get("source_ip", "0.0.0.0"))
        dst_port = raw_record.get("dstport", raw_record.get("dest_port", 0))
        action = raw_record.get("action", "ACCEPT")
        interface_id = raw_record.get("interface_id", "eni-00000000")

        actor = Actor(
            principal_id=src_ip,
            arn=None,
            account_id=str(raw_record.get("account_id", "000000000000")),
            user_type="NetworkClient",
            user_name=f"IP-{src_ip}",
        )

        resource = ResourceTarget(
            name=str(interface_id),
            resource_type="ec2:network-interface",
            region=raw_record.get("region", "us-east-1"),
        )

        return CanonicalCloudEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            event_source=EventSourceType.VPC_FLOW,
            event_name=f"VPC_FLOW_{action}",
            actor=actor,
            resource=resource,
            source_ip=src_ip,
            region=raw_record.get("region", "us-east-1"),
            status=action,
            request_parameters={"dst_port": dst_port, "protocol": raw_record.get("protocol", "6")},
            response_elements={},
            raw_event=raw_record,
        )


class AwsConfigNormalizer(BaseNormalizer):
    """Parses AWS Config compliance status change notifications."""

    def can_handle(self, raw_record: Dict[str, Any]) -> bool:
        return "configRuleName" in raw_record or "complianceType" in raw_record

    def normalize(self, raw_record: Dict[str, Any]) -> CanonicalCloudEvent:
        res_id = raw_record.get("resourceId", "unknown-resource")
        res_type = raw_record.get("resourceType", "aws:config:resource")

        actor = Actor(
            principal_id="aws-config-service",
            account_id=raw_record.get("awsAccountId", "000000000000"),
            user_type="AWSService",
            user_name="AWSConfig",
        )

        resource = ResourceTarget(
            arn=raw_record.get("resourceArn"),
            name=res_id,
            resource_type=res_type,
            region=raw_record.get("awsRegion", "us-east-1"),
        )

        return CanonicalCloudEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            event_source=EventSourceType.AWS_CONFIG,
            event_name=raw_record.get("configRuleName", "ConfigRuleEvaluation"),
            actor=actor,
            resource=resource,
            source_ip="127.0.0.1",
            region=raw_record.get("awsRegion", "us-east-1"),
            status=raw_record.get("complianceType", "NON_COMPLIANT"),
            request_parameters=raw_record,
            raw_event=raw_record,
        )
