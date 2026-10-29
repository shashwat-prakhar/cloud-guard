"""Unified Canonical Event Schema for CloudGuard.

Normalizes event feeds from AWS CloudTrail, VPC Flow Logs, and AWS Config
(and extensible to Azure Activity Logs / GCP Audit Logs) into a single,
strongly-typed data structure for the detection engine.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field


class EventSourceType(str, Enum):
    CLOUDTRAIL = "aws.cloudtrail"
    VPC_FLOW = "aws.vpc_flow"
    AWS_CONFIG = "aws.config"
    AZURE_ACTIVITY = "azure.activity"
    GCP_AUDIT = "gcp.audit"
    CUSTOM = "custom.security_event"


class Actor(BaseModel):
    """The identity/principal that triggered the event."""
    principal_id: str = Field(..., description="Unique principal identifier (e.g. user ID, role ID)")
    arn: Optional[str] = Field(None, description="AWS ARN or cloud resource identity")
    account_id: str = Field("000000000000", description="Cloud Account/Subscription ID")
    user_type: str = Field("IAMUser", description="IAMUser, Root, AssumedRole, FederatedUser, etc.")
    user_name: Optional[str] = Field(None, description="Human or service user name")
    mfa_authenticated: bool = Field(False, description="Whether MFA was used during authentication")


class ResourceTarget(BaseModel):
    """The target cloud resource affected by the event."""
    arn: Optional[str] = Field(None, description="Target resource ARN if available")
    name: str = Field(..., description="Resource name or ID (e.g., bucket-name, sg-0123abc)")
    resource_type: str = Field(..., description="Resource type (e.g., s3:bucket, ec2:security-group)")
    region: str = Field("us-east-1", description="AWS/Cloud region")
    tags: Dict[str, str] = Field(default_factory=dict, description="Resource tags")


class CanonicalCloudEvent(BaseModel):
    """Unified security event data model across all cloud providers and log sources."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_source: EventSourceType = Field(..., description="Source log stream")
    event_name: str = Field(..., description="API action or network verb (e.g., PutBucketAcl, REJECT)")
    actor: Actor
    resource: ResourceTarget
    source_ip: str = Field("0.0.0.0", description="Originating client IP address")
    user_agent: Optional[str] = Field(None, description="Client User-Agent string")
    region: str = Field("us-east-1", description="Cloud region")
    status: str = Field("Success", description="Success, Failure, Denied, or Accept/Reject")
    request_parameters: Dict[str, Any] = Field(default_factory=dict, description="API request parameters")
    response_elements: Dict[str, Any] = Field(default_factory=dict, description="API response elements")
    raw_event: Dict[str, Any] = Field(default_factory=dict, description="Original unparsed log record")

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
