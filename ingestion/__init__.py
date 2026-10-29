"""CloudGuard Ingestion Pipeline

Normalizes heterogeneous cloud audit logs (AWS CloudTrail, VPC Flow Logs, AWS Config)
into a unified canonical security event schema.
"""

from ingestion.models import CanonicalCloudEvent, Actor, ResourceTarget, EventSourceType
from ingestion.normalizers import CloudTrailNormalizer, VpcFlowLogNormalizer, AwsConfigNormalizer
from ingestion.pipeline import IngestionPipeline

__all__ = [
    "CanonicalCloudEvent",
    "Actor",
    "ResourceTarget",
    "EventSourceType",
    "CloudTrailNormalizer",
    "VpcFlowLogNormalizer",
    "AwsConfigNormalizer",
    "IngestionPipeline",
]
