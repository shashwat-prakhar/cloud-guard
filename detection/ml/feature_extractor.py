"""Feature engineering for ML-based behavioral anomaly detection."""

from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List
import numpy as np
from ingestion.models import CanonicalCloudEvent


class FeatureExtractor:
    """Extracts numerical feature vectors from sequences of canonical cloud events."""

    def __init__(self):
        # Rolling state per principal
        self.user_history = defaultdict(lambda: {
            "timestamps": [],
            "services": set(),
            "failed_calls": 0,
            "total_calls": 0,
            "bytes_transferred": 0,
        })

    def extract_features_from_event(self, event: CanonicalCloudEvent) -> np.ndarray:
        """Extract a real-time behavioral feature vector for an incoming event.

        Vector Schema:
        [0]: api_calls_per_hour (user frequency)
        [1]: distinct_services_count (lateral spread)
        [2]: event_hour (time of day 0-23)
        [3]: is_off_hours (1 if between 01:00 and 05:00 UTC, else 0)
        [4]: failed_call_ratio (error rate 0.0 - 1.0)
        [5]: high_privilege_service_flag (1 if IAM/STS/KMS, else 0)
        """
        user_key = event.actor.principal_id
        hist = self.user_history[user_key]

        hist["timestamps"].append(event.timestamp)
        # Parse service prefix (e.g. s3 from s3:bucket or PutBucketAcl)
        svc = event.resource.resource_type.split(":")[0] if ":" in event.resource.resource_type else "generic"
        hist["services"].add(svc)
        hist["total_calls"] += 1
        if event.status in ["Failure", "Denied", "Client.UnauthorizedOperation"]:
            hist["failed_calls"] += 1

        hour = event.timestamp.hour
        is_off_hours = 1.0 if (1 <= hour <= 5) else 0.0

        # Estimate calls in the last 60 minutes
        recent_cutoff = event.timestamp.timestamp() - 3600
        recent_calls = sum(1 for ts in hist["timestamps"] if ts.timestamp() >= recent_cutoff)

        failed_ratio = (hist["failed_calls"] / hist["total_calls"]) if hist["total_calls"] > 0 else 0.0
        high_priv = 1.0 if svc in ["iam", "sts", "kms", "guardduty"] else 0.0

        return np.array([
            float(recent_calls),
            float(len(hist["services"])),
            float(hour),
            is_off_hours,
            failed_ratio,
            high_priv,
        ], dtype=np.float32)

    def extract_batch(self, events: List[CanonicalCloudEvent]) -> np.ndarray:
        """Extract a matrix of feature vectors from a list of events."""
        matrix = []
        for e in events:
            matrix.append(self.extract_features_from_event(e))
        return np.array(matrix, dtype=np.float32)
