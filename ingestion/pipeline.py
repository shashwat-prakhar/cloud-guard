"""Stream and batch ingestion pipeline for CloudGuard."""

import logging
from typing import Any, Dict, List, Optional
from ingestion.models import CanonicalCloudEvent
from ingestion.normalizers import (
    AwsConfigNormalizer,
    BaseNormalizer,
    CloudTrailNormalizer,
    VpcFlowLogNormalizer,
)

logger = logging.getLogger("cloudguard.ingestion")


class IngestionPipeline:
    """Coordinates parsing, normalizing, and routing of security logs."""

    def __init__(self, normalizers: Optional[List[BaseNormalizer]] = None):
        self.normalizers: List[BaseNormalizer] = normalizers or [
            CloudTrailNormalizer(),
            VpcFlowLogNormalizer(),
            AwsConfigNormalizer(),
        ]
        self._processed_count = 0
        self._error_count = 0

    def register_normalizer(self, normalizer: BaseNormalizer) -> None:
        """Add an additional log normalizer (e.g. for GCP or Azure)."""
        self.normalizers.append(normalizer)

    def process_record(self, raw_record: Dict[str, Any]) -> Optional[CanonicalCloudEvent]:
        """Normalize a single raw record."""
        for normalizer in self.normalizers:
            if normalizer.can_handle(raw_record):
                try:
                    event = normalizer.normalize(raw_record)
                    self._processed_count += 1
                    return event
                except Exception as e:
                    self._error_count += 1
                    logger.error(f"Failed to normalize record: {e}", exc_info=True)
                    return None

        logger.warning("No suitable normalizer found for raw record")
        self._error_count += 1
        return None

    def process_batch(self, raw_records: List[Dict[str, Any]]) -> List[CanonicalCloudEvent]:
        """Normalize a batch of raw records."""
        events: List[CanonicalCloudEvent] = []
        for record in raw_records:
            normalized = self.process_record(record)
            if normalized:
                events.append(normalized)
        return events

    @property
    def stats(self) -> Dict[str, int]:
        return {
            "processed_count": self._processed_count,
            "error_count": self._error_count,
        }
