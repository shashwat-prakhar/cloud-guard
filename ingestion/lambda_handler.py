"""AWS Lambda handler for processing S3 / EventBridge CloudTrail batches."""

import json
import logging
from typing import Any, Dict
from ingestion.pipeline import IngestionPipeline

logger = logging.getLogger("cloudguard.lambda")
pipeline = IngestionPipeline()


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entrypoint triggered by AWS CloudWatch, EventBridge, or S3 notifications."""
    records = []

    # Handle direct EventBridge CloudTrail event
    if "detail" in event and isinstance(event["detail"], dict):
        records.append(event["detail"])

    # Handle batch Records list (e.g. SQS or Kinesis)
    elif "Records" in event and isinstance(event["Records"], list):
        for rec in event["Records"]:
            if "body" in rec:
                try:
                    records.append(json.loads(rec["body"]))
                except Exception:
                    pass
            elif "s3" in rec:
                # S3 event notification placeholder
                records.append(rec)
            else:
                records.append(rec)
    else:
        records.append(event)

    processed_events = pipeline.process_batch(records)
    logger.info(f"Ingested {len(processed_events)} canonical events")

    return {
        "statusCode": 200,
        "processed_count": len(processed_events),
        "events": [e.model_dump(mode="json") for e in processed_events],
    }
