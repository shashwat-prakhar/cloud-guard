"""Dual-layer detection engine coordinating rule matching and ML anomaly detection."""

from datetime import datetime, timezone
from enum import Enum
import logging
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field

from detection.ml.anomaly_detector import IsolationForestAnomalyDetector
from detection.ml.feature_extractor import FeatureExtractor
from detection.rules.base import BaseRule, MitreAttackRef, Severity
from detection.rules.catalog import get_default_rules
from ingestion.models import CanonicalCloudEvent

logger = logging.getLogger("cloudguard.detection")


class DetectionType(str, Enum):
    RULE = "RULE_BASED"
    ANOMALY = "ML_ANOMALY"


class SecurityFinding(BaseModel):
    """Enriched security finding ready for LLM explanation and remediation triage."""
    finding_id: str = Field(default_factory=lambda: f"FIND-{uuid.uuid4().hex[:8].upper()}")
    detection_type: DetectionType
    rule_id: Optional[str] = None
    title: str
    severity: Severity
    description: str
    mitre_attack: Optional[MitreAttackRef] = None
    cis_benchmark: Optional[str] = None
    affected_resource: str
    resource_type: str
    actor_principal: str
    source_ip: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_event: Dict[str, Any] = Field(default_factory=dict)
    remediation_hint: str
    anomaly_score: Optional[float] = None


class DetectionEngine:
    """Evaluates incoming canonical events against both signature rules and ML models."""

    def __init__(self, rules: Optional[List[BaseRule]] = None):
        self.rules = rules or get_default_rules()
        self.feature_extractor = FeatureExtractor()
        self.ml_detector = IsolationForestAnomalyDetector()

    def evaluate_event(self, event: CanonicalCloudEvent) -> List[SecurityFinding]:
        """Runs the two detection layers against a single event."""
        findings: List[SecurityFinding] = []

        # Layer 1: Rule-Based Evaluation
        for rule in self.rules:
            try:
                res = rule.evaluate(event)
                if res and res.matched:
                    finding = SecurityFinding(
                        detection_type=DetectionType.RULE,
                        rule_id=res.rule_id,
                        title=res.rule_name,
                        severity=res.severity,
                        description=res.description,
                        mitre_attack=res.mitre_attack,
                        cis_benchmark=res.cis_benchmark,
                        affected_resource=res.affected_resource,
                        resource_type=event.resource.resource_type,
                        actor_principal=event.actor.principal_id,
                        source_ip=event.source_ip,
                        timestamp=event.timestamp,
                        raw_event=event.raw_event,
                        remediation_hint=res.remediation_suggestion,
                    )
                    findings.append(finding)
            except Exception as e:
                logger.error(f"Rule {rule.id} failed during evaluation: {e}", exc_info=True)

        # Layer 2: ML Behavioral Anomaly Detection
        try:
            feat = self.feature_extractor.extract_features_from_event(event)
            is_anomaly, score = self.ml_detector.predict(feat)
            if is_anomaly:
                ml_finding = SecurityFinding(
                    detection_type=DetectionType.ANOMALY,
                    rule_id="ML-ANOMALY-001",
                    title="Behavioral Anomaly: Uncharacteristic Cloud API Pattern",
                    severity=Severity.HIGH if score > 0.75 else Severity.MEDIUM,
                    description=(
                        f"Principal '{event.actor.principal_id}' demonstrated anomalous API burst or "
                        f"off-hours access patterns (anomaly score: {score:.2f})."
                    ),
                    mitre_attack=MitreAttackRef(
                        technique_id="T1078.004",
                        technique_name="Compromised Cloud Credentials",
                        tactic="Initial Access",
                        url="https://attack.mitre.org/techniques/T1078/004/",
                    ),
                    cis_benchmark=None,
                    affected_resource=event.actor.principal_id,
                    resource_type=event.resource.resource_type,
                    actor_principal=event.actor.principal_id,
                    source_ip=event.source_ip,
                    timestamp=event.timestamp,
                    raw_event=event.raw_event,
                    remediation_hint="Audit recent STS sessions and consider temporarily revoking active credentials.",
                    anomaly_score=round(score, 3),
                )
                findings.append(ml_finding)
        except Exception as e:
            logger.error(f"ML Anomaly detection failed: {e}", exc_info=True)

        return findings
