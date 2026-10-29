"""Base definitions and interfaces for CloudGuard detection rules."""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field
from ingestion.models import CanonicalCloudEvent


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class MitreAttackRef(BaseModel):
    technique_id: str = Field(..., description="e.g. T1530, T1078")
    technique_name: str = Field(..., description="e.g. Data from Cloud Storage Object")
    tactic: str = Field(..., description="e.g. Exfiltration, Initial Access")
    url: Optional[str] = None


class RuleEvaluationResult(BaseModel):
    matched: bool
    rule_id: str
    rule_name: str
    severity: Severity
    description: str
    mitre_attack: Optional[MitreAttackRef] = None
    cis_benchmark: Optional[str] = None
    affected_resource: str
    remediation_suggestion: str
    event_context: Dict[str, Any] = Field(default_factory=dict)


class BaseRule(ABC):
    """Abstract base class for all CloudGuard detection rules."""

    id: str
    name: str
    severity: Severity
    description: str
    mitre_attack: Optional[MitreAttackRef] = None
    cis_benchmark: Optional[str] = None
    remediation_suggestion: str

    @abstractmethod
    def evaluate(self, event: CanonicalCloudEvent) -> Optional[RuleEvaluationResult]:
        """Evaluates a normalized event. Returns RuleEvaluationResult if matched, None otherwise."""
        pass
