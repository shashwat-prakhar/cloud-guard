"""Pydantic schemas for LLM explanation generation and guardrail enforcement."""

from typing import List, Optional
from pydantic import BaseModel, Field


class LLMExplanationResult(BaseModel):
    """Structured security incident explanation with actionable remediation guidance."""
    summary: str = Field(..., description="Plain-English summary of what happened and who did it")
    severity_assessment: str = Field(..., description="CRITICAL, HIGH, MEDIUM, or LOW")
    business_risk: str = Field(..., description="Potential business, financial, or data impact")
    remediation_steps: List[str] = Field(..., description="Step-by-step remediation plan")
    aws_cli_fix: str = Field(..., description="AWS CLI command snippet to execute or verify")
    terraform_fix: str = Field(..., description="Terraform HCL snippet to enforce desired state in IaC")
    guardrail_notice: str = Field(
        default="Advisory output only. LLMs do not directly execute mutations; deterministic engines govern remediation.",
        description="Explicit architectural guardrail disclosure"
    )
