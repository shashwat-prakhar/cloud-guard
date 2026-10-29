# CloudGuard: AI-Powered Cloud Security Monitoring Platform (Local MVP)

CloudGuard is a cloud security monitoring platform designed to ingest multi-source cloud audit telemetry, normalize it into a unified canonical schema, detect threats using dual-layer signature rules and behavioral machine learning anomaly detection, and generate advisory incident explanations.

> **Status Notice (Local MVP)**: Automated remediation and live cloud mutation actions are explicitly **disabled** in this MVP. Telemetry analysis and explanation capabilities operate offline in local dry-run mode without modifying any live cloud resources.

---

## Architecture Overview

CloudGuard is organized into modular pipelines designed for high audit throughput and defense-in-depth:

```
[ Cloud Audit Logs ] (CloudTrail, VPC Flow, AWS Config)
         │
         ▼
[ Ingestion Pipeline ] ──► Normalizes to CanonicalCloudEvent schema
         │
         ▼
[ Dual-Layer Detection ]
   ├── Layer 1: 18 CIS Benchmark & MITRE ATT&CK Rule Engine
   └── Layer 2: Scikit-Learn Isolation Forest Anomaly Detection
         │
         ▼
[ Advisory Explanation Layer ] ──► Schema-validated structured incident report
                                   (Strictly advisory; no execution sinks)
```

---

## Currently Implemented Functionality

### 1. Canonical Ingestion Pipeline (`ingestion/`)
- **Unified Event Schema (`models.py`)**: Defines `CanonicalCloudEvent`, normalizing diverse cloud telemetry formats (AWS CloudTrail, VPC Flow Logs, AWS Config) into a strongly-typed schema (actor, target resource, action verb, timestamp, IP, parameters).
- **Format Normalizers (`normalizers.py`)**: Extensible parsers for:
  - `CloudTrailNormalizer`: Extracts principal identity, MFA status, action parameters, and resources.
  - `VpcFlowLogNormalizer`: Normalizes network layer flow records (source/dest IPs, ports, accept/reject status).
  - `AwsConfigNormalizer`: Ingests compliance change notifications.
- **Batch & Stream Processing (`pipeline.py`, `lambda_handler.py`)**: Stream ingestion engine and AWS Lambda-compatible entrypoint.

### 2. Dual-Layer Detection Engine (`detection/`)
- **Signature Detection Rules (`detection/rules/catalog.py`)**: 18 pre-built security rules mapped to MITRE ATT&CK techniques and CIS AWS Foundations Benchmarks:
  - S3 bucket made public or public access block deleted (`RULE-S3-001`, MITRE T1530, CIS 2.1.5)
  - S3 bucket default encryption removed (`RULE-S3-002`, MITRE T1485, CIS 2.1.1)
  - Security Group opening SSH port 22 to `0.0.0.0/0` (`RULE-SG-001`, MITRE T1021.004, CIS 5.2)
  - Security Group opening RDP port 3389 to `0.0.0.0/0` (`RULE-SG-002`, MITRE T1021.001, CIS 5.3)
  - AWS Root account usage detected (`RULE-IAM-001`, MITRE T1078.001, CIS 1.7)
  - Overly permissive wildcard policy (`*:*`) attached (`RULE-IAM-002`, MITRE T1098, CIS 1.16)
  - Console login without Multi-Factor Authentication (`RULE-IAM-003`, MITRE T1078.004, CIS 1.5)
  - CloudTrail logging stopped or trail deleted (`RULE-CT-001`, MITRE T1562.001, CIS 3.1)
  - Unencrypted EBS volume provisioned (`RULE-EBS-001`, MITRE T1486, CIS 2.2.1)
  - RDS snapshot made publicly accessible (`RULE-RDS-001`, MITRE T1530, CIS 2.3.1)
  - Console login originating from flagged geolocations (`RULE-GEO-001`, MITRE T1078, CIS 1.3)
  - VPC Flow Logs deleted (`RULE-NET-001`, MITRE T1562.001, CIS 3.9)
  - Security CloudWatch metric alarm deleted (`RULE-CW-001`, MITRE T1562.001, CIS 3.14)
  - KMS Customer Master Key scheduled for deletion (`RULE-KMS-001`, MITRE T1485, CIS 3.7)
  - EC2 instance permitting legacy IMDSv1 (`RULE-EC2-001`, MITRE T1552.005, CIS 5.4)
  - S3 mass object deletion ransomware pattern (`RULE-S3-003`, MITRE T1485, CIS 2.1.3)
  - IAM access key older than 90 days (`RULE-IAM-004`, MITRE T1078.004, CIS 1.14)
  - IAM account password policy weakened (`RULE-IAM-005`, MITRE T1078, CIS 1.8)
- **Machine Learning Anomaly Detection (`detection/ml/`)**:
  - `FeatureExtractor`: Extracts real-time behavioral vectors (call frequency, distinct services touched, off-hours execution, failed call ratio).
  - `IsolationForestAnomalyDetector`: Scikit-learn unsupervised Isolation Forest identifying credential compromise bursts and anomalous activity.
  - `SyntheticDataGenerator`: Generates synthetic baseline vs. attacker telemetry for training and evaluation metrics.

### 3. Advisory LLM Schema & Safety Guardrails (`llm/schemas.py`)
- **Strict Advisory Schema (`LLMExplanationResult`)**: Pydantic model enforcing:
  - Allowed severity ratings (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
  - Separation of verified `observed_facts` from `inferred_risk`.
  - Rejection of empty or whitespace-only remediation strings.
  - Mandatory `missing_context_explanation` whenever CLI or Terraform fixes cannot be formulated without guessing.
  - Explicit architectural guardrail disclosure ensuring output is never piped into execution sinks.

---

## Planned / Roadmap Features (Not Yet Implemented in MVP)

- **Automated Remediation Execution**: Deterministic playbooks with rollback state capture (currently kept inactive).
- **Interactive Web Dashboard**: React/Recharts frontend for live incident visualization and metrics.
- **Slack Alerting & Approval Webhook**: Interactive Slack approval buttons for human-in-the-loop triage.
- **Terraform Infrastructure Modules**: Automated provisioning of baseline test environments.

---

## Installation & Setup

### Prerequisites
- Python 3.10 or 3.11
- Git

### 1. Clone & Set Up Virtual Environment

```bash
cd E:\Projects\cloud-guard
python -m venv .venv
# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# On Linux/macOS:
source .venv/bin/activate
```

### 2. Install Dependencies

Install the project in editable mode with development dependencies:

```bash
pip install -e .
```

Or install using `requirements.txt`:

```bash
pip install -r requirements.txt
```

### 3. Environment Configuration

Copy `.env.example` to `.env` to review the safe default settings:

```bash
cp .env.example .env
```

Default configuration in `.env.example`:
```ini
ENVIRONMENT=development
HOST=127.0.0.1
PORT=8000
DEBUG=false
LLM_PROVIDER=mock
ENABLE_SLACK_NOTIFICATIONS=false
AUTO_REMEDIATION_ENABLED=false
DRY_RUN=true
REQUIRE_APPROVAL_FOR_MEDIUM_RISK=true
```

---

## Testing

Run the test suite using `pytest`:

```bash
# Using the virtual environment executable:
.\.venv\Scripts\python.exe -m pytest -q
```

---

## Project Structure

```
cloud-guard/
├── .env.example              # Safe default configuration (offline/mock mode)
├── .gitignore                # Git exclusions (venv, secrets, cache)
├── LICENSE                   # MIT License
├── README.md                 # Project documentation
├── pyproject.toml            # Packaging & discovery configuration
├── requirements.txt          # Python dependencies
├── detection/
│   ├── __init__.py           # Detection package entrypoint
│   ├── engine.py             # Dual-layer detection coordinator
│   ├── ml/                   # Machine learning anomaly detection
│   │   ├── __init__.py
│   │   ├── anomaly_detector.py
│   │   ├── dataset_generator.py
│   │   └── feature_extractor.py
│   └── rules/                # Signature detection rules
│       ├── __init__.py
│       ├── base.py
│       ├── catalog.py        # 18 MITRE/CIS rules
│       └── rules.yaml        # YAML rules definition catalog
├── ingestion/
│   ├── __init__.py           # Ingestion package entrypoint
│   ├── lambda_handler.py     # AWS Lambda entrypoint
│   ├── models.py             # CanonicalCloudEvent schema
│   ├── normalizers.py        # CloudTrail, VPC Flow, Config normalizers
│   └── pipeline.py           # Stream & batch ingestion engine
└── llm/
    ├── __init__.py           # LLM package entrypoint
    └── schemas.py            # Validated advisory response schemas
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
