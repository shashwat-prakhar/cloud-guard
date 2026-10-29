"""Tests for CloudGuard Machine Learning Behavioral Anomaly Detection."""

import numpy as np
import pytest

from detection.ml.anomaly_detector import IsolationForestAnomalyDetector
from detection.ml.dataset_generator import SyntheticDataGenerator
from detection.ml.feature_extractor import FeatureExtractor
from ingestion.models import Actor, CanonicalCloudEvent, EventSourceType, ResourceTarget


def make_canonical_event(
    principal_id: str = "dev-user",
    resource_type: str = "s3:bucket",
    status: str = "Success",
    event_hour: int = 14
) -> CanonicalCloudEvent:
    """Helper creating event for feature extractor tests."""
    return CanonicalCloudEvent(
        event_source=EventSourceType.CLOUDTRAIL,
        event_name="GetObject",
        actor=Actor(principal_id=principal_id),
        resource=ResourceTarget(name="test-bkt", resource_type=resource_type),
        status=status,
    )


def test_feature_extractor_dimensions_and_types():
    """Verify FeatureExtractor generates 6-dimensional numerical feature vectors."""
    extractor = FeatureExtractor()
    event = make_canonical_event(principal_id="alice", resource_type="iam:user", status="Failure")

    vector = extractor.extract_features_from_event(event)

    assert isinstance(vector, np.ndarray)
    assert vector.shape == (6,)
    assert vector.dtype == np.float32

    # Check high-privilege service flag (iam -> index 5 = 1.0)
    assert vector[5] == 1.0
    # Check failure ratio (1 failure out of 1 call -> index 4 = 1.0)
    assert vector[4] == 1.0


def test_feature_extractor_batch():
    """Verify batch extraction converts list of events to (N, 6) matrix."""
    extractor = FeatureExtractor()
    events = [
        make_canonical_event(principal_id="bob"),
        make_canonical_event(principal_id="bob", resource_type="ec2:instance"),
    ]

    matrix = extractor.extract_batch(events)
    assert matrix.shape == (2, 6)


def test_synthetic_data_generator():
    """Verify synthetic normal and attack activity shapes and value bounds."""
    normal_data = SyntheticDataGenerator.generate_normal_activity(samples=100)
    attack_data = SyntheticDataGenerator.generate_attack_activity(samples=50)
    X_test, y_test = SyntheticDataGenerator.get_evaluation_dataset()

    assert normal_data.shape == (100, 6)
    assert attack_data.shape == (50, 6)
    assert len(X_test) == len(y_test)
    assert len(y_test) == 600  # 500 normal + 100 attack


def test_isolation_forest_detector_predict():
    """Verify Isolation Forest predicts anomaly boolean and normalized score [0, 1]."""
    detector = IsolationForestAnomalyDetector()

    # Normal daytime feature vector: 10 calls/hr, 1 service, 11 AM, not off-hours, 0% failure, no high-priv
    normal_vector = np.array([10.0, 1.0, 11.0, 0.0, 0.0, 0.0], dtype=np.float32)
    is_anomaly, score = detector.predict(normal_vector)

    assert isinstance(is_anomaly, (bool, np.bool_))
    assert 0.0 <= score <= 1.0
    # Normal activity should produce a lower anomaly score
    assert score < 0.60

    # Attacker reconnaissance burst: 300 calls/hr, 10 services, 3 AM off-hours, 40% failure, high-priv
    attacker_vector = np.array([300.0, 10.0, 3.0, 1.0, 0.40, 1.0], dtype=np.float32)
    is_anomaly_atk, score_atk = detector.predict(attacker_vector)

    assert score_atk > score
    assert is_anomaly_atk is True


def test_isolation_forest_evaluate_performance():
    """Verify precision, recall, and F1 calculation on benchmark attack scenarios."""
    detector = IsolationForestAnomalyDetector()
    metrics = detector.evaluate_performance()

    assert "precision" in metrics
    assert "recall" in metrics
    assert "f1_score" in metrics
    assert "test_samples" in metrics

    assert 0.0 <= metrics["precision"] <= 1.0
    assert 0.0 <= metrics["recall"] <= 1.0
    assert 0.0 <= metrics["f1_score"] <= 1.0
    assert metrics["test_samples"] > 0
