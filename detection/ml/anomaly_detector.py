"""Isolation Forest anomaly detection engine for behavioral security analysis."""

import logging
from typing import Dict, Optional, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import f1_score, precision_score, recall_score

from detection.ml.dataset_generator import SyntheticDataGenerator

logger = logging.getLogger("cloudguard.ml")


class IsolationForestAnomalyDetector:
    """Lightweight behavioral anomaly detector powered by scikit-learn Isolation Forest."""

    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.contamination = contamination
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=random_state,
            n_jobs=1,  # Keep single threaded for low RAM footprint
        )
        self.is_trained = False
        self._cached_metrics: Optional[Dict[str, float]] = None
        self._auto_train()

    def _auto_train(self) -> None:
        """Trains baseline model on synthetic normal cloud operations."""
        logger.info("Initializing baseline Isolation Forest model with synthetic normal dataset...")
        normal_data = SyntheticDataGenerator.generate_normal_activity(samples=1200)
        self.model.fit(normal_data)
        self.is_trained = True

    def predict(self, feature_vector: np.ndarray) -> Tuple[bool, float]:
        """Predicts whether the feature vector is anomalous.

        Returns:
            Tuple[is_anomaly (bool), anomaly_score (float, 0.0 to 1.0)]
        """
        if not self.is_trained:
            self._auto_train()

        X = feature_vector.reshape(1, -1)
        # IsolationForest predict returns: -1 for anomaly, 1 for inlier
        raw_pred = self.model.predict(X)[0]
        # decision_function returns negative values for anomalies, positive for normal
        score = self.model.decision_function(X)[0]

        # Normalize score into [0, 1] range where 1.0 is extremely anomalous
        # Typical decision_function values range from -0.5 (most anomalous) to +0.2 (most normal)
        anomaly_prob = float(np.clip(1.0 - (score + 0.5) / 0.7, 0.0, 1.0))
        is_anomaly = bool(raw_pred == -1)

        return is_anomaly, anomaly_prob

    def evaluate_performance(self) -> Dict[str, float]:
        """Computes Precision, Recall, and F1 metrics on simulated attack scenarios."""
        if self._cached_metrics:
            return self._cached_metrics

        X_test, y_test = SyntheticDataGenerator.get_evaluation_dataset()
        preds = self.model.predict(X_test)
        # Convert IsolationForest (-1=anomaly, 1=inlier) to binary (1=anomaly, 0=inlier)
        y_pred = np.where(preds == -1, 1, 0)

        precision = float(precision_score(y_test, y_pred, zero_division=0))
        recall = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))

        self._cached_metrics = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "test_samples": len(y_test),
        }
        return self._cached_metrics
