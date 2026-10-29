"""Synthetic CloudTrail baseline and attack dataset generator.

Simulates normal enterprise user workloads vs attacker anomalies (e.g. credential compromise,
3 AM reconnaissance bursts, IAM enumeration) for training and F1/Recall evaluation.
"""

from typing import Tuple
import numpy as np


class SyntheticDataGenerator:
    """Generates synthetic behavioral feature vectors for training and benchmark evaluations."""

    @staticmethod
    def generate_normal_activity(samples: int = 1000, random_seed: int = 42) -> np.ndarray:
        """Simulates typical daytime engineer activity:
        - Moderate API call rate (5 - 35 calls/hr)
        - 1 to 3 distinct services touched
        - Working hours (08:00 - 18:00)
        - Off-hours flag = 0
        - Low failure ratio (0% - 3%)
        - Rare high-privilege IAM calls
        """
        np.random.seed(random_seed)
        calls_per_hour = np.random.uniform(5.0, 35.0, samples)
        services_touched = np.random.choice([1.0, 2.0, 3.0], size=samples, p=[0.6, 0.3, 0.1])
        hours = np.random.uniform(8.0, 18.0, samples)
        off_hours = np.zeros(samples)
        failure_ratio = np.random.uniform(0.0, 0.03, samples)
        high_priv = np.random.choice([0.0, 1.0], size=samples, p=[0.95, 0.05])

        return np.column_stack([
            calls_per_hour,
            services_touched,
            hours,
            off_hours,
            failure_ratio,
            high_priv,
        ]).astype(np.float32)

    @staticmethod
    def generate_attack_activity(samples: int = 150, random_seed: int = 43) -> np.ndarray:
        """Simulates compromised credentials / attacker anomalies:
        - Massive reconnaissance call burst (120 - 450 calls/hr)
        - Broad enumeration across many services (6 to 12 services)
        - Uncharacteristic off-hours (02:00 - 04:30 AM)
        - Off-hours flag = 1
        - Elevated permission denial failure ratio (15% - 60%)
        - High volume of IAM/STS enumeration (high_priv = 1)
        """
        np.random.seed(random_seed)
        calls_per_hour = np.random.uniform(120.0, 450.0, samples)
        services_touched = np.random.uniform(6.0, 12.0, samples)
        hours = np.random.uniform(2.0, 4.5, samples)
        off_hours = np.ones(samples)
        failure_ratio = np.random.uniform(0.15, 0.60, samples)
        high_priv = np.ones(samples)

        return np.column_stack([
            calls_per_hour,
            services_touched,
            hours,
            off_hours,
            failure_ratio,
            high_priv,
        ]).astype(np.float32)

    @classmethod
    def get_evaluation_dataset(cls) -> Tuple[np.ndarray, np.ndarray]:
        """Returns combined test feature matrix X and ground truth binary labels y (0=Normal, 1=Attack)."""
        normal = cls.generate_normal_activity(samples=500, random_seed=101)
        attacks = cls.generate_attack_activity(samples=100, random_seed=202)

        X = np.vstack([normal, attacks])
        y = np.array([0] * len(normal) + [1] * len(attacks))
        return X, y
