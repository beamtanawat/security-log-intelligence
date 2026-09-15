"""Deterministic Stage 1.8 anomaly-scoring contracts and helpers.

This package scores validated Stage 1.7 feature vectors.  It does not infer
attacks, maliciousness, incidents, or analyst conclusions.
"""

from .models import ANOMALY_SCHEMA_VERSION, AnomalyScoreRow

__all__ = ("ANOMALY_SCHEMA_VERSION", "AnomalyScoreRow")
