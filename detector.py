"""
Behavioral-baseline anomaly detector per sector.

Ensemble of two independent signals:
  1. IsolationForest        — trained on synthetic 'normal' traffic (startup
                               bootstrap) or a rolling window of real ingested
                               telemetry (production).  retrain_on_real_data()
                               re-fits it whenever enough new traffic exists.
  2. EWMA/CUSUM trend watch — an online exponentially-weighted mean/variance
                               tracker that catches sustained drift even when
                               a single reading isn't extreme enough to trip
                               the isolation forest alone.

The two are blended into one 0-100 risk score. When a reading is flagged
anomalous, its z-score vector is compared (cosine similarity) against known
attack "fingerprints" to classify *what kind* of attack it most resembles —
this is the explainability layer.

A lightweight feedback loop lets an analyst mark an alert as a false
positive; that nudges a per-sector risk bias down for a while, which is a
simple stand-in for "the model adapts."

Continuous baseline learning
----------------------------
The admin "Retrain Detector" button and the background retraining thread in
app.py both call retrain_on_real_data(rows).  *rows* is a list of metric dicts
pulled from the ingest_telemetry table — real traffic from /api/ingest or any
future connector.  If fewer than MIN_REAL_ROWS rows are available the method
falls back to synthetic data augmented with whatever real rows do exist, so
the detector degrades gracefully rather than refusing to retrain.
"""
import random
import time

import numpy as np
from sklearn.ensemble import IsolationForest

from simulator import METRIC_BASELINES, ATTACK_SIGNATURES, METRIC_NAMES

# Minimum number of real ingested rows before we trust them enough to retrain.
# Below this threshold we pad with synthetic Gaussian samples so the
# IsolationForest still has enough variance to learn from.
MIN_REAL_ROWS = 50
# How many synthetic samples to add when padding a small real dataset.
SYNTHETIC_PAD_SIZE = 200

# Precompute a normalized "fingerprint" vector per attack type from its
# multiplier ranges, so we can classify anomalies by cosine similarity.
_ATTACK_CENTROIDS = {}
for atype, spec in ATTACK_SIGNATURES.items():
    vec = np.array([np.mean(spec["multipliers"][m]) - 1.0 for m in METRIC_NAMES])
    norm = np.linalg.norm(vec)
    _ATTACK_CENTROIDS[atype] = vec / norm if norm > 0 else vec


def _generate_normal_sample():
    return [max(0, random.gauss(mean, std)) for mean, std in METRIC_BASELINES.values()]


class _EwmaTracker:
    """Online exponentially-weighted mean/variance per metric, used to catch
    sustained drift (a CUSUM-style trend signal) independent of the
    IsolationForest's point-in-time view."""

    def __init__(self, n_metrics, alpha=0.05):
        self.alpha = alpha
        self.mean = np.zeros(n_metrics)
        self.var = np.ones(n_metrics)
        self.cusum = np.zeros(n_metrics)
        self._initialized = False

    def update_and_score(self, x):
        if not self._initialized:
            self.mean = x.copy()
            self.var = np.ones_like(x)
            self._initialized = True
            return 0.0

        deviation = x - self.mean
        # CUSUM-style accumulation of sustained positive drift, decayed each step
        self.cusum = np.maximum(0, self.cusum * 0.85 + deviation / (np.sqrt(self.var) + 1e-6))
        # update running mean/var (EWMA)
        self.mean = (1 - self.alpha) * self.mean + self.alpha * x
        self.var = (1 - self.alpha) * self.var + self.alpha * (deviation ** 2)

        trend_score = float(np.clip(np.max(self.cusum) * 8.0, 0, 100))
        return trend_score


class SectorDetector:
    def __init__(self, training_size=300):
        X_train = np.array([_generate_normal_sample() for _ in range(training_size)])
        self.model = IsolationForest(
            n_estimators=150, contamination=0.05, random_state=42
        )
        self.model.fit(X_train)

        self.means = X_train.mean(axis=0)
        self.stds = X_train.std(axis=0) + 1e-6

        self.trend = _EwmaTracker(len(METRIC_NAMES))

        # Feedback state: analyst-driven bias that suppresses over-eager alerts.
        self.risk_bias = 0.0

        # When this instance's IsolationForest was fit — surfaced on the
        # admin System Health panel so it's obvious how stale a sector's
        # model is (esp. after a "Retrain Detector" / "Reset Demo" action).
        self.trained_at = time.time()

        # False when using the synthetic bootstrap; True once retrained on
        # at least MIN_REAL_ROWS of real ingested traffic.
        self.trained_on_real_data = False
        # How many real rows were used in the last fit (0 = pure synthetic).
        self.real_row_count = 0

    def retrain_on_real_data(self, rows):
        """Re-fit the IsolationForest on a rolling window of real telemetry.

        *rows* is a list of metric dicts from storage.get_ingest_baseline_window().
        If len(rows) >= MIN_REAL_ROWS the model is trained purely on real data;
        otherwise it is padded with synthetic Gaussian samples so the
        IsolationForest always has enough examples to learn a baseline.

        The EWMA trend tracker is intentionally *not* reset here — it is an
        online signal that accumulates continuously regardless of how the
        IsolationForest has been trained.  The feedback bias (risk_bias) is
        also preserved so an ongoing suppression survives a background retrain.

        Returns True if the retrain succeeded, False if it was skipped (e.g.
        rows is empty and MIN_REAL_ROWS > 0 was not met — callers can check).
        """
        n_real = len(rows)

        if n_real == 0:
            return False  # nothing to learn from yet

        # Build the real portion of the training matrix.
        real_matrix = np.array(
            [[r[m] for m in METRIC_NAMES] for r in rows], dtype=float
        )

        if n_real >= MIN_REAL_ROWS:
            X_train = real_matrix
        else:
            # Pad with synthetic samples so IsolationForest has enough data.
            synthetic = np.array(
                [_generate_normal_sample() for _ in range(SYNTHETIC_PAD_SIZE)]
            )
            X_train = np.vstack([real_matrix, synthetic])

        new_model = IsolationForest(
            n_estimators=150, contamination=0.05, random_state=42
        )
        new_model.fit(X_train)

        # Atomic swap — keeps the detector live during the (cheap) fit.
        self.model = new_model
        self.means = X_train.mean(axis=0)
        self.stds = X_train.std(axis=0) + 1e-6
        self.trained_at = time.time()
        self.trained_on_real_data = n_real >= MIN_REAL_ROWS
        self.real_row_count = n_real
        return True

    def mark_false_positive(self):
        """Called when an analyst flags the latest alert as a false positive.
        Raises the bar for this sector for a while (decays back over time)."""
        self.risk_bias = min(35.0, self.risk_bias + 9.0)

    def _decay_bias(self):
        self.risk_bias *= 0.96
        if self.risk_bias < 0.3:
            self.risk_bias = 0.0

    def _classify_attack(self, z_scores):
        v = z_scores - z_scores.mean()
        norm = np.linalg.norm(v)
        if norm == 0:
            return None, 0.0
        v = v / norm
        best_type, best_sim = None, -1.0
        for atype, centroid in _ATTACK_CENTROIDS.items():
            sim = float(np.dot(v, centroid))
            if sim > best_sim:
                best_type, best_sim = atype, sim
        return best_type, best_sim

    def score(self, reading: dict, alert_threshold: float = 40.0):
        x = np.array([reading[m] for m in METRIC_NAMES])
        x2d = x.reshape(1, -1)

        raw_score = self.model.decision_function(x2d)[0]  # higher = more normal
        prediction = self.model.predict(x2d)[0]  # -1 anomaly, 1 normal
        forest_risk = float(np.clip((0.5 - raw_score) * 100, 0, 100))

        trend_risk = self.trend.update_and_score(x)

        # Ensemble: weighted blend of point-anomaly and sustained-drift signals
        ensemble_risk = 0.7 * forest_risk + 0.3 * trend_risk

        self._decay_bias()
        risk_score = float(np.clip(ensemble_risk - self.risk_bias, 0, 100))
        # alert_threshold is the per-sector configurable risk-score cutoff
        # (see storage.sector_thresholds / admin panel) — lets, e.g., the
        # hospital sector alert more eagerly than a lower-stakes sector.
        is_anomaly = bool(prediction == -1) and risk_score > alert_threshold

        z_scores = np.abs((x - self.means) / self.stds)
        top_idx = int(np.argmax(z_scores))
        top_factor = METRIC_NAMES[top_idx]

        attack_type, confidence = (None, 0.0)
        if is_anomaly:
            attack_type, confidence = self._classify_attack(z_scores)

        # Per-metric z-scores for investigation drill-down
        metric_scores = {
            METRIC_NAMES[i]: round(float(z_scores[i]), 2) for i in range(len(METRIC_NAMES))
        }
        
        return {
            "risk_score": round(risk_score, 1),
            "is_anomaly": is_anomaly,
            "top_factor": top_factor,
            "forest_risk": round(forest_risk, 1),
            "trend_risk": round(trend_risk, 1),
            "predicted_attack_type": attack_type,
            "attack_confidence": round(confidence, 2),
            "metric_scores": metric_scores,  # Per-metric z-scores for drill-down
        }