"""
Model Loader and Inference Manager for NetSentinel
Manages model loading, versioning, fallback resilience, and inference.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Optional, List

MODELS_DIR = "models"
ACTIVE_VERSION_FILE = os.path.join(MODELS_DIR, "active_version.json")

class ModelManager:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(ModelManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if getattr(self, "_initialized", False):
            return
        self.active_version = None
        self.rf_model = None
        self.iso_model = None
        self.metadata = {}
        # Fallback values are NetSentinel project calibration defaults based on the benign baseline distribution;
        # they are NOT official CIC-Bell-DNS-EXF-2021 thresholds.
        self.iso_score_min = -0.72
        self.iso_score_max = -0.38
        self.feature_names: List[str] = []
        self.load_active_model()
        self._initialized = True

    def get_active_version_name(self) -> str:
        if os.path.exists(ACTIVE_VERSION_FILE):
            try:
                with open(ACTIVE_VERSION_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("active_version", "v1")
            except Exception:
                return "v1"
        return "v1"

    def load_active_model(self, version_name: Optional[str] = None) -> bool:
        """
        Loads the specified or currently active model artifacts.
        Preserves existing working model if loading fails.
        """
        target_version = version_name or self.get_active_version_name()
        version_dir = os.path.join(MODELS_DIR, target_version)
        rf_path = os.path.join(version_dir, "random_forest.joblib")
        iso_path = os.path.join(version_dir, "isolation_forest.joblib")
        meta_path = os.path.join(version_dir, "metadata.json")

        if not (os.path.exists(rf_path) and os.path.exists(iso_path) and os.path.exists(meta_path)):
            print(f"Warning: Model artifacts missing for version '{target_version}' at {version_dir}.")
            return False

        try:
            new_rf = joblib.load(rf_path)
            new_iso = joblib.load(iso_path)
            with open(meta_path, "r", encoding="utf-8") as f:
                new_meta = json.load(f)

            # Successfully loaded; update active instance
            self.rf_model = new_rf
            self.iso_model = new_iso
            self.metadata = new_meta
            self.active_version = target_version
            self.feature_names = new_meta.get("feature_names", [])

            iso_cfg = new_meta.get("isolation_forest_config", {})
            self.iso_score_min = float(iso_cfg.get("score_min", -0.72))
            self.iso_score_max = float(iso_cfg.get("score_max", -0.38))

            print(f"NetSentinel: Successfully activated model version '{self.active_version}'.")
            return True
        except Exception as e:
            print(f"Error loading model version '{target_version}': {e}. Preserving previous model.")
            return False

    def activate_version(self, version_name: str) -> bool:
        """Sets a validated version as active in active_version.json."""
        if self.load_active_model(version_name):
            os.makedirs(MODELS_DIR, exist_ok=True)
            with open(ACTIVE_VERSION_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "active_version": version_name,
                    "updated_at": self.metadata.get("trained_at", "")
                }, f, indent=2)
            return True
        return False

    def normalize_if_score(self, raw_scores: np.ndarray) -> np.ndarray:
        """
        Calibrates raw Isolation Forest score_samples (negative values) into [0.0, 1.0].
        0.0 = completely normal baseline
        1.0 = highly anomalous

        Note: Lower raw score indicates greater anomaly; higher indicates normal.
        Calibration defaults (score_min=-0.72, score_max=-0.38) are NetSentinel project
        calibration defaults and are NOT official CIC-Bell-DNS-EXF-2021 thresholds.
        """
        denom = self.iso_score_max - self.iso_score_min
        if denom == 0:
            denom = 1e-6
        # Invert: lower raw score -> higher anomaly score
        normalized = (self.iso_score_max - raw_scores) / denom
        return np.clip(normalized, 0.0, 1.0)

    def predict(self, feature_df: pd.DataFrame) -> Dict[str, Any]:
        """
        Runs RF supervised prediction and IF anomaly detection on a batch of DNS features.
        Returns aggregated probabilities, anomaly scores, and per-query predictions.
        """
        if self.rf_model is None or self.iso_model is None:
            raise RuntimeError("ML models are not loaded.")

        # 1. Empty input validation
        if feature_df.empty:
            raise ValueError("No DNS feature rows available for prediction.")

        # 2. Feature validation
        if not self.feature_names:
            raise RuntimeError("Model feature names are missing from metadata.")

        missing_features = [col for col in self.feature_names if col not in feature_df.columns]
        if missing_features:
            raise ValueError(f"Missing required feature columns for prediction: {missing_features}")

        # Ensure exact column ordering matching model metadata
        X = feature_df[self.feature_names].copy()

        # 3. Random Forest Attack Class Handling (Locate class 1 explicitly)
        classes = list(self.rf_model.classes_)
        if 1 not in classes:
            raise RuntimeError(
                f"Random Forest model '{self.active_version}' does not contain the expected Attack class (label 1). Classes found: {classes}"
            )
        attack_class_index = classes.index(1)
        rf_probas = self.rf_model.predict_proba(X)[:, attack_class_index]
        rf_preds = self.rf_model.predict(X)

        # 4. Isolation Forest score & normalization
        raw_iso_scores = self.iso_model.score_samples(X)
        norm_if_scores = self.normalize_if_score(raw_iso_scores)

        # 5 & 6. PCAP-level aggregation
        # Note: The 60/40 weighting (60% peak burst + 40% volume mean) is a NetSentinel
        # project-defined aggregation heuristic designed to detect exfiltration bursts while
        # incorporating average session behavior.
        mean_rf_prob = float(np.mean(rf_probas))
        max_rf_prob = float(np.max(rf_probas))
        blended_rf_prob = float((0.6 * max_rf_prob) + (0.4 * mean_rf_prob))

        mean_if_score = float(np.mean(norm_if_scores))
        max_if_score = float(np.max(norm_if_scores))
        blended_if_score = float((0.6 * max_if_score) + (0.4 * mean_if_score))

        # 7. Attack Decision Threshold
        # Note: 0.5 is the current NetSentinel project decision threshold (not an official CIC threshold).
        predicted_class = "Attack" if blended_rf_prob >= 0.5 else "Benign"

        return {
            "predicted_class": predicted_class,
            "rf_probability": round(blended_rf_prob, 4),
            "if_anomaly_score": round(blended_if_score, 4),
            "rf_mean_prob": round(mean_rf_prob, 4),
            "rf_max_prob": round(max_rf_prob, 4),
            "per_query_rf": [round(float(p), 4) for p in rf_probas],
            "per_query_if": [round(float(s), 4) for s in norm_if_scores],
            "model_version": self.active_version
        }

model_manager = ModelManager()
