"""
Loads the trained XGBoost DoS/DDoS classifier, the fitted StandardScaler,
and the exact training feature order, then exposes a single `predict`
method that turns a feature dict into an attack probability.

This is a thin, defensive wrapper: it never lets a missing/odd feature
crash a live request - anything not supplied is filled with 0.0 and the
vector is always re-ordered to match feature_names.json before scaling.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Mapping

import joblib
import numpy as np
import xgboost as xgb

from .config import settings

logger = logging.getLogger("gateway.model")


class ModelService:
    def __init__(self, model_dir: str | Path):
        model_dir = Path(model_dir)
        features_path = model_dir / "feature_names.json"
        scaler_path = model_dir / "scaler.pkl"
        model_json_path = model_dir / "dos_ddos_xgboost.json"
        model_pkl_path = model_dir / "dos_ddos_xgboost.pkl"

        with open(features_path) as f:
            self.feature_names: list[str] = json.load(f)

        self.scaler = joblib.load(scaler_path)

        self.model = xgb.XGBClassifier()
        if model_json_path.exists():
            self.model.load_model(str(model_json_path))
        elif model_pkl_path.exists():
            self.model = joblib.load(model_pkl_path)
        else:
            raise FileNotFoundError(
                f"No model file found in {model_dir} (expected dos_ddos_xgboost.json or .pkl)"
            )

        n_expected = getattr(self.scaler, "n_features_in_", len(self.feature_names))
        if n_expected != len(self.feature_names):
            raise ValueError(
                f"scaler expects {n_expected} features but feature_names.json has "
                f"{len(self.feature_names)} entries - artifacts are out of sync."
            )

        logger.info(
            "Model service ready: %d features, threshold=%.3f",
            len(self.feature_names), settings.attack_threshold,
        )

    def vectorize(self, feature_dict: Mapping[str, float]) -> np.ndarray:
        row = [float(feature_dict.get(name, 0.0)) for name in self.feature_names]
        arr = np.array([row], dtype=np.float32)
        # Guard against NaN/Inf sneaking in from a pathological flow (e.g.
        # a flow duration of 0 driving a rate feature to infinity) - the
        # training data had the same issue and those rows were dropped;
        # here we can't drop a live request, so we clip instead.
        arr = np.nan_to_num(arr, nan=0.0, posinf=1e9, neginf=-1e9)
        return arr

    def predict(self, feature_dict: Mapping[str, float]) -> tuple[float, np.ndarray]:
        """Returns (attack_probability, raw_feature_vector)."""
        raw = self.vectorize(feature_dict)
        scaled = self.scaler.transform(raw)
        proba = float(self.model.predict_proba(scaled)[0, 1])
        return proba, raw[0]

    def is_attack(self, attack_probability: float) -> bool:
        return attack_probability >= settings.attack_threshold


_model_service: ModelService | None = None


def get_model_service() -> ModelService:
    global _model_service
    if _model_service is None:
        _model_service = ModelService(settings.model_dir)
    return _model_service
