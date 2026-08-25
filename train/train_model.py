"""
Trains the L7-native DoS/DDoS classifier used by the gateway.

Usage:
    python3 -m train.train_model
    python3 -m train.train_model --samples-per-archetype 300
    python3 -m train.train_model --data real_traffic_export.csv   # blend in real labeled traffic
    python3 -m train.train_model --data real_traffic_export.csv --real-only  # real traffic only

Always trains on features produced by app.flow_tracker.compute_features_from_events
(imported directly, never reimplemented), so whatever the model learns on
is exactly what it's scored on in production - no train/serve mismatch.

Writes models/dos_ddos_xgboost.json, models/scaler.pkl, models/feature_names.json.
The first time this runs it backs up whatever was already in models/ into
models/_previous_model/ so you can always roll back.
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import joblib  # noqa: E402
import numpy as np  # noqa: E402
import xgboost as xgb  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    accuracy_score, classification_report, confusion_matrix, f1_score,
    precision_score, recall_score,
)
from sklearn.model_selection import train_test_split  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402

from app.flow_tracker import FEATURE_NAMES, compute_features_from_events  # noqa: E402
from train.generate_synthetic_traffic import generate_dataset  # noqa: E402

RANDOM_STATE = 42
MODELS_DIR = ROOT / "models"
BACKUP_DIR = MODELS_DIR / "_previous_model"


def sessions_to_rows(sessions, idle_gap_seconds: float = 1.0):
    """Expand each (events, label) session into several training rows by
    scoring at multiple prefix lengths (25%/55%/85%/100% of the session),
    matching how the live gateway scores on every incoming request using
    history-so-far, not just on a fully-formed completed session."""
    X, y = [], []
    for events, label in sessions:
        n = len(events)
        if n == 0:
            continue
        cut_fracs = [0.25, 0.55, 0.85, 1.0] if n >= 8 else [1.0]
        seen_cuts = set()
        for frac in cut_fracs:
            k = max(1, min(n, round(n * frac)))
            if k in seen_cuts:
                continue
            seen_cuts.add(k)
            prefix = events[:k]
            feats = compute_features_from_events(prefix, prefix[-1].ts, idle_gap_seconds)
            X.append([feats[name] for name in FEATURE_NAMES])
            y.append(label)
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int64)


def load_real_data(csv_path: Path):
    X, y = [], []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        missing = [c for c in FEATURE_NAMES if c not in reader.fieldnames]
        if missing:
            raise ValueError(f"{csv_path} is missing expected feature columns: {missing}")
        if "label" not in reader.fieldnames:
            raise ValueError(f"{csv_path} must have a 'label' column (0=benign, 1=attack)")
        for row in reader:
            X.append([float(row[name]) for name in FEATURE_NAMES])
            y.append(int(row["label"]))
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int64)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples-per-archetype", type=int, default=200,
                         help="synthetic sessions generated per benign/attack archetype")
    parser.add_argument("--data", type=Path, default=None,
                         help="CSV of real labeled traffic from export_labeled_data.py, blended into training")
    parser.add_argument("--real-only", action="store_true",
                         help="train on --data only, skip synthetic data entirely")
    parser.add_argument("--out-dir", type=Path, default=MODELS_DIR)
    args = parser.parse_args()

    rng = random.Random(RANDOM_STATE)

    X_parts, y_parts = [], []
    if not args.real_only:
        print(f"Generating synthetic traffic ({args.samples_per_archetype} sessions/archetype)...")
        sessions = generate_dataset(rng, args.samples_per_archetype)
        X_syn, y_syn = sessions_to_rows(sessions)
        print(f"  -> {len(X_syn)} synthetic training rows "
              f"({int(y_syn.sum())} attack / {len(y_syn) - int(y_syn.sum())} benign)")
        X_parts.append(X_syn)
        y_parts.append(y_syn)

    if args.data:
        print(f"Loading real labeled traffic from {args.data}...")
        X_real, y_real = load_real_data(args.data)
        print(f"  -> {len(X_real)} real training rows "
              f"({int(y_real.sum())} attack / {len(y_real) - int(y_real.sum())} benign)")
        X_parts.append(X_real)
        y_parts.append(y_real)

    if not X_parts:
        raise SystemExit("No training data: pass --data or drop --real-only.")

    X = np.concatenate(X_parts, axis=0)
    y = np.concatenate(y_parts, axis=0)
    X = np.nan_to_num(X, nan=0.0, posinf=1e9, neginf=-1e9)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train).astype(np.float32)
    X_test_scaled = scaler.transform(X_test).astype(np.float32)

    n_neg, n_pos = int((y_train == 0).sum()), int((y_train == 1).sum())
    scale_pos_weight = n_neg / max(n_pos, 1)

    model = xgb.XGBClassifier(
        n_estimators=250,
        max_depth=6,
        learning_rate=0.1,
        tree_method="hist",
        objective="binary:logistic",
        eval_metric="aucpr",
        scale_pos_weight=scale_pos_weight,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_train_scaled, y_train, eval_set=[(X_test_scaled, y_test)], verbose=False)

    y_pred = model.predict(X_test_scaled)
    print("\n--- Evaluation on held-out test set ---")
    print(f"Accuracy : {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"Recall   : {recall_score(y_test, y_pred):.4f}")
    print(f"F1-Score : {f1_score(y_test, y_pred):.4f}")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Attack"]))
    print("Confusion matrix [[TN, FP], [FN, TP]]:")
    print(confusion_matrix(y_test, y_pred))

    importances = model.feature_importances_
    print("\nTop 10 feature importances:")
    for i in np.argsort(importances)[::-1][:10]:
        print(f"  {FEATURE_NAMES[i]:<24s} {importances[i]:.4f}")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    if not BACKUP_DIR.exists():
        existing = list(MODELS_DIR.glob("*.json")) + list(MODELS_DIR.glob("*.pkl"))
        if existing:
            BACKUP_DIR.mkdir(parents=True, exist_ok=True)
            for f in existing:
                shutil.copy2(f, BACKUP_DIR / f.name)
            print(f"\nBacked up previous model artifacts to {BACKUP_DIR}")

    model.save_model(str(args.out_dir / "dos_ddos_xgboost.json"))
    joblib.dump(scaler, args.out_dir / "scaler.pkl")
    with open(args.out_dir / "feature_names.json", "w") as f:
        json.dump(FEATURE_NAMES, f, indent=2)

    print(f"\nSaved model + scaler + feature_names.json to {args.out_dir}")


if __name__ == "__main__":
    main()
