"""
Model Training Script for NetSentinel
======================================
Trains:
    1. RandomForestClassifier  on (X_train, y_train)
    2. IsolationForest         on X_train[y_train == 0]  (Benign baseline ONLY)

Evaluates Random Forest on the unseen (X_test, y_test).

The metrics reported here describe the Random Forest supervised classifier only.
They do NOT represent overall NetSentinel accuracy because NetSentinel also
uses Isolation Forest, the Rule Engine, and a Hybrid Risk Scorer.

Saves model version v1 artifacts to models/v1/.
Updates models/active_version.json to point to v1.

Source data in archive/ is NEVER modified.
No model artifact is written until all training and evaluation succeeds.
"""

import os
import sys
import time
import json
import datetime
import numpy as np
from pathlib import Path
import joblib

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# ---------------------------------------------------------------------------
# Robust path resolution — works from any working directory
# ---------------------------------------------------------------------------
SCRIPT_DIR  = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent          # CN_FINAL/
DATA_PATH   = PROJECT_DIR / "data" / "processed_data.joblib"
MODELS_DIR  = PROJECT_DIR / "models"
VERSION     = "v1"
VERSION_DIR = MODELS_DIR / VERSION

EXPECTED_FEATURES = [
    "FQDN_count", "subdomain_length", "upper", "lower", "numeric",
    "entropy", "special", "labels", "labels_max", "labels_average",
    "longest_word_len", "sld_len", "len", "subdomain"
]


def train_and_evaluate():
    print("=" * 65)
    print("NETSENTINEL — Machine Learning Training Pipeline (Version: v1)")
    print("=" * 65)

    # ------------------------------------------------------------------
    # 1. Load and validate processed dataset
    # ------------------------------------------------------------------
    if not DATA_PATH.exists():
        print(f"Error: '{DATA_PATH}' not found. Run scripts/prepare_dataset.py first.")
        sys.exit(1)

    print(f"Loading processed dataset from {DATA_PATH}...")
    try:
        dataset = joblib.load(DATA_PATH)
    except Exception as exc:
        print(f"Error: Cannot load processed data: {exc}")
        sys.exit(1)

    # Required keys
    required_keys = ["X_train", "X_test", "y_train", "y_test", "feature_names",
                     "total_source_rows", "class_distribution"]
    missing_keys = [k for k in required_keys if k not in dataset]
    if missing_keys:
        print(f"Error: Processed dataset is missing required keys: {missing_keys}")
        sys.exit(1)

    X_train      = dataset["X_train"]
    X_test       = dataset["X_test"]
    y_train      = dataset["y_train"]
    y_test       = dataset["y_test"]
    feature_names = list(dataset["feature_names"])

    # Feature schema validation
    if feature_names != EXPECTED_FEATURES:
        print(f"Error: Feature schema mismatch!")
        print(f"  Processed data has : {feature_names}")
        print(f"  Expected           : {EXPECTED_FEATURES}")
        print("Stopping — re-run scripts/prepare_dataset.py.")
        sys.exit(1)

    if hasattr(X_train, "columns") and list(X_train.columns) != EXPECTED_FEATURES:
        print(f"Error: X_train column order differs from expected features.")
        sys.exit(1)

    if hasattr(X_test, "columns") and list(X_test.columns) != EXPECTED_FEATURES:
        print(f"Error: X_test column order differs from expected features.")
        sys.exit(1)

    # Length validation
    if len(X_train) == 0:
        print("Error: X_train is empty.")
        sys.exit(1)
    if len(X_test) == 0:
        print("Error: X_test is empty.")
        sys.exit(1)
    if len(X_train) != len(y_train):
        print(f"Error: X_train ({len(X_train)}) and y_train ({len(y_train)}) length mismatch.")
        sys.exit(1)
    if len(X_test) != len(y_test):
        print(f"Error: X_test ({len(X_test)}) and y_test ({len(y_test)}) length mismatch.")
        sys.exit(1)

    # Class label validation
    for split_name, y_split in [("y_train", y_train), ("y_test", y_test)]:
        unique_labels = set(int(v) for v in y_split)
        if not unique_labels.issubset({0, 1}):
            print(f"Error: {split_name} contains invalid labels: {unique_labels}. Expected {{0, 1}}.")
            sys.exit(1)
        if not {0, 1}.issubset(unique_labels):
            print(f"Error: {split_name} is missing a class. Found: {unique_labels}.")
            sys.exit(1)

    print(f"Training samples : {len(X_train):,} | Test samples: {len(X_test):,}")
    print(f"Features         : {len(feature_names)} → {feature_names}")

    VERSION_DIR.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # 2. Train Random Forest Classifier
    # ------------------------------------------------------------------
    print("\n[1/3] Training RandomForestClassifier (n_estimators=100, max_depth=25, random_state=42)...")
    rf_start = time.time()
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=25,
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train, y_train)
    rf_train_time = time.time() - rf_start
    print(f"  Completed in {rf_train_time:.2f}s")

    # ------------------------------------------------------------------
    # 3. Train Isolation Forest (Benign baseline ONLY)
    # ------------------------------------------------------------------
    print("\n[2/3] Training IsolationForest on Benign training samples only...")
    X_train_benign = X_train[y_train == 0]
    if len(X_train_benign) == 0:
        print("Error: No benign training samples available for Isolation Forest training.")
        sys.exit(1)
    print(f"  Fitting on {len(X_train_benign):,} benign samples (Attack samples excluded).")
    if_start = time.time()
    iso = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=42,
        n_jobs=-1
    )
    iso.fit(X_train_benign)
    if_train_time = time.time() - if_start
    print(f"  Completed in {if_train_time:.2f}s")

    # Calibration bounds for the NetSentinel IF normalizer.
    # These are training-data calibration bounds — NOT universal thresholds.
    train_scores  = iso.score_samples(X_train_benign)
    iso_score_min = float(np.percentile(train_scores, 1))
    iso_score_max = float(np.percentile(train_scores, 99))
    print(f"  IF calibration (training-data bounds): min={iso_score_min:.4f}, max={iso_score_max:.4f}")

    # ------------------------------------------------------------------
    # 4. Evaluate Random Forest on unseen test set
    # ------------------------------------------------------------------
    print(f"\n[3/3] Random Forest Test Set Evaluation ({len(X_test):,} samples)...")
    eval_start = time.time()
    y_pred = rf.predict(X_test)
    eval_time = time.time() - eval_start

    # Verify Attack class (1) is in rf.classes_ before indexing.
    if 1 not in rf.classes_:
        print("Error: RF model classes_ does not contain Attack class (1). Cannot compute attack probability.")
        sys.exit(1)

    # Metrics with explicit pos_label=1 (Attack class).
    acc  = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, pos_label=1, zero_division=0))
    rec  = float(recall_score(y_test, y_pred, pos_label=1, zero_division=0))
    f1   = float(f1_score(y_test, y_pred, pos_label=1, zero_division=0))

    # Confusion matrix with explicit label ordering: 0=Benign, 1=Attack.
    # [[TN, FP], [FN, TP]]
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1]).tolist()

    clf_report = classification_report(
        y_test, y_pred,
        labels=[0, 1],
        target_names=["Benign", "Attack"],
        output_dict=True,
        zero_division=0
    )

    # Feature importance — sorted descending.
    importances       = dict(zip(feature_names, [float(v) for v in rf.feature_importances_]))
    sorted_importances = dict(sorted(importances.items(), key=lambda kv: kv[1], reverse=True))

    print("\n" + "=" * 50)
    print("RANDOM FOREST TEST SET EVALUATION METRICS")
    print("(These metrics describe the RF classifier only,")
    print(" NOT the overall NetSentinel hybrid pipeline.)")
    print("=" * 50)
    print(f"Test Samples : {len(X_test):,}")
    print(f"Accuracy     : {acc  * 100:.2f}%")
    print(f"Precision    : {prec * 100:.2f}%  (Attack class, pos_label=1)")
    print(f"Recall       : {rec  * 100:.2f}%  (Attack class, pos_label=1)")
    print(f"F1-Score     : {f1   * 100:.2f}%  (Attack class, pos_label=1)")
    print(f"Eval time    : {eval_time:.2f}s ({(eval_time / len(X_test)) * 1e6:.2f} µs/sample)")
    print(f"\nConfusion Matrix [Labels: 0=Benign, 1=Attack]:")
    print(f"  [[TN={cm[0][0]:6d}, FP={cm[0][1]:6d}],")
    print(f"   [FN={cm[1][0]:6d}, TP={cm[1][1]:6d}]]")
    print("\nTop 5 Important Features (RF):")
    for feat, imp in list(sorted_importances.items())[:5]:
        print(f"  {feat:20s}: {imp * 100:.2f}%")

    # ------------------------------------------------------------------
    # 5. Build metadata — no fabricated values
    # ------------------------------------------------------------------
    metadata = {
        "model_version":    VERSION,
        "trained_at":       datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "dataset_name":     "CIC-Bell-DNS-EXF-2021",
        "dataset_location": "archive",
        "total_source_rows": dataset["total_source_rows"],
        "training_samples": len(X_train),
        "test_samples":     len(X_test),
        "feature_count":    len(feature_names),
        "feature_names":    feature_names,
        "target_definition": {
            "0": "Benign",
            "1": "Attack"
        },
        "class_distribution": dataset["class_distribution"],
        "metrics": {
            "accuracy":              acc,
            "precision":             prec,
            "recall":                rec,
            "f1_score":              f1,
            "confusion_matrix":      cm,
            "confusion_matrix_note": "[[TN, FP], [FN, TP]] — label order: 0=Benign, 1=Attack",
            "classification_report": clf_report
        },
        "feature_importance": sorted_importances,
        "isolation_forest_config": {
            "description":            "Training-data calibration bounds — NOT universal thresholds.",
            "baseline_training_samples": int(len(X_train_benign)),
            "contamination":          "auto",
            "score_min_p1":           iso_score_min,
            "score_max_p99":          iso_score_max
        },
        "timing": {
            "rf_train_seconds":  rf_train_time,
            "if_train_seconds":  if_train_time,
            "eval_seconds":      eval_time
        },
        "scope_note": (
            "Accuracy / Precision / Recall / F1 describe the Random Forest classifier "
            "on the held-out test set.  They do NOT represent overall NetSentinel accuracy "
            "because NetSentinel also uses Isolation Forest, the Rule Engine, and a "
            "Hybrid Risk Scorer."
        ),
        "status": "active"
    }

    # ------------------------------------------------------------------
    # 6. Atomic artifact saving — all succeed or none are activated
    # ------------------------------------------------------------------
    rf_path   = VERSION_DIR / "random_forest.joblib"
    iso_path  = VERSION_DIR / "isolation_forest.joblib"
    meta_path = VERSION_DIR / "metadata.json"

    print(f"\nSaving model artifacts to {VERSION_DIR}...")
    try:
        joblib.dump(rf, rf_path)
        joblib.dump(iso, iso_path)
        with open(meta_path, "w", encoding="utf-8") as fh:
            json.dump(metadata, fh, indent=2)
    except Exception as exc:
        print(f"Error: Failed to save artifacts: {exc}")
        print("Active version pointer was NOT updated.")
        sys.exit(1)

    # Only update active_version.json after all artifacts are safely written.
    active_path = MODELS_DIR / "active_version.json"
    active_data = {
        "active_version": VERSION,
        "updated_at":     metadata["trained_at"]
    }
    try:
        with open(active_path, "w", encoding="utf-8") as fh:
            json.dump(active_data, fh, indent=2)
    except Exception as exc:
        print(f"Error: Artifacts saved but failed to update active_version.json: {exc}")
        sys.exit(1)

    print("Artifacts successfully written:")
    print(f"  - {rf_path}")
    print(f"  - {iso_path}")
    print(f"  - {meta_path}")
    print(f"  - {active_path}  (active_version = '{VERSION}')")
    print("=" * 65)


if __name__ == "__main__":
    train_and_evaluate()
