"""
Model Evaluation Script for NetSentinel
========================================
Evaluates the ACTIVE Random Forest supervised classifier on the held-out test set.

IMPORTANT SCOPE DISCLAIMER
---------------------------
This script evaluates the Random Forest classifier only.
It does NOT evaluate:
    - Isolation Forest
    - DNS Rule Engine
    - RiskScorer hybrid risk formula
    - Final 0-100 hybrid risk score

The reported accuracy / precision / recall / F1 describe the RF classifier
on the held-out test set.  They must NOT be labelled "overall NetSentinel accuracy."

No model is retrained here.  No model artifact is modified.
"""

import os
import sys
import json
import joblib
from pathlib import Path
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# ---------------------------------------------------------------------------
# Path resolution — robust relative to the CN_FINAL project root
# ---------------------------------------------------------------------------
SCRIPT_DIR  = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent          # CN_FINAL/
MODELS_DIR  = PROJECT_DIR / "models"
DATA_PATH   = PROJECT_DIR / "data" / "processed_data.joblib"


def evaluate():
    # ------------------------------------------------------------------
    # 1. Locate and validate active_version.json
    # ------------------------------------------------------------------
    active_path = MODELS_DIR / "active_version.json"
    if not active_path.exists():
        print(f"ERROR: '{active_path}' not found. Run scripts/train_model.py first.")
        sys.exit(1)

    try:
        with open(active_path, "r", encoding="utf-8") as fh:
            active_data = json.load(fh)
    except json.JSONDecodeError as exc:
        print(f"ERROR: '{active_path}' contains invalid JSON: {exc}")
        sys.exit(1)

    version = active_data.get("active_version")
    if not version or not isinstance(version, str) or not version.strip():
        print(f"ERROR: 'active_version' key is missing or empty in {active_path}.")
        sys.exit(1)
    version = version.strip()

    print("=" * 60)
    print(f"NETSENTINEL — Random Forest Test Set Evaluation")
    print(f"Active Version: {version}")
    print("=" * 60)

    # ------------------------------------------------------------------
    # 2. Validate model and dataset paths
    # ------------------------------------------------------------------
    version_dir = MODELS_DIR / version
    rf_path     = version_dir / "random_forest.joblib"
    meta_path   = version_dir / "metadata.json"

    if not rf_path.exists():
        print(f"ERROR: Random Forest artifact not found: '{rf_path}'")
        sys.exit(1)

    if not DATA_PATH.exists():
        print(f"ERROR: Processed data file not found: '{DATA_PATH}'")
        print("Run scripts/prepare_dataset.py first.")
        sys.exit(1)

    # ------------------------------------------------------------------
    # 3. Load dataset and validate
    # ------------------------------------------------------------------
    try:
        dataset = joblib.load(DATA_PATH)
    except Exception as exc:
        print(f"ERROR: Failed to load processed data: {exc}")
        sys.exit(1)

    if "X_test" not in dataset:
        print("ERROR: 'X_test' key missing from processed data.")
        sys.exit(1)
    if "y_test" not in dataset:
        print("ERROR: 'y_test' key missing from processed data.")
        sys.exit(1)

    X_test = dataset["X_test"]
    y_test = dataset["y_test"]

    if len(X_test) == 0 or len(y_test) == 0:
        print("ERROR: Test dataset is empty. Re-run scripts/prepare_dataset.py.")
        sys.exit(1)

    if len(X_test) != len(y_test):
        print(f"ERROR: X_test length ({len(X_test)}) != y_test length ({len(y_test)}). "
              "Data integrity problem — re-run scripts/prepare_dataset.py.")
        sys.exit(1)

    # ------------------------------------------------------------------
    # 4. Load Random Forest and validate feature compatibility
    # ------------------------------------------------------------------
    try:
        rf = joblib.load(rf_path)
    except Exception as exc:
        print(f"ERROR: Failed to load model artifact '{rf_path}': {exc}")
        sys.exit(1)

    # If the model exposes feature_names_in_, verify they match X_test columns.
    if hasattr(rf, "feature_names_in_") and hasattr(X_test, "columns"):
        model_features = list(rf.feature_names_in_)
        test_features  = list(X_test.columns)
        if model_features != test_features:
            print("ERROR: Feature mismatch between RF model and X_test.")
            print(f"  Model expects : {model_features}")
            print(f"  X_test has    : {test_features}")
            sys.exit(1)

    # Verify Attack class (1) is present in model.
    if not hasattr(rf, "classes_") or 1 not in rf.classes_:
        print("ERROR: RF model does not expose class 1 (Attack) in rf.classes_. "
              "The model may be corrupted or trained on different labels.")
        sys.exit(1)

    # Validate class labels in test set.
    unique_labels = set(int(v) for v in y_test)
    if not unique_labels.issubset({0, 1}):
        print(f"ERROR: y_test contains unexpected labels: {unique_labels}. "
              "Expected binary labels {{0, 1}}.")
        sys.exit(1)

    # ------------------------------------------------------------------
    # 5. Inference — no retraining, no threshold tuning, no data modification
    # ------------------------------------------------------------------
    y_pred = rf.predict(X_test)

    # Metrics use pos_label=1 (Attack) explicitly.
    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, pos_label=1, zero_division=0)
    rec  = recall_score(y_test, y_pred, pos_label=1, zero_division=0)
    f1   = f1_score(y_test, y_pred, pos_label=1, zero_division=0)

    # Confusion matrix with explicit label ordering: 0=Benign, 1=Attack.
    # Layout: [[TN, FP], [FN, TP]]
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])

    # ------------------------------------------------------------------
    # 6. Print results
    # ------------------------------------------------------------------
    print(f"\nRandom Forest Test Set Evaluation")
    print(f"  (positive class = 1 = Attack)\n")
    print(f"Test Samples : {len(X_test):,}")
    print(f"Accuracy     : {acc  * 100:.2f}%")
    print(f"Precision    : {prec * 100:.2f}%  (Attack class)")
    print(f"Recall       : {rec  * 100:.2f}%  (Attack class)")
    print(f"F1-Score     : {f1   * 100:.2f}%  (Attack class)")

    print("\nConfusion Matrix (rows=Actual, cols=Predicted):")
    print("  Labels: 0=Benign, 1=Attack")
    print(f"  [[TN={cm[0][0]:6d}, FP={cm[0][1]:6d}],")
    print(f"   [FN={cm[1][0]:6d}, TP={cm[1][1]:6d}]]")

    print("\nClassification Report:")
    print(classification_report(
        y_test, y_pred,
        labels=[0, 1],
        target_names=["Benign", "Attack"],
        zero_division=0
    ))

    # ------------------------------------------------------------------
    # 7. Feature importance from metadata (if available)
    # ------------------------------------------------------------------
    if meta_path.exists():
        try:
            with open(meta_path, "r", encoding="utf-8") as fh:
                meta = json.load(fh)
        except json.JSONDecodeError as exc:
            print(f"WARNING: metadata.json is invalid JSON: {exc}. "
                  "Feature importance cannot be displayed.")
            meta = {}

        fi = meta.get("feature_importance", {})
        if fi and isinstance(fi, dict):
            # Sort by importance descending before displaying.
            sorted_fi = sorted(fi.items(), key=lambda kv: kv[1], reverse=True)
            print("Top Feature Importances (Random Forest):")
            for feat, imp in sorted_fi[:7]:
                print(f"  {feat:20s}: {imp * 100:.2f}%")
        else:
            print("WARNING: Feature importance metadata is unavailable or empty.")
    else:
        print(f"WARNING: '{meta_path}' not found — feature importance metadata is unavailable.")

    print("=" * 60)


if __name__ == "__main__":
    evaluate()
