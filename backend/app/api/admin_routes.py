"""
Admin Portal API Endpoints for NetSentinel.
Accessible exclusively to users with 'admin' role.
Provides model version inspection, dataset management, retraining triggers, and version activation.
"""

import os
import json
import datetime
from typing import List, Optional


from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.database.models import User, Analysis, ModelVersion
from backend.app.auth.deps import get_current_admin
from backend.app.ml.model_loader import model_manager, MODELS_DIR
from backend.app.schemas.all_schemas import ModelVersionResponse, AdminDashboardResponse, RetrainRequest

router = APIRouter(prefix="/admin", tags=["Administrator"])

def ensure_model_versions_in_db(db: Session):
    """Syncs models directory metadata into database model_versions table."""
    if not os.path.exists(MODELS_DIR):
        return

    active_ver = model_manager.get_active_version_name()

    for item in os.listdir(MODELS_DIR):
        v_dir = os.path.join(MODELS_DIR, item)
        if os.path.isdir(v_dir) and item.startswith("v"):
            meta_path = os.path.join(v_dir, "metadata.json")
            if os.path.exists(meta_path):
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)

                    existing = db.query(ModelVersion).filter(ModelVersion.version == item).first()
                    is_active = (item == active_ver)

                    if existing:
                        existing.is_active = is_active
                    else:
                        m = meta.get("metrics", {})
                        new_rec = ModelVersion(
                            version=item,
                            trained_at=datetime.datetime.now(datetime.timezone.utc),
                            dataset_name=meta.get("dataset_name", "CIC-Bell-DNS-EXF-2021"),
                            sample_count=meta.get("training_samples", 0),
                            feature_count=meta.get("feature_count", 14),
                            accuracy=m.get("accuracy", 0.0),
                            precision=m.get("precision", 0.0),
                            recall=m.get("recall", 0.0),
                            f1_score=m.get("f1_score", 0.0),
                            is_active=is_active,
                            confusion_matrix=json.dumps(m.get("confusion_matrix", [])),
                            training_metadata=json.dumps(meta)
                        )
                        db.add(new_rec)
                    db.commit()
                except Exception as e:
                    print(f"Error syncing model {item}: {e}")

@router.get("/dashboard", response_model=AdminDashboardResponse)
def get_admin_dashboard(
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    ensure_model_versions_in_db(db)

    total_analyses = db.query(Analysis).count()
    total_users = db.query(User).count()
    versions = db.query(ModelVersion).order_by(ModelVersion.trained_at.desc()).all()
    active_m = db.query(ModelVersion).filter(ModelVersion.is_active == True).first()

    # Formatted versions
    ver_responses = []
    for v in versions:
        cm = json.loads(v.confusion_matrix) if v.confusion_matrix else []
        meta = json.loads(v.training_metadata) if v.training_metadata else {}
        ver_responses.append(ModelVersionResponse(
            id=v.id,
            version=v.version,
            trained_at=v.trained_at,
            dataset_name=v.dataset_name,
            sample_count=v.sample_count,
            feature_count=v.feature_count,
            accuracy=v.accuracy,
            precision=v.precision,
            recall=v.recall,
            f1_score=v.f1_score,
            is_active=v.is_active,
            confusion_matrix=cm,
            training_metadata=meta
        ))

    active_resp = None
    if active_m:
        active_resp = ModelVersionResponse(
            id=active_m.id,
            version=active_m.version,
            trained_at=active_m.trained_at,
            dataset_name=active_m.dataset_name,
            sample_count=active_m.sample_count,
            feature_count=active_m.feature_count,
            accuracy=active_m.accuracy,
            precision=active_m.precision,
            recall=active_m.recall,
            f1_score=active_m.f1_score,
            is_active=active_m.is_active,
            confusion_matrix=json.loads(active_m.confusion_matrix) if active_m.confusion_matrix else [],
            training_metadata=json.loads(active_m.training_metadata) if active_m.training_metadata else {}
        )

    # Dataset statistics — populated dynamically from processed_data.joblib so that
    # displayed counts always reflect what prepare_dataset.py actually processed.
    # Hard-coded row counts are NOT used here to avoid stale/fabricated values.
    dataset_stats = {
        "dataset_name": "CIC-Bell-DNS-EXF-2021",
        "archive_directory": "archive"
    }
    _data_file = os.path.join("data", "processed_data.joblib")
    if os.path.exists(_data_file):
        try:
            import joblib as _jl
            _ds = _jl.load(_data_file)
            _cd = _ds.get("class_distribution", {})
            dataset_stats.update({
                "source_file_count": _ds.get("source_file_count", "N/A"),
                "total_source_rows": _ds.get("total_source_rows", "N/A"),
                "sampled_rows":      _ds.get("sampled_rows", "N/A"),
                "total_benign":      _cd.get("total_benign", "N/A"),
                "total_attack":      _cd.get("total_attack", "N/A"),
                "train_samples":     _ds.get("train_samples", "N/A"),
                "test_samples":      _ds.get("test_samples", "N/A"),
            })
        except Exception:
            dataset_stats["note"] = "Processed data could not be read."
    else:
        dataset_stats["note"] = "Processed dataset not found — run scripts/prepare_dataset.py."


    return {
        "active_model": active_resp,
        "total_models": len(versions),
        "total_analyses_systemwide": total_analyses,
        "total_users": total_users,
        "dataset_stats": dataset_stats,
        "model_versions": ver_responses
    }

@router.get("/models", response_model=List[ModelVersionResponse])
def list_models(
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    ensure_model_versions_in_db(db)
    versions = db.query(ModelVersion).order_by(ModelVersion.trained_at.desc()).all()
    results = []
    for v in versions:
        results.append(ModelVersionResponse(
            id=v.id,
            version=v.version,
            trained_at=v.trained_at,
            dataset_name=v.dataset_name,
            sample_count=v.sample_count,
            feature_count=v.feature_count,
            accuracy=v.accuracy,
            precision=v.precision,
            recall=v.recall,
            f1_score=v.f1_score,
            is_active=v.is_active,
            confusion_matrix=json.loads(v.confusion_matrix) if v.confusion_matrix else [],
            training_metadata=json.loads(v.training_metadata) if v.training_metadata else {}
        ))
    return results

@router.post("/models/{version}/activate", response_model=ModelVersionResponse)
def activate_model_version(
    version: str,
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    target = db.query(ModelVersion).filter(ModelVersion.version == version).first()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Model version '{version}' not found.")

    success = model_manager.activate_version(version)
    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to activate model version '{version}'. Artifacts may be corrupted.")

    # Update database flags
    db.query(ModelVersion).update({ModelVersion.is_active: False})
    target.is_active = True
    db.commit()
    db.refresh(target)

    return ModelVersionResponse(
        id=target.id,
        version=target.version,
        trained_at=target.trained_at,
        dataset_name=target.dataset_name,
        sample_count=target.sample_count,
        feature_count=target.feature_count,
        accuracy=target.accuracy,
        precision=target.precision,
        recall=target.recall,
        f1_score=target.f1_score,
        is_active=target.is_active,
        confusion_matrix=json.loads(target.confusion_matrix) if target.confusion_matrix else [],
        training_metadata=json.loads(target.training_metadata) if target.training_metadata else {}
    )

@router.post("/retrain", response_model=ModelVersionResponse)
def trigger_retraining(
    req: RetrainRequest,
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """
    Executes actual retraining on the real dataset to produce a new model version.
    If retraining fails, the previous working model remains active.
    """
    import time
    import numpy as np
    import pandas as pd
    import joblib
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report

    # Determine next version name — scan for the highest existing vN and increment.
    # len() is fragile if versions are non-contiguous (e.g., v1, v3 after deleting v2).
    existing_nums = []
    if os.path.isdir(MODELS_DIR):
        for _d in os.listdir(MODELS_DIR):
            if _d.startswith("v") and os.path.isdir(os.path.join(MODELS_DIR, _d)):
                try:
                    existing_nums.append(int(_d[1:]))
                except ValueError:
                    pass
    next_num = (max(existing_nums) + 1) if existing_nums else 1
    new_version_name = f"v{next_num}"
    new_version_dir = os.path.join(MODELS_DIR, new_version_name)
    if os.path.exists(new_version_dir):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Version directory '{new_version_name}' already exists. Cannot overwrite."
        )

    data_file = os.path.join("data", "processed_data.joblib")
    if not os.path.exists(data_file):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Processed training dataset not found. Please run preparation first."
        )

    try:
        dataset = joblib.load(data_file)
        X_train = dataset["X_train"]
        X_test = dataset["X_test"]
        y_train = dataset["y_train"]
        y_test = dataset["y_test"]
        feature_names = dataset["feature_names"]

        # Train Random Forest
        rf = RandomForestClassifier(
            n_estimators=req.n_estimators or 100,
            max_depth=25,
            random_state=42 + next_num,
            n_jobs=-1
        )
        rf.fit(X_train, y_train)

        # Train Isolation Forest on benign baseline ONLY (attack samples excluded).
        X_train_benign = X_train[y_train == 0]
        if len(X_train_benign) == 0:
            raise ValueError("No benign training samples available for Isolation Forest.")
        iso = IsolationForest(
            n_estimators=100,
            contamination="auto",
            random_state=42 + next_num,
            n_jobs=-1
        )
        iso.fit(X_train_benign)

        train_scores = iso.score_samples(X_train_benign)
        iso_min = float(np.percentile(train_scores, 1))
        iso_max = float(np.percentile(train_scores, 99))

        # Evaluate on test set — pos_label=1 (Attack) explicit; labels=[0,1] for CM.
        y_pred = rf.predict(X_test)
        if 1 not in rf.classes_:
            raise ValueError("RF model classes_ does not contain Attack class (1).")
        acc  = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, pos_label=1, zero_division=0))
        rec  = float(recall_score(y_test, y_pred, pos_label=1, zero_division=0))
        f1   = float(f1_score(y_test, y_pred, pos_label=1, zero_division=0))
        cm   = confusion_matrix(y_test, y_pred, labels=[0, 1]).tolist()


        # Save artifacts to new version directory
        os.makedirs(new_version_dir, exist_ok=True)
        joblib.dump(rf, os.path.join(new_version_dir, "random_forest.joblib"))
        joblib.dump(iso, os.path.join(new_version_dir, "isolation_forest.joblib"))

        metadata = {
            "model_version": new_version_name,
            "trained_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "dataset_name": req.dataset_name or "CIC-Bell-DNS-EXF-2021",
            "training_samples": len(X_train),
            "test_samples": len(X_test),
            "feature_count": len(feature_names),
            "feature_names": feature_names,
            "metrics": {
                "accuracy": acc,
                "precision": prec,
                "recall": rec,
                "f1_score": f1,
                "confusion_matrix": cm
            },
            "isolation_forest_config": {
                "score_min": iso_min,
                "score_max": iso_max
            }
        }
        with open(os.path.join(new_version_dir, "metadata.json"), "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        # Register in database (inactive until explicitly activated or keep previous)
        new_mv = ModelVersion(
            version=new_version_name,
            trained_at=datetime.datetime.now(datetime.timezone.utc),
            dataset_name=metadata["dataset_name"],
            sample_count=len(X_train),
            feature_count=len(feature_names),
            accuracy=acc,
            precision=prec,
            recall=rec,
            f1_score=f1,
            is_active=False,
            confusion_matrix=json.dumps(cm),
            training_metadata=json.dumps(metadata)
        )
        db.add(new_mv)
        db.commit()
        db.refresh(new_mv)

        return ModelVersionResponse(
            id=new_mv.id,
            version=new_mv.version,
            trained_at=new_mv.trained_at,
            dataset_name=new_mv.dataset_name,
            sample_count=new_mv.sample_count,
            feature_count=new_mv.feature_count,
            accuracy=new_mv.accuracy,
            precision=new_mv.precision,
            recall=new_mv.recall,
            f1_score=new_mv.f1_score,
            is_active=new_mv.is_active,
            confusion_matrix=cm,
            training_metadata=metadata
        )

    except Exception as e:
        # KEEP PREVIOUS MODEL WORKING!
        print(f"Retraining failed: {e}. Preserving current working model.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Retraining failed: {str(e)}. Previous model version remains active and untouched."
        )

@router.post("/dataset/upload")
async def upload_training_dataset(
    file: UploadFile = File(...),
    current_admin: User = Depends(get_current_admin)
):
    """
    Allows admin to upload valid training dataset files.
    """
    if not file.filename.endswith((".csv", ".pcap.csv")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid dataset format. Only .csv and .pcap.csv files are accepted."
        )

    os.makedirs("uploads/custom_datasets", exist_ok=True)
    dest_path = os.path.join("uploads", "custom_datasets", file.filename)
    with open(dest_path, "wb") as f:
        content = await file.read()
        f.write(content)

    return {
        "status": "SUCCESS",
        "message": f"Dataset file '{file.filename}' uploaded successfully ({len(content):,} bytes). Ready for retraining.",
        "filepath": dest_path
    }
