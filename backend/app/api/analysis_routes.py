"""
Analysis API endpoints for NetSentinel.
Handles PCAP upload, DNS extraction, ML inference, rule engine, and history querying.
"""

import os
import json
import uuid
import datetime
import shutil
from typing import List, Optional
import numpy as np

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, status
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.database.models import User, Analysis
from backend.app.auth.deps import get_current_user
from backend.app.dns.pcap_extractor import extract_dns_from_pcap, NoDNSTrafficError, InvalidPCAPError
from backend.app.ml.model_loader import model_manager
from backend.app.ml.rule_engine import RuleEngine
from backend.app.ml.risk_scorer import RiskScorer
from backend.app.schemas.all_schemas import AnalysisResponse, AnalysisListItem, DashboardStats

router = APIRouter(prefix="/analysis", tags=["Analysis"])

UPLOAD_DIR = os.path.join("uploads", "user_uploads")
MAX_FILE_SIZE = 50 * 1024 * 1024 # 50 MB

rule_engine = RuleEngine()
risk_scorer = RiskScorer()

def format_analysis_response(analysis: Analysis) -> dict:
    rule_flags = json.loads(analysis.rule_flags) if analysis.rule_flags else []
    features_summary = json.loads(analysis.dns_features_summary) if analysis.dns_features_summary else {}
    queries_detail = json.loads(analysis.queries_detail) if analysis.queries_detail else []

    risk_breakdown = risk_scorer.compute_risk(
        analysis.rf_probability,
        analysis.if_anomaly_score,
        analysis.rule_score
    )

    return {
        "id": analysis.id,
        "filename": analysis.filename,
        "file_size": analysis.file_size,
        "upload_time": analysis.upload_time,
        "status": analysis.status,
        "predicted_class": analysis.predicted_class,
        "risk_score": analysis.risk_score,
        "risk_level": analysis.risk_level,
        "rf_probability": analysis.rf_probability,
        "if_anomaly_score": analysis.if_anomaly_score,
        "rule_score": analysis.rule_score,
        "rule_flags": rule_flags,
        "model_version": analysis.model_version,
        "query_count": analysis.query_count,
        "dns_features_summary": features_summary,
        "queries_detail": queries_detail,
        "risk_breakdown": risk_breakdown
    }

@router.post("/upload", response_model=AnalysisResponse, status_code=status.HTTP_201_CREATED)
async def upload_and_analyze_pcap(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # 1. Validate File Extension
    original_name = file.filename or "unknown.pcap"
    clean_name = os.path.basename(original_name)
    ext = os.path.splitext(clean_name)[1].lower()

    if ext not in [".pcap", ".pcapng"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file format. Only standard .pcap and .pcapng network capture files are supported."
        )

    # 2. Save Uploaded File Safely
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    unique_id = uuid.uuid4().hex[:10]
    safe_filename = f"{unique_id}_{clean_name}"
    saved_filepath = os.path.join(UPLOAD_DIR, safe_filename)

    file_size = 0
    with open(saved_filepath, "wb") as buffer:
        while chunk := await file.read(1024 * 1024):
            file_size += len(chunk)
            if file_size > MAX_FILE_SIZE:
                os.remove(saved_filepath)
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"File exceeds maximum allowed upload limit of {MAX_FILE_SIZE // (1024*1024)}MB."
                )
            buffer.write(chunk)

    # 3. Extract DNS Queries and Structural Features
    try:
        feature_df, query_records = extract_dns_from_pcap(saved_filepath)
    except NoDNSTrafficError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
    except InvalidPCAPError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Capture parsing error: {str(e)}")

    # 4. Run Random Forest and Isolation Forest Predictions
    try:
        ml_result = model_manager.predict(feature_df)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"ML inference failure: {str(e)}")

    # 5. Evaluate Rule Engine Heuristics
    rule_result = rule_engine.evaluate_batch(query_records)

    # 6. Compute Hybrid Risk Score
    risk_result = risk_scorer.compute_risk(
        rf_attack_probability=ml_result["rf_probability"],
        if_anomaly_score=ml_result["if_anomaly_score"],
        rule_score=rule_result["rule_score"]
    )

    # 7. Generate DNS Features Summary for UI display
    summary_metrics = {
        "avg_fqdn_length": round(float(feature_df["FQDN_count"].mean()), 1),
        "max_fqdn_length": int(feature_df["FQDN_count"].max()),
        "avg_subdomain_length": round(float(feature_df["subdomain_length"].mean()), 1),
        "max_subdomain_length": int(feature_df["subdomain_length"].max()),
        "avg_entropy": round(float(feature_df["entropy"].mean()), 2),
        "max_entropy": round(float(feature_df["entropy"].max()), 2),
        "avg_labels": round(float(feature_df["labels"].mean()), 1),
        "avg_numeric_chars": round(float(feature_df["numeric"].mean()), 1),
        "avg_special_chars": round(float(feature_df["special"].mean()), 1)
    }

    # Store query details (capped at first 100 queries for performance)
    capped_queries = []
    for idx, q_rec in enumerate(query_records[:100]):
        capped_queries.append({
            "packet_index": q_rec["packet_index"],
            "query": q_rec["query"],
            "qtype": q_rec["qtype"],
            "rf_prob": ml_result["per_query_rf"][idx] if idx < len(ml_result["per_query_rf"]) else 0.0,
            "if_score": ml_result["per_query_if"][idx] if idx < len(ml_result["per_query_if"]) else 0.0,
            "features": q_rec["features"]
        })

    # 8. Save Record to Database
    new_analysis = Analysis(
        user_id=current_user.id,
        filename=clean_name,
        file_size=file_size,
        upload_time=datetime.datetime.now(datetime.timezone.utc),
        status="COMPLETED",
        predicted_class=ml_result["predicted_class"],
        risk_score=risk_result["risk_score"],
        risk_level=risk_result["risk_level"],
        rf_probability=ml_result["rf_probability"],
        if_anomaly_score=ml_result["if_anomaly_score"],
        rule_score=rule_result["rule_score"],
        rule_flags=json.dumps(rule_result["triggered_rules"]),
        model_version=ml_result["model_version"],
        query_count=len(query_records),
        dns_features_summary=json.dumps(summary_metrics),
        queries_detail=json.dumps(capped_queries)
    )

    db.add(new_analysis)
    db.commit()
    db.refresh(new_analysis)

    return format_analysis_response(new_analysis)

@router.get("/history", response_model=List[AnalysisListItem])
def get_user_analysis_history(
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(Analysis).filter(Analysis.user_id == current_user.id)
    if search:
        query = query.filter(Analysis.filename.ilike(f"%{search}%"))
    analyses = query.order_by(Analysis.upload_time.desc()).limit(limit).all()
    return analyses

@router.get("/stats/user", response_model=DashboardStats)
def get_user_dashboard_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user_analyses = db.query(Analysis).filter(Analysis.user_id == current_user.id).all()
    total = len(user_analyses)
    attacks = sum(1 for a in user_analyses if a.predicted_class == "Attack" or a.risk_score >= 60)
    benign = sum(1 for a in user_analyses if a.predicted_class == "Benign" and a.risk_score < 60)
    anomalies = sum(1 for a in user_analyses if a.if_anomaly_score >= 0.5)
    avg_risk = float(np.mean([a.risk_score for a in user_analyses])) if total > 0 else 0.0

    recent = db.query(Analysis).filter(Analysis.user_id == current_user.id).order_by(Analysis.upload_time.desc()).limit(5).all()

    return {
        "total_analyses": total,
        "attacks_detected": attacks,
        "benign_analyses": benign,
        "anomalous_analyses": anomalies,
        "average_risk_score": round(avg_risk, 1),
        "recent_analyses": recent
    }

@router.get("/{analysis_id}", response_model=AnalysisResponse)
def get_analysis_detail(
    analysis_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis record not found.")

    # Only owner or admin can view
    if analysis.user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied to this analysis.")

    return format_analysis_response(analysis)
