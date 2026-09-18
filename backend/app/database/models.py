"""
SQLAlchemy ORM Database Models for NetSentinel.

Three core entities:
    User         — Credentials and roles ('user' | 'admin').
    Analysis     — PCAP processing records with risk metrics and feature summaries.
    ModelVersion — Trained ML model catalog with evaluation metrics and active state.

Table names are stable and must not be renamed:
    users, analyses, model_versions

Constraints
-----------
CHECK constraints on risk_score, rf_probability, if_anomaly_score, rule_score,
file_size, query_count, and ModelVersion metrics are added at the SQLAlchemy
CheckConstraint level.  They are compatible with SQLite and PostgreSQL.

SQLite NOTE: SQLite does not enforce NOT NULL on existing rows during ALTER TABLE,
but CHECK constraints are enforced on INSERT/UPDATE from SQLAlchemy onwards once
the table is (re)created via init_db().

This file is a database model layer only.  Authentication, password hashing,
ML inference, risk scoring, PCAP parsing, and rule evaluation belong in other layers.
"""

import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text, Boolean, CheckConstraint
from sqlalchemy.orm import relationship
from backend.app.database.session import Base


class User(Base):
    __tablename__ = "users"

    id            = Column(Integer, primary_key=True, index=True)
    name          = Column(String(120), nullable=False)
    email         = Column(String(255), unique=True, index=True, nullable=False)
    # Only the password hash is stored here. Hashing belongs in the auth layer.
    password_hash = Column(String(255), nullable=False)
    # Allowed values: 'user' or 'admin'.  Validated at the application/auth layer.
    role          = Column(String(50), default="user", nullable=False)
    created_at    = Column(
        DateTime,
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        nullable=False
    )

    analyses = relationship("Analysis", back_populates="user", cascade="all, delete-orphan")

    __table_args__ = (
        # Database-level guard — role must be one of the two supported values.
        CheckConstraint("role IN ('user', 'admin')", name="ck_user_role"),
    )


class Analysis(Base):
    __tablename__ = "analyses"

    id             = Column(Integer, primary_key=True, index=True)
    user_id        = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    filename       = Column(String(255), nullable=False)
    # file_size is the uploaded file size in bytes; must not be negative.
    file_size      = Column(Integer, nullable=False)
    # upload_time — UTC-aware datetime at record creation.
    # FIXED: previously incorrectly defaulted to `datetime.timezone.utc` (a timezone object,
    # not a datetime value).  Now correctly uses a callable that returns the current UTC time.
    upload_time    = Column(
        DateTime,
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        nullable=False
    )
    # Valid values: COMPLETED, FAILED, PROCESSING.
    status          = Column(String(50), default="COMPLETED", nullable=False)
    # Valid values: 'Benign' or 'Attack' (exact casing preserved).
    predicted_class = Column(String(50), nullable=False)
    # risk_score: 0 to 100.
    risk_score      = Column(Integer, nullable=False)
    risk_level      = Column(String(50), nullable=False)
    # Normalized probability/score values in [0.0, 1.0].
    rf_probability  = Column(Float, nullable=False)
    if_anomaly_score = Column(Float, nullable=False)
    rule_score      = Column(Float, nullable=False)
    # JSON-encoded fields — stored as Text for SQLite/PostgreSQL compatibility.
    rule_flags           = Column(Text, default="[]",  nullable=False)
    model_version        = Column(String(50), default="v1", nullable=False)
    query_count          = Column(Integer, default=0,   nullable=False)
    dns_features_summary = Column(Text, default="{}",  nullable=False)
    queries_detail       = Column(Text, default="[]",  nullable=False)

    user = relationship("User", back_populates="analyses")

    __table_args__ = (
        CheckConstraint("status IN ('COMPLETED', 'FAILED', 'PROCESSING')",   name="ck_analysis_status"),
        CheckConstraint("predicted_class IN ('Benign', 'Attack')",           name="ck_analysis_predicted_class"),
        CheckConstraint("risk_score >= 0 AND risk_score <= 100",             name="ck_analysis_risk_score"),
        CheckConstraint("rf_probability >= 0.0 AND rf_probability <= 1.0",   name="ck_analysis_rf_probability"),
        CheckConstraint("if_anomaly_score >= 0.0 AND if_anomaly_score <= 1.0", name="ck_analysis_if_anomaly_score"),
        CheckConstraint("rule_score >= 0.0 AND rule_score <= 1.0",           name="ck_analysis_rule_score"),
        CheckConstraint("file_size >= 0",                                    name="ck_analysis_file_size"),
        CheckConstraint("query_count >= 0",                                  name="ck_analysis_query_count"),
    )


class ModelVersion(Base):
    __tablename__ = "model_versions"

    id       = Column(Integer, primary_key=True, index=True)
    version  = Column(String(50), unique=True, index=True, nullable=False)
    trained_at = Column(
        DateTime,
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        nullable=False
    )
    dataset_name   = Column(String(120), default="CIC-Bell-DNS-EXF-2021", nullable=False)
    # sample_count and feature_count are populated from actual training metadata.
    # No artificial defaults are provided.
    sample_count   = Column(Integer, nullable=False)
    feature_count  = Column(Integer, nullable=False)
    # Normalized evaluation metrics in [0.0, 1.0].  Must be real values from training.
    accuracy       = Column(Float, nullable=False)
    precision      = Column(Float, nullable=False)
    recall         = Column(Float, nullable=False)
    f1_score       = Column(Float, nullable=False)
    # is_active managed by ModelManager via models/active_version.json.
    # Do not create conflicting activation logic here.
    is_active      = Column(Boolean, default=False, nullable=False)
    # JSON-encoded fields.
    confusion_matrix    = Column(Text, default="[]", nullable=False)
    training_metadata   = Column(Text, default="{}", nullable=False)

    __table_args__ = (
        CheckConstraint("accuracy >= 0.0 AND accuracy <= 1.0",       name="ck_mv_accuracy"),
        CheckConstraint("precision >= 0.0 AND precision <= 1.0",      name="ck_mv_precision"),
        CheckConstraint("recall >= 0.0 AND recall <= 1.0",            name="ck_mv_recall"),
        CheckConstraint("f1_score >= 0.0 AND f1_score <= 1.0",        name="ck_mv_f1_score"),
        CheckConstraint("sample_count >= 0",                          name="ck_mv_sample_count"),
        CheckConstraint("feature_count >= 0",                         name="ck_mv_feature_count"),
    )
