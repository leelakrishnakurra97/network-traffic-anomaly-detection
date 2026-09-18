"""
NETSENTINEL — Intelligent DNS Traffic Anomaly and Threat Detection System
FastAPI Main Application Entrypoint
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.database.session import init_db, SessionLocal
from backend.app.database.models import User
from backend.app.auth.jwt_handler import get_password_hash
from backend.app.api.auth_routes import router as auth_router
from backend.app.api.analysis_routes import router as analysis_router
from backend.app.api.admin_routes import router as admin_router, ensure_model_versions_in_db
from backend.app.ml.model_loader import model_manager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Initialize database tables
    print("NetSentinel Backend: Initializing database tables...")
    init_db()

    # 2. Seed default admin and user if not present
    db = SessionLocal()
    try:
        admin_user = db.query(User).filter(User.email == "admin@netsentinel.sec").first()
        if not admin_user:
            admin_user = User(
                name="Security Administrator",
                email="admin@netsentinel.sec",
                password_hash=get_password_hash("AdminPassword@2026"),
                role="admin"
            )
            db.add(admin_user)
            # NOTE: Default credentials are defined here for academic/demo use only.
            # In production, set ADMIN_EMAIL and ADMIN_PASSWORD as environment variables
            # and never commit credentials to source code.
            print("NetSentinel: Default admin account seeded (admin@netsentinel.sec).")

        analyst_user = db.query(User).filter(User.email == "analyst@netsentinel.sec").first()
        if not analyst_user:
            analyst_user = User(
                name="SOC Security Analyst",
                email="analyst@netsentinel.sec",
                password_hash=get_password_hash("AnalystPassword@2026"),
                role="user"
            )
            db.add(analyst_user)
            print("NetSentinel: Default analyst account seeded (analyst@netsentinel.sec).")


        db.commit()

        # 3. Synchronize trained model metadata into DB
        ensure_model_versions_in_db(db)
    finally:
        db.close()

    yield
    print("NetSentinel Backend: Shutting down...")

app = FastAPI(
    title="NetSentinel API",
    description="Intelligent DNS Traffic Anomaly and Threat Detection System REST API",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production specify trusted origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers
app.include_router(auth_router)
app.include_router(analysis_router)
app.include_router(admin_router)

@app.get("/")
def root():
    return {
        "system": "NETSENTINEL",
        "title": "Intelligent DNS Traffic Anomaly and Threat Detection System",
        "status": "OPERATIONAL",
        "active_model_version": model_manager.active_version,
        "docs_url": "/docs"
    }

@app.get("/health")
def health_check():
    return {
        "status": "HEALTHY",
        "model_loaded": model_manager.rf_model is not None and model_manager.iso_model is not None,
        "active_version": model_manager.active_version
    }
