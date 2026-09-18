# NetSentinel: System Architecture & Design

## 1. High-Level System Architecture

```
┌────────────────────────────────────────────────────────┐
│               React + Tailwind Frontend                │
│    (Dashboard, Upload, Report View, Admin Portal)      │
└───────────────────────────┬────────────────────────────┘
                            │ HTTP REST / JWT Bearer
                            ▼
┌────────────────────────────────────────────────────────┐
│                   FastAPI Backend                      │
│   ┌───────────────────┬────────────────────────────┐   │
│   │   Auth & RBAC     │     Analysis Router        │   │
│   │ (JWT, Bcrypt)     │   (PCAP Ingest & Save)     │   │
│   └─────────┬─────────┴─────────────┬──────────────┘   │
│             │                       │                  │
│             ▼                       ▼                  │
│   ┌───────────────────┐   ┌────────────────────────┐   │
│   │ SQLite / Postgres │   │  DNS Packet Extractor  │   │
│   │  Database Engine  │   │(Scapy / Binary Parser) │   │
│   └───────────────────┘   └─────────┬──────────────┘   │
│                                     │                  │
│                                     ▼                  │
│   ┌────────────────────────────────────────────────┐   │
│   │              Detection Subsystem               │   │
│   │   Random Forest  │ Isolation Forest │ Rules    │   │
│   │   P(Attack)      │ Anomaly Score    │ Penalty  │   │
│   └─────────────────────────┬──────────────────────┘   │
│                             ▼                          │
│   ┌────────────────────────────────────────────────┐   │
│   │           Hybrid Risk Scoring Engine           │   │
│   │            Risk Score: 0 to 100                │   │
│   └────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────┘
```

---

## 2. Directory Layout

```
CN_FINAL/
│
├── archive/                   # Canonical CIC-Bell-DNS-EXF-2021 Dataset (Read-only)
│   ├── Benign/
│   ├── Attack_Light_Benign/
│   └── Attack_heavy_Benign/
│
├── backend/                   # FastAPI Backend
│   ├── app/
│   │   ├── main.py            # Entrypoint, CORS, Lifespan initialization
│   │   ├── api/               # API routes (auth, analysis, admin)
│   │   ├── auth/              # JWT token handling, bcrypt password hashing, deps
│   │   ├── database/          # SQLAlchemy session, ORM models (User, Analysis, ModelVersion)
│   │   ├── dns/               # High-speed native & Scapy PCAP DNS feature extractor
│   │   ├── ml/                # ModelManager, RuleEngine, RiskScorer
│   │   └── schemas/           # Pydantic v2 data models
│   ├── requirements.txt
│   └── .env.example
│
├── frontend/                  # React + Vite + Tailwind CSS Frontend
│   ├── src/
│   │   ├── components/        # Navbar, Footer, RiskGauge, ProtectedRoute
│   │   ├── pages/             # Landing, Login, Register, Dashboard, Upload, Result, History, Admin
│   │   ├── services/          # Axios client with JWT interceptors
│   │   ├── context/           # AuthContext (state & tokens)
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
│
├── models/                    # Model Version Artifacts
│   ├── v1/                    # Active baseline model
│   │   ├── random_forest.joblib
│   │   ├── isolation_forest.joblib
│   │   └── metadata.json
│   └── active_version.json
│
├── scripts/                   # Data Exploration & ML Training
│   ├── explore_dataset.py     # Inspects archive/ and writes docs/dataset_exploration.md
│   ├── prepare_dataset.py     # Clean dataset, engineer features, create train/test split
│   ├── train_model.py         # Train RF + IF, evaluate real metrics, save models
│   └── evaluate_model.py      # Standalone model validation script
│
├── docs/                      # Architectural & Dataset Reports
│   ├── dataset_exploration.md
│   ├── DATASET.md
│   ├── ML_PIPELINE.md
│   └── ARCHITECTURE.md
│
├── uploads/                   # Upload storage & synthetic sample PCAPs
├── netsentinel.db             # Local SQLite database (or Postgres in prod)
├── pytest.ini
└── README.md
```

---

## 3. Database Schema

1. **`users` Table**:
   - `id`: Primary key (Integer)
   - `name`: String(120)
   - `email`: String(255), Unique index
   - `password_hash`: String(255)
   - `role`: String(50) — `'user'` or `'admin'`
   - `created_at`: DateTime (UTC)

2. **`analyses` Table**:
   - `id`: Primary key (Integer)
   - `user_id`: Foreign key $\to$ `users.id`
   - `filename`: Original capture name
   - `file_size`: File size in bytes
   - `upload_time`: DateTime
   - `status`: `'COMPLETED'` | `'FAILED'`
   - `predicted_class`: `'Benign'` | `'Attack'`
   - `risk_score`: Integer ($0 - 100$)
   - `risk_level`: String (`'LOW RISK'` | `'MODERATE RISK'` | `'HIGH RISK'` | `'CRITICAL THREAT'`)
   - `rf_probability`: Float
   - `if_anomaly_score`: Float
   - `rule_score`: Float
   - `rule_flags`: JSON text (list of triggered security heuristics)
   - `model_version`: String (`'v1'`)
   - `query_count`: Integer
   - `dns_features_summary`: JSON text (statistical feature averages)
   - `queries_detail`: JSON text (capped telemetry of individual query packets)

3. **`model_versions` Table**:
   - `id`: Primary key
   - `version`: String(50), Unique (`'v1'`, `'v2'`)
   - `trained_at`: DateTime
   - `dataset_name`: String
   - `sample_count`: Integer
   - `feature_count`: Integer
   - `accuracy`: Float
   - `precision`: Float
   - `recall`: Float
   - `f1_score`: Float
   - `is_active`: Boolean
   - `confusion_matrix`: JSON text
   - `training_metadata`: JSON text
