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
├── archive/                        # CIC-Bell-DNS-EXF-2021 Dataset (Read-only)
│   ├── Benign/
│   ├── Attack_Light_Benign/
│   └── Attack_heavy_Benign/
│
├── backend/                        # FastAPI Backend
│   ├── app/
│   │   ├── main.py                 # Entrypoint, CORS, Lifespan initialization
│   │   ├── api/                    # Route handlers (auth, analysis, admin)
│   │   │   ├── auth_routes.py
│   │   │   ├── analysis_routes.py
│   │   │   └── admin_routes.py
│   │   ├── auth/                   # JWT token handling, bcrypt, dependency injection
│   │   ├── database/               # SQLAlchemy session, ORM models (User, Analysis, ModelVersion)
│   │   ├── dns/                    # Native binary + Scapy PCAP parser & DNS feature extractor
│   │   ├── ml/                     # ModelManager, RuleEngine, RiskScorer
│   │   └── schemas/                # Pydantic v2 request/response schemas
│   ├── requirements.txt
│   ├── .env.example
│   └── tests/                      # Pytest unit & integration tests
│
├── frontend/                       # React 18 + Vite 5 + Tailwind CSS 3
│   ├── src/
│   │   ├── App.jsx                 # React Router setup
│   │   ├── main.jsx                # Vite entry point
│   │   ├── index.css               # Global styles + Tailwind directives
│   │   ├── components/             # Navbar, Footer, RiskGauge, ProtectedRoute, etc.
│   │   ├── pages/                  # LandingPage, LoginPage, RegisterPage, UserDashboardPage,
│   │   │                           # PcapUploadPage, AnalysisResultPage, AnalysisHistoryPage,
│   │   │                           # AdminDashboardPage, AdminModelsPage, AdminTrainingPage
│   │   ├── services/               # api.js — Axios instance with JWT interceptors
│   │   └── context/                # AuthContext.jsx — global auth state
│   ├── package.json
│   ├── vite.config.js
│   ├── tailwind.config.js
│   └── .env.example
│
├── models/                         # Trained ML Model Artifacts
│   ├── active_version.json         # Controls which model loads at runtime
│   ├── v1/                         # Baseline model (99.91% recall)
│   │   ├── random_forest.joblib
│   │   ├── isolation_forest.joblib
│   │   └── metadata.json
│   └── v2/                         # Second model version
│       ├── random_forest.joblib
│       ├── isolation_forest.joblib
│       └── metadata.json
│
├── scripts/                        # Data Exploration & ML Training Utilities
│   ├── explore_dataset.py          # Inspect archive/, write docs/dataset_exploration.md
│   ├── prepare_dataset.py          # Feature engineering + train/test split → data/
│   ├── train_model.py              # Train RF + IF, save to models/vN/
│   ├── evaluate_model.py           # Standalone model evaluation
│   ├── validate_len_formula.py     # Validates `len` feature formula consistency
│   └── test_pcapng_wireshark.py    # PCAPNG format compatibility tests
│
├── docs/                           # Project Documentation
│   ├── PRD.md                      # Product requirements & user stories
│   ├── ARCHITECTURE.md             # THIS FILE — system design & DB schema
│   ├── DESIGN.md                   # UI/UX design system & color palette
│   ├── RULES.md                    # Coding standards & development rules
│   ├── TASKS.md                    # Task breakdown & progress tracker
│   ├── MEMORY.md                   # AI context snapshot (project memory)
│   ├── DATASET.md                  # Dataset facts & class balance statistics
│   ├── ML_PIPELINE.md              # ML training pipeline documentation
│   └── dataset_exploration.md      # Auto-generated dataset exploration report
│
├── data/                           # Processed train/test splits (auto-generated by scripts)
├── uploads/                        # Uploaded PCAP files (auto-created at runtime)
├── netsentinel.db                  # SQLite database (auto-created on first run)
├── pytest.ini                      # Pytest configuration
├── requirements.txt                # Python dependencies entrypoint
└── README.md                       # Project overview + quickstart guide
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
