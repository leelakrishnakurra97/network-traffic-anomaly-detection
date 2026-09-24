# NetSentinel — Project Memory (AI Context Snapshot)

> This file is the **single source of truth** for an AI assistant's understanding of this project.
> Keep it up to date after every major change. It answers: "what is this project, what has been built, and what are the key decisions made?"

---

## 1. What Is NetSentinel?

NetSentinel is a **full-stack cybersecurity web application** that analyzes `.pcap` / `.pcapng` network captures to detect **DNS-based data exfiltration** using machine learning.

- **Training Dataset**: CIC-Bell-DNS-EXF-2021 (757,211 rows, located in `archive/`)
- **Detection Approach**: Hybrid — Random Forest (55%) + Isolation Forest (25%) + DNS Heuristic Rules (20%)
- **Output**: A risk score (0–100) + classification (Benign / Attack) + per-query telemetry

---

## 2. Tech Stack (What's Actually Running)

| Layer | Technology |
|:---|:---|
| Backend API | FastAPI + Uvicorn, Python 3.12 |
| ORM + Database | SQLAlchemy + SQLite (`netsentinel.db`) |
| Auth | bcrypt password hashing + Python-Jose JWT |
| ML Models | scikit-learn `RandomForestClassifier` + `IsolationForest` |
| PCAP Parsing | Custom native binary parser + Scapy fallback |
| Frontend | React 18 + Vite 5 + Tailwind CSS 3 |
| HTTP Client | Axios with JWT interceptors |
| Icons | Lucide React |
| Testing | Pytest + FastAPI TestClient + HTTPX |

---

## 3. Current Project Status

**All core features are COMPLETE and working.** The project is in a post-MVP documentation and polish phase.

- Backend API: fully functional (auth, analysis, admin endpoints)
- ML models: trained and saved at `models/v1/` and `models/v2/`
- Frontend: all pages built (Landing, Login, Register, Dashboard, Upload, Result, History, Admin)
- Tests: full test suite passing
- Database: SQLite at project root (`netsentinel.db`)

---

## 4. Active Model

- **Active Version**: Check `models/active_version.json`
- **v1**: Trained on 120,000 samples from `archive/`; 99.91% recall, 75.25% accuracy
- **v2**: Exists in `models/v2/` (see its `metadata.json` for metrics)
- Models loaded at startup by `ModelManager` singleton in `backend/app/ml/model_loader.py`

---

## 5. The 14 DNS Features (Critical — Do Not Change Without Full Review)

These exact features are used in **both** `scripts/prepare_dataset.py` (training) and `backend/app/dns/` (inference). They must stay identical.

| # | Feature Name | Type | Description |
|:--|:---|:---|:---|
| 1 | `FQDN_count` | int | Total character length of full query domain |
| 2 | `subdomain_length` | int | Total length of subdomain portion |
| 3 | `upper` | int | Count of uppercase characters |
| 4 | `lower` | int | Count of lowercase characters |
| 5 | `numeric` | int | Count of digit characters |
| 6 | `entropy` | float | Shannon entropy of domain string |
| 7 | `special` | int | Count of `.`, `-`, `_` characters |
| 8 | `labels` | int | Number of dot-delimited labels |
| 9 | `labels_max` | int | Length of longest label |
| 10 | `labels_average` | float | Average label length |
| 11 | `longest_word_len` | int | Length of longest alphanumeric token |
| 12 | `sld_len` | int | Length of second-level domain |
| 13 | `len` | int | Character length of domain without TLD |
| 14 | `subdomain` | int | Binary: 1 if subdomain exists, else 0 |

**Excluded (data leakage prevention)**: `timestamp`, `sld` (raw string), `longest_word` (raw string), all 27 stateful features.

---

## 6. Risk Scoring Formula

```
Risk Score = round(100 × (0.55 × P_RF + 0.25 × S_IF + 0.20 × S_Rules))
```

| Component | Weight | Source |
|:---|:---|:---|
| `P_RF` | 55% | Random Forest attack probability (0.0–1.0) |
| `S_IF` | 25% | Isolation Forest normalized anomaly score (0.0–1.0) |
| `S_Rules` | 20% | Heuristic rule engine penalty score (0.0–1.0) |

Risk Levels: `0–29` LOW | `30–59` MODERATE | `60–79` HIGH | `80–100` CRITICAL

---

## 7. Directory Structure

```
CN_FINAL/
├── archive/                   # CIC-Bell-DNS-EXF-2021 dataset (read-only)
│   ├── Benign/
│   ├── Attack_Light_Benign/
│   └── Attack_heavy_Benign/
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI entrypoint + lifespan + CORS
│   │   ├── api/               # auth_routes.py, analysis_routes.py, admin_routes.py
│   │   ├── auth/              # jwt_handler.py, dependencies.py
│   │   ├── database/          # session.py, models.py (User, Analysis, ModelVersion)
│   │   ├── dns/               # extractor.py (native + Scapy parser + feature extraction)
│   │   ├── ml/                # model_loader.py, rule_engine.py, risk_scorer.py
│   │   └── schemas/           # Pydantic v2 models for requests/responses
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── App.jsx            # React Router setup
│   │   ├── main.jsx           # Vite entry
│   │   ├── index.css          # Global Tailwind + custom styles
│   │   ├── components/        # Navbar, Footer, RiskGauge, ProtectedRoute, etc.
│   │   ├── pages/             # LandingPage, LoginPage, RegisterPage, DashboardPage,
│   │   │                      # UploadPage, AnalysisResultPage, HistoryPage, AdminPage
│   │   ├── services/          # api.js (Axios instance + JWT interceptor)
│   │   └── context/           # AuthContext.jsx
│   ├── package.json
│   ├── vite.config.js
│   └── tailwind.config.js
├── models/
│   ├── active_version.json    # Controls which model version loads at startup
│   ├── v1/                    # random_forest.joblib, isolation_forest.joblib, metadata.json
│   └── v2/                    # Same structure as v1
├── scripts/
│   ├── explore_dataset.py     # Reads archive/, writes docs/dataset_exploration.md
│   ├── prepare_dataset.py     # Feature engineering + train/test split
│   ├── train_model.py         # Train RF + IF, save to models/vN/
│   ├── evaluate_model.py      # Standalone model evaluation
│   ├── validate_len_formula.py# Validates `len` feature formula correctness
│   └── test_pcapng_wireshark.py # PCAPNG format compatibility tests
├── docs/
│   ├── PRD.md                 # Product requirements
│   ├── ARCHITECTURE.md        # System architecture + DB schema + directory layout
│   ├── DESIGN.md              # UI/UX design system
│   ├── RULES.md               # Coding standards and dev rules
│   ├── TASKS.md               # Task breakdown and progress tracker
│   ├── MEMORY.md              # THIS FILE — AI context snapshot
│   ├── DATASET.md             # Dataset facts and statistics
│   ├── ML_PIPELINE.md         # ML training pipeline documentation
│   └── dataset_exploration.md # Auto-generated dataset exploration report
├── uploads/                   # Uploaded PCAP files (auto-created)
├── data/                      # Processed train/test data splits (auto-generated by scripts)
├── netsentinel.db             # SQLite database (auto-created on first run)
├── pytest.ini                 # Pytest configuration
└── README.md                  # Project overview + quickstart guide
```

---

## 8. Key Architectural Decisions (ADRs)

| Decision | Rationale |
|:---|:---|
| SQLite as default DB | Zero-config for development; easily swappable to Postgres via `DATABASE_URL` |
| Stateless features only | Prevents data leakage from timestamps/raw strings; enables live PCAP inference |
| Native binary PCAP parser | Avoids Scapy startup overhead; Scapy is fallback for edge-case formats |
| `ModelManager` as singleton | Load models once at startup, not per-request (performance critical) |
| 14 features frozen | Changing features invalidates all trained models — requires full retrain |
| JWT in localStorage | Acceptable for academic/demo; production should use httpOnly cookies |
| `allow_origins=["*"]` | Development convenience only; must be restricted in production |

---

## 9. How to Run the Project

```bash
# From project root (CN_FINAL/)

# 1. Start backend
python -m uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000

# 2. Start frontend (in a second terminal)
cd frontend && npm run dev

# 3. Run tests
python -m pytest backend/tests -v
```

**Default Credentials:**
- Admin: `admin@netsentinel.sec` / `AdminPassword@2026`
- Analyst: `analyst@netsentinel.sec` / `AnalystPassword@2026`

**URLs:**
- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- API Docs (Swagger): http://localhost:8000/docs

---

## 10. Things To Know Before Making Changes

1. **Feature count is sacred** — The 14 features in training must exactly match inference. Validate with `scripts/validate_len_formula.py`.
2. **Model versioning** — Always save new models to `models/vN+1/` and update `active_version.json`.
3. **Database migrations** — SQLAlchemy uses `create_all()` at startup; for schema changes, delete `netsentinel.db` and restart (dev only).
4. **CORS in production** — Change `allow_origins=["*"]` to explicit domains before deploying.
5. **Secrets** — JWT secret and passwords must be in `.env`, never in source code.
6. **Test before committing** — Run `python -m pytest backend/tests -v` and confirm all pass.
