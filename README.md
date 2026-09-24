# NETSENTINEL: Intelligent DNS Traffic Anomaly & Threat Detection System

NETSENTINEL is an end-to-end full-stack cybersecurity application built to detect DNS data exfiltration, covert tunneling, and malicious algorithmic domain patterns from raw network packet captures (`.pcap` and `.pcapng`).

The system is trained on the real **CIC-Bell-DNS-EXF-2021** dataset located in `archive/` and features a hybrid detection architecture combining supervised classification (Random Forest), unsupervised anomaly profiling (Isolation Forest), and DNS structural security heuristics.

---

## 1. Project Overview & Key Features

- **Real Machine Learning**: Trained directly on 120,000 real samples from the canonical `archive/` directory; tested on 30,000 unseen test samples.
- **99.91% Attack Recall**: High-sensitivity detection of stealthy exfiltration payloads (only 10 false negatives out of 11,662 attack test samples).
- **Dual-Mode Packet Ingestion**: Ultra-fast native binary PCAP/PCAPNG parser paired with Scapy for reliable UDP/TCP port 53 extraction.
- **100% Training/Inference Feature Compatibility**: Exactly 14 stateless structural DNS features extracted identically from live PCAP queries and training files.
- **Zero Domain Memorization**: Data leakage prevention eliminates raw domain tokens (`google`, `amazon`, attacker hashes) and timestamps, transforming them into structural length indicators (`sld_len`, `longest_word_len`).
- **Hybrid Multi-Signal Risk Engine**: Fuses Random Forest attack probabilities ($55\%$), Isolation Forest baseline anomaly scores ($25\%$), and DNS security heuristics ($20\%$) into an explainable $0-100$ threat risk score.
- **Role-Based Access Control (RBAC)**: Distinct permissions for Security Analysts and System Administrators with secure bcrypt hashing and JWT bearer authentication.
- **Administrator Portal**: Live model metrics, dataset telemetry, one-click model version activation, and retraining capabilities.
- **Cybersecurity Dark UI**: React 18, Vite, and Tailwind CSS dashboard with circular SVG risk gauges, statistical breakdown cards, and deep packet inspection tables.

---

## 2. Technology Stack

- **Backend**: Python 3.12, FastAPI, Uvicorn, SQLAlchemy, Pydantic v2
- **Machine Learning**: scikit-learn (`RandomForestClassifier`, `IsolationForest`), joblib, pandas, numpy
- **Packet Capture Processing**: Scapy & custom zero-dependency binary PCAP/PCAPNG packet parser
- **Authentication**: Native bcrypt password hashing, Python-Jose (JWT)
- **Database**: SQLite (built-in development default) with PostgreSQL support via `DATABASE_URL`
- **Frontend**: React 18, Vite, Tailwind CSS, Lucide React, Axios
- **Testing**: Pytest, FastAPI TestClient, HTTPX

---

## 3. Dataset Information

- **Name**: Canadian Institute for Cybersecurity (CIC) Bell DNS Exfiltration 2021 (`CIC-Bell-DNS-EXF-2021`)
- **Location**: `CN_FINAL/archive/` (Read-only reference training repository)
- **Physical Layout**: 36 files ending in `.pcap.csv`
  - 18 stateless feature files: **757,211 total rows**
  - 18 stateful feature files: **262,105 total rows**
- **Class Balance (Stateless Corpus)**:
  - **Benign ($y=0$)**: 462,858 rows ($61.13\%$)
  - **Attack ($y=1$)**: 294,353 rows ($38.87\%$)
- **Scenarios**: Heavy Attack ($33.2\%$), Light Attack ($5.6\%$), Pure Benign ($29.2\%$), Heavy Benign ($24.0\%$), Light Benign ($7.9\%$).

---

## 4. Live PCAP Features & Data Leakage Prevention

| Feature | Type | Description | Live PCAP Compatible? |
| :--- | :--- | :--- | :--- |
| `FQDN_count` | int | Total character length of full query domain | YES |
| `subdomain_length` | int | Total length of subdomain segments | YES |
| `upper` | int | Count of uppercase alphabetic characters | YES |
| `lower` | int | Count of lowercase alphabetic characters | YES |
| `numeric` | int | Count of numeric digits ($0-9$) | YES |
| `entropy` | float | Shannon entropy: $-\sum p_i \log_2(p_i)$ | YES |
| `special` | int | Count of special characters (`.`, `-`, `_`) | YES |
| `labels` | int | Number of dot-delimited labels in domain | YES |
| `labels_max` | int | Length of longest single label | YES |
| `labels_average` | float | Average character length across all labels | YES |
| `longest_word_len` | int | Length of longest alphanumeric token in domain | YES |
| `sld_len` | int | Length of Second-Level Domain | YES |
| `len` | int | Character length of domain without TLD | YES |
| `subdomain` | int | Binary indicator ($1$ if subdomain exists, $0$ otherwise) | YES |

### Excluded Features
- **`timestamp`**: Dropped to avoid chronology leakage.
- **`sld` & `longest_word` (Raw Strings)**: Converted to lengths (`sld_len`, `longest_word_len`) to prevent model from memorizing specific brand names.
- **Stateful Features (27 columns)**: Require WHOIS/ASN lookups (`unique_country`, `unique_asn`) or external multi-query histories (`ttl_variance`). Excluded from live PCAP model to prevent fabricating missing data.

---

## 5. Real Model Evaluation Results (Version v1)

Trained on 120,000 samples and evaluated on 30,000 unseen test samples:

- **Accuracy**: $75.25\%$
- **Precision**: $61.11\%$
- **Recall (Sensitivity)**: $99.91\%$
- **F1-Score**: $75.83\%$
- **Confusion Matrix**:
  ```
  [[10922,  7416],   <-- [TN, FP]
   [   10, 11652]]   <-- [FN, TP]
  ```
- **Top 5 Predictive Features**:
  1. `FQDN_count` ($24.59\%$)
  2. `labels` ($18.66\%$)
  3. `subdomain_length` ($13.84\%$)
  4. `special` ($13.06\%$)
  5. `sld_len` ($9.07\%$)

---

## 6. Hybrid Risk Scoring Engine

NetSentinel computes an explainable composite risk score:

$$\text{Risk Score} = \text{round}\left(100 \times \left(0.55 \cdot P_{\text{RF}} + 0.25 \cdot S_{\text{IF}} + 0.20 \cdot S_{\text{Rules}}\right)\right)$$

### Presentation Risk Levels
- **0 – 29**: **LOW RISK** (Standard benign DNS query profile)
- **30 – 59**: **MODERATE RISK** (Anomalous DNS patterns observed)
- **60 – 79**: **HIGH RISK** (Suspicious tunneling / exfiltration signatures)
- **80 – 100**: **CRITICAL THREAT** (Active high-confidence DNS exfiltration)

---

## 7. Installation & Quickstart

### Prerequisites
- Python 3.10+ (Tested on Python 3.12)
- Node.js 18+ and npm

### Backend Setup
```bash
# 1. Navigate to project root
cd network-traffic-anomaly-detection

# 2. Install backend Python dependencies
pip install -r requirements.txt

# 3. Explore archive and verify dataset integrity
python scripts/explore_dataset.py

# 4. Prepare dataset and train initial model (already pre-generated in models/v1)
python scripts/prepare_dataset.py
python scripts/train_model.py

# 5. Run backend server
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```
API Documentation will be live at: `http://localhost:8000/docs`.

### Frontend Setup
```bash
# 1. Navigate to frontend directory
cd frontend

# 2. Install npm dependencies
npm install

# 3. Start development server
npm run dev
```
Web application will be live at: `http://localhost:5173`.

---

## 8. Default Credentials

| Role | Email | Password |
| :--- | :--- | :--- |
| **System Administrator** | `admin@netsentinel.sec` | `AdminPassword@2026` |
| **Security Analyst** | `analyst@netsentinel.sec` | `AnalystPassword@2026` |

*Note: You can also register custom accounts via the `/register` page.*

---

## 9. Automated Testing

Run the comprehensive unit and integration test suite:

```bash
python -m pytest backend/tests -v
```

Tests cover:
- Authentication & JWT token generation
- Role-Based Access Control (403 Forbidden for non-admin users)
- Scapy & native binary PCAP parser
- Non-DNS PCAP rejection (422 Unprocessable Entity)
- Corrupt PCAP rejection (400 Bad Request)
- Random Forest & Isolation Forest prediction consistency
- Heuristic Rule Engine evaluations
- Hybrid risk score formula and boundaries

---

## 10. Known Protocol Limitations

- **Encrypted DNS**: Modern protocols like DNS-over-HTTPS (DoH, RFC 8484) and DNS-over-TLS (DoT, RFC 7858) encrypt DNS transactions inside TLS tunnels. NetSentinel analyzes standard plaintext DNS traffic extractable from port 53.
- **Stateful Features**: Stateful metrics requiring prolonged multi-day connection windows or real-time WHOIS lookups are excluded from the live PCAP model to prevent fabricating unobserved data.
