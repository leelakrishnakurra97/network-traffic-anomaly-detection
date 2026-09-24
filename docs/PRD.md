# NetSentinel — Product Requirements Document (PRD)

## 1. Product Overview

**NetSentinel** is an intelligent, end-to-end full-stack cybersecurity application for detecting DNS data exfiltration, covert tunneling, and malicious algorithmic domain patterns from raw network packet captures (`.pcap` / `.pcapng`).

- **Target Users**: Security Operations Center (SOC) analysts and system administrators
- **Core Problem**: Detecting DNS-based covert data exfiltration in enterprise networks
- **Training Data**: CIC-Bell-DNS-EXF-2021 (Canadian Institute for Cybersecurity)

---

## 2. MVP Features (In Scope)

### Authentication & Access Control
- [x] User registration with email + password
- [x] JWT-based login / logout
- [x] Role-Based Access Control: `user` (analyst) and `admin` roles
- [x] Protected routes on both frontend and backend

### PCAP Analysis
- [x] Upload `.pcap` and `.pcapng` files via the web UI
- [x] Native binary PCAP parser + Scapy-based fallback for reliable DNS query extraction
- [x] Extract 14 stateless structural DNS features per query
- [x] Reject non-DNS PCAPs (422 error) and corrupt files (400 error)

### ML Detection Engine
- [x] Random Forest Classifier — attack probability signal (55% weight)
- [x] Isolation Forest — unsupervised anomaly score (25% weight)
- [x] DNS Heuristic Rule Engine — structural security checks (20% weight)
- [x] Hybrid risk score: 0–100 scale with 4 risk levels (LOW / MODERATE / HIGH / CRITICAL)

### Dashboard & Reporting
- [x] Analysis history list with search and filtering
- [x] Detailed result page: risk gauge, feature breakdown, per-query table
- [x] Downloadable/viewable analysis summaries

### Admin Portal
- [x] View model metrics (accuracy, precision, recall, F1, confusion matrix)
- [x] List and activate different model versions
- [x] View dataset telemetry and user management

### Frontend UI
- [x] Cybersecurity dark-mode theme
- [x] Circular SVG risk gauge component
- [x] Statistical breakdown cards
- [x] Deep packet inspection query table

---

## 3. Out of Scope (Explicit Exclusions)

- Real-time live network traffic capture (offline PCAP only)
- DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) decryption
- Stateful features requiring WHOIS / ASN lookups or multi-session histories
- Email notifications or alerting integrations
- Multi-tenant organization management
- Mobile application

---

## 4. Non-Functional Requirements

| Requirement | Target |
|:---|:---|
| Attack Recall | >= 99% (current: 99.91%) |
| Risk Score Range | 0-100 (integer) |
| API Auth | JWT Bearer Token (1440 min expiry default) |
| Password Security | bcrypt hashing (no plaintext storage) |
| Test Coverage | Unit + integration tests via Pytest |

---

## 5. User Stories

| Role | Story |
|:---|:---|
| Analyst | Upload a .pcap file and see a risk score + classification within seconds |
| Analyst | View a history of all my previous analysis runs |
| Analyst | Drill into individual DNS query details for a specific analysis |
| Admin | View ML model performance metrics (precision, recall, F1) |
| Admin | Activate a different trained model version |
| Admin | See all registered users and manage accounts |
