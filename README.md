# NETSENTINEL: Intelligent DNS Traffic Anomaly and Threat Detection System

## 1\. Project Overview

NETSENTINEL is a network security platform that uses machine learning and DNS traffic analysis to detect suspicious activities such as DNS tunneling, data exfiltration, and algorithmically generated domains. It analyzes PCAP and PCAPNG files and displays threat analysis results through a web-based dashboard.

## 2\. Problem Statement

DNS traffic can be exploited by attackers to transfer sensitive information, communicate with malicious servers, and bypass traditional security controls. Manual traffic analysis is time-consuming and may fail to identify hidden threats.

NETSENTINEL addresses this problem by combining machine learning, statistical feature extraction, and rule-based detection to identify suspicious DNS traffic and provide risk scores.

## 3\. Objectives

- Detect DNS-based attacks and abnormal traffic patterns.
- Analyze PCAP and PCAPNG network capture files.
- Use machine learning to classify suspicious DNS queries.
- Generate risk scores and threat classifications.
- Provide secure, role-based access for administrators and security analysts.
- Display analysis results through an interactive dashboard.
- Maintain analysis history and support security monitoring.

## 4\. Key Features and Modules

1. **PCAP File Analysis:** Upload and analyze network packet capture files.
2. **DNS Feature Extraction:** Extract domain length, entropy, label count, and other structural features.
3. **Machine Learning Detection:** Use Random Forest and Isolation Forest models to identify threats and anomalies.
4. **Rule-Based Detection:** Identify suspicious patterns such as high entropy, excessive label depth, and encoded domain strings.
5. **Risk Scoring:** Calculate a composite risk score and classify threats as low, moderate, high, or critical.
6. **Security Dashboard:** Display threat statistics, query analysis, risk levels, and detection results.
7. **Authentication and Authorization:** Provide JWT-based authentication, password hashing, and role-based access.
8. **Admin Portal:** Support model management, monitoring, and audit activities.
9. **Analysis Reports:** Present detection results for security investigation and review.

## 5\. Technology Stack

| Component | Technology |
| --- | --- |
| Frontend | React 18, Vite |
| Styling | Tailwind CSS |
| Backend | Python, FastAPI |
| Machine Learning | Scikit-learn |
| Data Processing | Pandas, NumPy |
| Packet Analysis | Scapy, Custom PCAP Parser |
| Database | SQLite, PostgreSQL compatible |
| Authentication | JWT, bcrypt |
| Testing | Pytest, HTTPX |
| API Documentation | Swagger UI |

## 6\. System Workflow

1. Upload a PCAP or PCAPNG file.
2. Extract DNS queries from captured packets.
3. Calculate structural and statistical DNS features.
4. Analyze the features using machine learning models and detection rules.
5. Generate a risk score and threat classification.
6. Display results on the security dashboard for investigation.

## 7\. Expected Outcomes

- Automated detection of suspicious DNS traffic.
- Faster identification of potential DNS tunneling and data exfiltration.
- Risk-based threat prioritization.
- Centralized traffic analysis and reporting.
- Improved visibility into network security threats.

## 8\. Limitations

- Detection accuracy depends on dataset quality and model performance.
- Encrypted DNS traffic may limit visibility into query details.
- False positives may require manual investigation.
- Real-time monitoring of live network traffic may require additional integration.

## 9\. Future Enhancements

- Real-time network traffic monitoring.
- Automated threat alerts through email and messaging services.
- Integration with SIEM platforms.
- Advanced threat visualization and forensic reporting.
- Continuous model improvement using newly collected data.

## 10\. Installation and Execution

**Prerequisites:** Python 3.10 or later, Node.js 18 or later, and npm.

### Backend Setup

Clone the repository and install dependencies:

```
git clone https://github.com/leelakrishnakurra97/network-traffic-anomaly-detection.git
cd network-traffic-anomaly-detection
pip install -r requirements.txt
```

Start the backend:

```
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

API documentation: `http://localhost:8000/docs`

### Frontend Setup

Open a separate terminal:

```
cd frontend
npm install
npm run dev
```

Frontend dashboard: `http://localhost:5173`

### Run Tests

```
python -m pytest backend/tests -v
```

## 11\. License

The project is described as being licensed under the MIT License. Verify that the repository includes the corresponding license file before redistribution.
