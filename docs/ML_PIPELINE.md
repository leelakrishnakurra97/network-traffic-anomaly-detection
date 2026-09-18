# NetSentinel: Machine Learning & Threat Detection Pipeline

## 1. Pipeline Overview

NetSentinel fuses supervised machine learning, unsupervised anomaly profiling, and domain security heuristics to achieve robust, explainable detection of DNS data exfiltration and tunneling.

```
[ Uploaded PCAP / PCAPNG ]
            │
            ▼
 [ Scapy / Native DNS Parser ] ──(Extracts UDP/TCP Port 53 queries)
            │
            ▼
[ 14 Structural DNS Features ] ──(FQDN len, entropy, subdomain len, etc.)
            │
   ┌────────┴────────────────────────┬─────────────────────────┐
   │                                 │                         │
   ▼                                 ▼                         ▼
[ Random Forest ]            [ Isolation Forest ]        [ Rule Engine ]
Supervised Learner           Anomaly Detector            Heuristic Engine
P(Attack) ∈ [0, 1]           S_IF ∈ [0, 1]               S_Rules ∈ [0, 1]
   │                                 │                         │
   └────────┬────────────────────────┴─────────────────────────┘
            │
            ▼
  [ Hybrid Risk Engine ]
  Risk Score = 100 × (0.55 × P_RF + 0.25 × S_IF + 0.20 × S_Rules)
            │
            ▼
[ Risk Level & SOC Telemetry ]
```

---

## 2. Supervised Learning: Random Forest

- **Algorithm**: `sklearn.ensemble.RandomForestClassifier`
- **Parameters**: `n_estimators=100`, `max_depth=25`, `random_state=42`, `n_jobs=-1`
- **Training Set**: 120,000 samples (73,352 Benign, 46,648 Attack)
- **Unseen Test Set**: 30,000 samples (18,338 Benign, 11,662 Attack)
- **Real Evaluation Metrics**:
  - **Accuracy**: 75.25%
  - **Precision**: 61.11%
  - **Recall**: 99.91% (11,652 out of 11,662 attacks detected)
  - **F1-Score**: 75.83%
  - **Confusion Matrix**:
    - True Negatives: 10,922
    - False Positives: 7,416
    - False Negatives: 10 (Only 0.09% missed)
    - True Positives: 11,652
- **Top 5 Predictive Features**:
  1. `FQDN_count` (24.59%)
  2. `labels` (18.66%)
  3. `subdomain_length` (13.84%)
  4. `special` (13.06%)
  5. `sld_len` (9.07%)

---

## 3. Unsupervised Anomaly Detection: Isolation Forest

- **Algorithm**: `sklearn.ensemble.IsolationForest`
- **Parameters**: `n_estimators=100`, `contamination='auto'`, `random_state=42`
- **Baseline Training**: Fitted strictly on normal benign DNS traffic ($X_{\text{train}}[y=0]$, 73,352 samples).
- **Normalization Formula**:
  Isolation Forest outputs raw decision values where lower (negative) values indicate anomalous outliers. NetSentinel normalizes this onto $[0.0, 1.0]$:
  $$S_{\text{IF}} = \text{clip}\left(\frac{\text{score\_max} - s}{\text{score\_max} - \text{score\_min}}, 0.0, 1.0\right)$$
  - $S_{\text{IF}} \to 0.0$: Typical normal DNS query.
  - $S_{\text{IF}} \to 1.0$: Deep anomaly compared to the benign baseline.

---

## 4. Heuristic DNS Rule Engine

Configurable project heuristics detecting structural exfiltration signatures:
1. **`RULE_HIGH_ENTROPY`** (Weight 0.25): Domain Shannon entropy $> 3.8$ (indicates encryption or base64).
2. **`RULE_LONG_SUBDOMAIN`** (Weight 0.25): Subdomain length $> 30$ chars (indicates chunked exfiltration payload).
3. **`RULE_HIGH_NUMERIC_RATIO`** (Weight 0.15): Numeric characters $> 40\%$ of domain string.
4. **`RULE_HEX_BASE32_ENCODING`** (Weight 0.20): Hexadecimal $(\ge 16\text{ chars})$ or Base32 $(\ge 20\text{ chars})$ continuous blocks.
5. **`RULE_DEEP_LABEL_HIERARCHY`** (Weight 0.15): Label count $> 5$.

Normalized Rule Penalty:
$$S_{\text{Rules}} = \min\left(1.0, \sum \text{triggered\_weights}\right)$$

---

## 5. Hybrid Composite Risk Formula

The composite risk score balances supervised pattern recognition, baseline anomaly deviation, and deterministic security heuristics:

$$\text{Risk Score} = \text{round}\left(100 \times \left(0.55 \cdot P_{\text{RF}} + 0.25 \cdot S_{\text{IF}} + 0.20 \cdot S_{\text{Rules}}\right)\right)$$

### Presentation Levels
- **$0 - 29$**: LOW RISK (Normal benign DNS traffic)
- **$30 - 59$**: MODERATE RISK (Anomalous DNS patterns observed)
- **$60 - 79$**: HIGH RISK (Suspicious DNS tunneling signatures detected)
- **$80 - 100$**: CRITICAL THREAT (Active high-confidence DNS exfiltration)
