# NetSentinel: CIC-Bell-DNS-EXF-2021 Dataset Documentation

## 1. Dataset Origin & Physical Storage

The Canadian Institute for Cybersecurity (CIC) published the **CIC-Bell-DNS-EXF-2021** dataset as a specialized cybersecurity benchmark for evaluating DNS data exfiltration and tunneling attacks across multiple file formats and bandwidth constraints.

- **Canonical Dataset Location**: `CN_FINAL/archive/` (Read-only reference training repository)
- **Directory Hierarchy**:
  ```
  CN_FINAL/archive/
  ├── Benign/
  ├── Attack_Light_Benign/
  │   ├── Attacks/
  │   └── Benign/
  └── Attack_heavy_Benign/
      ├── Attacks/
      └── Benign/
  ```
- **Physical Format**: 36 plaintext CSV files named with `.pcap.csv` extensions.
  - 18 stateless feature files (757,211 rows total)
  - 18 stateful feature files (262,105 rows total)

---

## 2. Target Label Formulation

Raw CSV files contain no explicit target label column. NetSentinel maps the ground-truth target deterministically from directory lineage:

- **$y = 0$ (Benign)**: All rows under `Benign/` directories.
- **$y = 1$ (Attack)**: All rows under `Attacks/` directories.

Attack scenarios (Heavy vs Light exfiltration bandwidths) are treated as contextual metadata and are not divided into arbitrary multi-class targets.

### Class Distribution (Stateless Corpus)
| Label | Category | Count | Percentage |
| :--- | :--- | :--- | :--- |
| **0** | Benign DNS | 462,858 | 61.13% |
| **1** | Attack (DNS Exfiltration / Tunneling) | 294,353 | 38.87% |
| **Total** | | **757,211** | **100.00%** |

---

## 3. Stateless vs. Stateful Feature Schemas

### Stateless Schema (15 Columns Discovered)
`['timestamp', 'FQDN_count', 'subdomain_length', 'upper', 'lower', 'numeric', 'entropy', 'special', 'labels', 'labels_max', 'labels_average', 'longest_word', 'sld', 'len', 'subdomain']`

### Stateful Schema (27 Columns Discovered)
`['rr', 'A_frequency', 'NS_frequency', 'CNAME_frequency', 'SOA_frequency', 'NULL_frequency', 'PTR_frequency', 'HINFO_frequency', 'MX_frequency', 'TXT_frequency', 'AAAA_frequency', 'SRV_frequency', 'OPT_frequency', 'rr_type', 'rr_count', 'rr_name_entropy', 'rr_name_length', 'distinct_ns', 'distinct_ip', 'unique_country', 'unique_asn', 'distinct_domains', 'reverse_dns', 'a_records', 'unique_ttl', 'ttl_mean', 'ttl_variance']`

---

## 4. Live PCAP Reproducibility & Data Leakage Prevention

### Excluded Features
1. **`timestamp`**: Dropped. Captures historical capture timestamps from Nov 2020. Using time would leak chronological batch ordering to the classifier.
2. **Directory & Filenames**: Never used as ML features.
3. **Stateful Features**: Excluded from live PCAP model. Stateful features depend on external WHOIS/ASN lookups (`unique_country`, `unique_asn`) or long-term historical windows (`ttl_variance`). User PCAP uploads may contain brief, isolated query traces without external IP reputation databases; fabricating missing stateful data would invalidate ML integrity.

### Engineered Structural Features (Project-Level Transformations)
1. **`sld` $\to$ `sld_len`**: In raw files, `sld` contains specific brand names (`google`, `amazon`) or attacker domains. Retaining raw tokens causes severe memorization leakage. NetSentinel defines `sld_len` as the character length of the extracted SLD to measure payload length while preventing brand memorization. This is an explicit project-level representation.
2. **`longest_word` $\to$ `longest_word_len`**: The official dataset defines `longest_word` as a categorical token string. NetSentinel engineers `longest_word_len` (character length of the longest alphanumeric token) as a project-level structural representation to preserve structural signal without memorizing vocabulary words.
3. **`len` (Empirically Validated Formula)**: While the official CIC-Bell documentation defines `len` as *"Length of domain and subdomain"*, empirical auditing across all 757,211 rows in `archive/` via `scripts/validate_len_formula.py` confirmed that:
   $$\text{len} \equiv \text{subdomain\_length} + \text{sld\_len} + 1 \quad (757,211 / 757,211 \text{ matches, } 100.0000\%)$$
   NetSentinel computes `len` strictly according to this empirically validated relationship.

### Final Live Feature Set (14 Features)
`FQDN_count`, `subdomain_length`, `upper`, `lower`, `numeric`, `entropy`, `special`, `labels`, `labels_max`, `labels_average`, `longest_word_len`, `sld_len`, `len`, `subdomain`.
All 14 features are directly extractable from standard DNS query packets using our Scapy / native binary PCAP extractor.
