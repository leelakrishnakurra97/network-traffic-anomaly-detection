# CIC-Bell-DNS-EXF-2021 Dataset Exploration Report

**Dataset Location**: `archive`

## 1. Executive Summary

- **Total Discovered Files**: 36
- **Stateless Feature Files**: 18
- **Stateful Feature Files**: 18
- **Total Stateless Rows**: 757,211
- **Total Stateful Rows**: 262,105
- **Stateless Class Balance**: Benign = 462,858 (61.13%), Attack = 294,353 (38.87%)

### Attack Scenario Breakdown (Stateless)

| Scenario | Row Count | Percentage |
| :--- | :--- | :--- |
| Attack (Heavy) | 251,670 | 33.24% |
| Attack (Light) | 42,683 | 5.64% |
| Benign (Heavy Benign) | 181,694 | 24.00% |
| Benign (Light Benign) | 60,091 | 7.94% |
| Benign (Pure Benign) | 221,073 | 29.20% |

## 2. File Format and Storage Observations

- **Naming convention**: All files have filenames ending with `.pcap.csv`.
- **Physical format**: Plaintext comma-delimited ASCII/UTF-8 CSV files, not raw binary PCAPs.
- **Source generator**: These CSVs were pre-extracted by the Canadian Institute for Cybersecurity (CIC) from original packet captures.
- **Label Column**: Neither stateless nor stateful files contain an in-band target column. Labels must be derived from folder placement (`Attacks` vs `Benign`).

## 3. Schema Consistency Analysis

### Stateless Schema Consistency (1 distinct schema found)

**Columns (15)**: `['timestamp', 'FQDN_count', 'subdomain_length', 'upper', 'lower', 'numeric', 'entropy', 'special', 'labels', 'labels_max', 'labels_average', 'longest_word', 'sld', 'len', 'subdomain']`

Found in 18 files:
- `Attack_heavy_Benign/Attacks/stateless_features-heavy_audio.pcap.csv`
- `Attack_heavy_Benign/Attacks/stateless_features-heavy_compressed.pcap.csv`
- `Attack_heavy_Benign/Attacks/stateless_features-heavy_exe.pcap.csv`
- `Attack_heavy_Benign/Attacks/stateless_features-heavy_image.pcap.csv`
- `Attack_heavy_Benign/Attacks/stateless_features-heavy_text.pcap.csv`
- `Attack_heavy_Benign/Attacks/stateless_features-heavy_video.pcap.csv`
- `Attack_heavy_Benign/Benign/stateless_features-benign_heavy_1.pcap.csv`
- `Attack_heavy_Benign/Benign/stateless_features-benign_heavy_2.pcap.csv`
- `Attack_heavy_Benign/Benign/stateless_features-benign_heavy_3.pcap.csv`
- `Attack_Light_Benign/Attacks/stateless_features-light_audio.pcap.csv`
- `Attack_Light_Benign/Attacks/stateless_features-light_compressed.pcap.csv`
- `Attack_Light_Benign/Attacks/stateless_features-light_exe.pcap.csv`
- `Attack_Light_Benign/Attacks/stateless_features-light_image.pcap.csv`
- `Attack_Light_Benign/Attacks/stateless_features-light_text.pcap.csv`
- `Attack_Light_Benign/Attacks/stateless_features-light_video.pcap.csv`
- `Attack_Light_Benign/Benign/stateless_features-light_benign.pcap.csv`
- `Benign/stateless_features-benign_1.pcap.csv`
- `Benign/stateless_features-benign_2.pcap.csv`

### Stateful Schema Consistency (1 distinct schema found)

**Columns (27)**: `['rr', 'A_frequency', 'NS_frequency', 'CNAME_frequency', 'SOA_frequency', 'NULL_frequency', 'PTR_frequency', 'HINFO_frequency', 'MX_frequency', 'TXT_frequency', 'AAAA_frequency', 'SRV_frequency', 'OPT_frequency', 'rr_type', 'rr_count', 'rr_name_entropy', 'rr_name_length', 'distinct_ns', 'distinct_ip', 'unique_country', 'unique_asn', 'distinct_domains', 'reverse_dns', 'a_records', 'unique_ttl', 'ttl_mean', 'ttl_variance']`

Found in 18 files:
- `Attack_heavy_Benign/Attacks/stateful_features-heavy_audio.pcap.csv`
- `Attack_heavy_Benign/Attacks/stateful_features-heavy_compressed.pcap.csv`
- `Attack_heavy_Benign/Attacks/stateful_features-heavy_exe.pcap.csv`
- `Attack_heavy_Benign/Attacks/stateful_features-heavy_image.pcap.csv`
- `Attack_heavy_Benign/Attacks/stateful_features-heavy_text.pcap.csv`
- `Attack_heavy_Benign/Attacks/stateful_features-heavy_video.pcap.csv`
- `Attack_heavy_Benign/Benign/stateful_features-benign_heavy_1.pcap.csv`
- `Attack_heavy_Benign/Benign/stateful_features-benign_heavy_2.pcap.csv`
- `Attack_heavy_Benign/Benign/stateful_features-benign_heavy_3.pcap.csv`
- `Attack_Light_Benign/Attacks/stateful_features-light_audio.pcap.csv`
- `Attack_Light_Benign/Attacks/stateful_features-light_compressed.pcap.csv`
- `Attack_Light_Benign/Attacks/stateful_features-light_exe.pcap.csv`
- `Attack_Light_Benign/Attacks/stateful_features-light_image.pcap.csv`
- `Attack_Light_Benign/Attacks/stateful_features-light_text.pcap.csv`
- `Attack_Light_Benign/Attacks/stateful_features-light_video.pcap.csv`
- `Attack_Light_Benign/Benign/stateful_features-_light_benign.pcap.csv`
- `Benign/stateful_features-benign_1.pcap.csv`
- `Benign/stateful_features-benign_2.pcap.csv`

## 4. File-by-File Inventory

| File | Kind | Scenario | Rows | Cols | Size (KB) | NaNs | Duplicates |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `Attack_heavy_Benign/Attacks/stateful_features-heavy_audio.pcap.csv` | stateful | Attack (Heavy) | 10,735 | 27 | 1202.3 | 0 | 10582 |
| `Attack_heavy_Benign/Attacks/stateful_features-heavy_compressed.pcap.csv` | stateful | Attack (Heavy) | 10,424 | 27 | 1170.6 | 0 | 10264 |
| `Attack_heavy_Benign/Attacks/stateful_features-heavy_exe.pcap.csv` | stateful | Attack (Heavy) | 9,980 | 27 | 1122.0 | 0 | 9829 |
| `Attack_heavy_Benign/Attacks/stateful_features-heavy_image.pcap.csv` | stateful | Attack (Heavy) | 11,076 | 27 | 1238.9 | 0 | 10934 |
| `Attack_heavy_Benign/Attacks/stateful_features-heavy_text.pcap.csv` | stateful | Attack (Heavy) | 18,916 | 27 | 2143.3 | 0 | 18718 |
| `Attack_heavy_Benign/Attacks/stateful_features-heavy_video.pcap.csv` | stateful | Attack (Heavy) | 10,897 | 27 | 1225.8 | 0 | 10731 |
| `Attack_heavy_Benign/Attacks/stateless_features-heavy_audio.pcap.csv` | stateless | Attack (Heavy) | 35,795 | 15 | 3273.7 | 0 | 43 |
| `Attack_heavy_Benign/Attacks/stateless_features-heavy_compressed.pcap.csv` | stateless | Attack (Heavy) | 35,746 | 15 | 3270.5 | 0 | 35 |
| `Attack_heavy_Benign/Attacks/stateless_features-heavy_exe.pcap.csv` | stateless | Attack (Heavy) | 34,629 | 15 | 3169.3 | 0 | 51 |
| `Attack_heavy_Benign/Attacks/stateless_features-heavy_image.pcap.csv` | stateless | Attack (Heavy) | 36,386 | 15 | 3328.9 | 0 | 39 |
| `Attack_heavy_Benign/Attacks/stateless_features-heavy_text.pcap.csv` | stateless | Attack (Heavy) | 71,102 | 15 | 6504.3 | 0 | 104 |
| `Attack_heavy_Benign/Attacks/stateless_features-heavy_video.pcap.csv` | stateless | Attack (Heavy) | 38,012 | 15 | 3479.3 | 0 | 68 |
| `Attack_heavy_Benign/Benign/stateful_features-benign_heavy_1.pcap.csv` | stateful | Benign (Heavy Benign) | 22,774 | 27 | 3060.7 | 0 | 6458 |
| `Attack_heavy_Benign/Benign/stateful_features-benign_heavy_2.pcap.csv` | stateful | Benign (Heavy Benign) | 19,660 | 27 | 2576.2 | 0 | 5746 |
| `Attack_heavy_Benign/Benign/stateful_features-benign_heavy_3.pcap.csv` | stateful | Benign (Heavy Benign) | 26,582 | 27 | 3560.7 | 0 | 7812 |
| `Attack_heavy_Benign/Benign/stateless_features-benign_heavy_1.pcap.csv` | stateless | Benign (Heavy Benign) | 61,567 | 15 | 5481.7 | 4 | 37 |
| `Attack_heavy_Benign/Benign/stateless_features-benign_heavy_2.pcap.csv` | stateless | Benign (Heavy Benign) | 49,115 | 15 | 4377.0 | 4 | 16 |
| `Attack_heavy_Benign/Benign/stateless_features-benign_heavy_3.pcap.csv` | stateless | Benign (Heavy Benign) | 71,012 | 15 | 6346.5 | 2 | 42 |
| `Attack_Light_Benign/Attacks/stateful_features-light_audio.pcap.csv` | stateful | Attack (Light) | 4,246 | 27 | 486.4 | 0 | 4127 |
| `Attack_Light_Benign/Attacks/stateful_features-light_compressed.pcap.csv` | stateful | Attack (Light) | 2,904 | 27 | 327.2 | 0 | 2798 |
| `Attack_Light_Benign/Attacks/stateful_features-light_exe.pcap.csv` | stateful | Attack (Light) | 1,836 | 27 | 206.9 | 0 | 1740 |
| `Attack_Light_Benign/Attacks/stateful_features-light_image.pcap.csv` | stateful | Attack (Light) | 143 | 27 | 16.5 | 0 | 97 |
| `Attack_Light_Benign/Attacks/stateful_features-light_text.pcap.csv` | stateful | Attack (Light) | 921 | 27 | 104.7 | 0 | 826 |
| `Attack_Light_Benign/Attacks/stateful_features-light_video.pcap.csv` | stateful | Attack (Light) | 1,245 | 27 | 140.4 | 0 | 1161 |
| `Attack_Light_Benign/Attacks/stateless_features-light_audio.pcap.csv` | stateless | Attack (Light) | 17,618 | 15 | 1612.9 | 0 | 2 |
| `Attack_Light_Benign/Attacks/stateless_features-light_compressed.pcap.csv` | stateless | Attack (Light) | 10,241 | 15 | 937.2 | 0 | 4 |
| `Attack_Light_Benign/Attacks/stateless_features-light_exe.pcap.csv` | stateless | Attack (Light) | 6,450 | 15 | 590.4 | 0 | 0 |
| `Attack_Light_Benign/Attacks/stateless_features-light_image.pcap.csv` | stateless | Attack (Light) | 524 | 15 | 48.3 | 0 | 0 |
| `Attack_Light_Benign/Attacks/stateless_features-light_text.pcap.csv` | stateless | Attack (Light) | 3,479 | 15 | 318.4 | 0 | 1 |
| `Attack_Light_Benign/Attacks/stateless_features-light_video.pcap.csv` | stateless | Attack (Light) | 4,371 | 15 | 400.2 | 0 | 3 |
| `Attack_Light_Benign/Benign/stateful_features-_light_benign.pcap.csv` | stateful | Benign (Light Benign) | 22,768 | 27 | 3048.3 | 0 | 6529 |
| `Attack_Light_Benign/Benign/stateless_features-light_benign.pcap.csv` | stateless | Benign (Light Benign) | 60,091 | 15 | 5351.4 | 4 | 8 |
| `Benign/stateful_features-benign_1.pcap.csv` | stateful | Benign (Pure Benign) | 52,438 | 27 | 6672.2 | 0 | 16022 |
| `Benign/stateful_features-benign_2.pcap.csv` | stateful | Benign (Pure Benign) | 34,560 | 27 | 4589.0 | 0 | 9600 |
| `Benign/stateless_features-benign_1.pcap.csv` | stateless | Benign (Pure Benign) | 132,499 | 15 | 11695.4 | 9 | 32 |
| `Benign/stateless_features-benign_2.pcap.csv` | stateless | Benign (Pure Benign) | 88,574 | 15 | 7884.0 | 8 | 41 |

## 5. Stateless Feature Data Types and Values

| Column | Observed Dtype | Sample Value | Live PCAP Compatible? | Rationale |
| :--- | :--- | :--- | :--- | :--- |
| `timestamp` | `object` | `2020-11-22 14:52:31.248351` | NO (EXCLUDE) | Data leakage: packet capture date/time. |
| `FQDN_count` | `int64` | `25` | YES (DIRECT) | Directly computable from DNS query string in PCAP packet. |
| `subdomain_length` | `int64` | `8` | YES (DIRECT) | Directly computable from DNS query string in PCAP packet. |
| `upper` | `int64` | `0` | YES (DIRECT) | Directly computable from DNS query string in PCAP packet. |
| `lower` | `int64` | `10` | YES (DIRECT) | Directly computable from DNS query string in PCAP packet. |
| `numeric` | `int64` | `9` | YES (DIRECT) | Directly computable from DNS query string in PCAP packet. |
| `entropy` | `float64` | `2.556641667147437` | YES (DIRECT) | Directly computable from DNS query string in PCAP packet. |
| `special` | `int64` | `6` | YES (DIRECT) | Directly computable from DNS query string in PCAP packet. |
| `labels` | `int64` | `6` | YES (DIRECT) | Directly computable from DNS query string in PCAP packet. |
| `labels_max` | `int64` | `7` | YES (DIRECT) | Directly computable from DNS query string in PCAP packet. |
| `labels_average` | `float64` | `3.333333333333333` | YES (DIRECT) | Directly computable from DNS query string in PCAP packet. |
| `longest_word` | `object` | `2` | TRANSFORM (Length) | Contains raw domain tokens (e.g., 'google', 'DESKTOP-3JF04TC'). Model would memorize specific strings. Transformed to length (`sld_len`, `longest_word_len`). |
| `sld` | `object` | `192` | TRANSFORM (Length) | Contains raw domain tokens (e.g., 'google', 'DESKTOP-3JF04TC'). Model would memorize specific strings. Transformed to length (`sld_len`, `longest_word_len`). |
| `len` | `int64` | `12` | YES (DIRECT) | Directly computable from DNS query string in PCAP packet. |
| `subdomain` | `int64` | `1` | YES (DIRECT) | Directly computable from DNS query string in PCAP packet. |

## 6. Stateful vs. Stateless Analysis for Live PCAP

- **Stateless Features**: 14 per-query numerical metrics (FQDN length, entropy, subdomain length, character composition). Fully reproducible from individual DNS packets extracted with Scapy.
- **Stateful Features**: 27 windowed metrics (`unique_country`, `unique_asn`, `distinct_ip`, `ttl_mean`, `ttl_variance`, `A_frequency`, etc.). These require either external WHOIS/GeoIP lookups or persistent aggregation over prolonged time windows. Because user-uploaded PCAPs may contain brief, isolated query captures without WHOIS enrichment, stateful features are excluded from the live prediction pipeline to avoid fabricating data.
