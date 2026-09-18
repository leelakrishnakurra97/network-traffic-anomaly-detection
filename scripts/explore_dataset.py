"""
Dataset Exploration Script for NetSentinel
===========================================
Recursively explores CN_FINAL/archive/ without modifying any files.
Generates a comprehensive analysis report at docs/dataset_exploration.md.

This script is READ-ONLY with respect to archive/.
All statistics are calculated dynamically — no values are hard-coded.

NOTE: Labels are derived from folder placement because the source feature
CSV files do not contain an in-band target column.
    */Attacks/* → Attack (label = 1)
    */Benign/*  → Benign (label = 0)
"""

import os
import sys
import csv
import io
import pandas as pd
from pathlib import Path

# ---------------------------------------------------------------------------
# Robust path resolution — works from any working directory
# ---------------------------------------------------------------------------
SCRIPT_DIR   = Path(__file__).resolve().parent
PROJECT_DIR  = SCRIPT_DIR.parent          # CN_FINAL/
ARCHIVE_DIR  = PROJECT_DIR / "archive"
DOCS_DIR     = PROJECT_DIR / "docs"
REPORT_PATH  = DOCS_DIR / "dataset_exploration.md"

# Expected stateless schema (CIC-Bell-DNS-EXF-2021 source fields)
EXPECTED_STATELESS_SCHEMA = [
    "timestamp", "FQDN_count", "subdomain_length", "upper", "lower",
    "numeric", "entropy", "special", "labels", "labels_max",
    "labels_average", "longest_word", "sld", "len", "subdomain"
]

# Live 14-feature model representation (project-level engineered)
LIVE_FEATURES = [
    "FQDN_count", "subdomain_length", "upper", "lower", "numeric",
    "entropy", "special", "labels", "labels_max", "labels_average",
    "longest_word_len", "sld_len", "len", "subdomain"
]


def _derive_label_and_scenario(rel_path_str: str):
    """Derive label (0/1) and scenario from the relative file path."""
    norm = rel_path_str.replace("\\", "/")
    if "/Attacks/" in norm or norm.startswith("Attacks/"):
        label, label_str = 1, "Attack"
        if "heavy" in norm.lower():
            scenario = "Attack (Heavy)"
        elif "light" in norm.lower():
            scenario = "Attack (Light)"
        else:
            scenario = "Attack (General)"
    elif "/Benign/" in norm or norm.startswith("Benign/"):
        label, label_str = 0, "Benign"
        if "heavy" in norm.lower():
            scenario = "Benign (Heavy Benign)"
        elif "light" in norm.lower():
            scenario = "Benign (Light Benign)"
        else:
            scenario = "Benign (Pure Benign)"
    else:
        label, label_str = 0, "Benign"
        scenario = "Benign (Pure Benign)"
    return label, label_str, scenario


def _is_valid_csv(full_path: Path) -> bool:
    """Return True only if the file can be parsed as a plain-text CSV."""
    try:
        with open(full_path, "r", encoding="utf-8", errors="strict") as fh:
            sample = fh.read(512)
        reader = csv.reader(io.StringIO(sample))
        next(reader)   # at least one row (header)
        return True
    except (UnicodeDecodeError, StopIteration, csv.Error):
        return False


def explore_archive():
    if not ARCHIVE_DIR.exists():
        print(f"Error: Archive directory '{ARCHIVE_DIR}' not found!")
        sys.exit(1)

    DOCS_DIR.mkdir(parents=True, exist_ok=True)

    file_records        = []
    stateless_schemas   = {}
    stateful_schemas    = {}
    stateless_total_rows  = 0
    stateful_total_rows   = 0
    stateless_benign_rows = 0
    stateless_attack_rows = 0
    stateless_scenarios   = {}

    print(f"Scanning '{ARCHIVE_DIR}'...")

    for root, _dirs, files in os.walk(ARCHIVE_DIR):
        root_path = Path(root)
        for fname in sorted(files):
            full_path = root_path / fname
            if not full_path.is_file():
                continue

            rel_path     = full_path.relative_to(ARCHIVE_DIR)
            rel_path_str = str(rel_path).replace("\\", "/")
            file_size    = full_path.stat().st_size

            # Classify by filename
            fname_lower = fname.lower()
            if "stateless" in fname_lower:
                kind = "stateless"
            elif "stateful" in fname_lower:
                kind = "stateful"
            else:
                kind = "unknown"

            label, label_str, scenario = _derive_label_and_scenario(rel_path_str)

            # Determine if this is a valid CSV before attempting pandas parse
            if not fname.endswith(".pcap.csv"):
                is_valid_csv_file = False
            else:
                is_valid_csv_file = _is_valid_csv(full_path)

            # Read CSV for statistics (only for valid CSV files)
            num_rows = 0
            columns  = []
            num_cols = 0
            null_counts  = {}
            total_nulls  = 0
            dtypes       = {}
            dup_count    = 0
            dup_type     = "N/A"
            parse_error  = None

            if is_valid_csv_file:
                try:
                    df = pd.read_csv(full_path, low_memory=False)
                    num_rows = len(df)
                    columns  = list(df.columns)
                    num_cols = len(columns)
                    null_counts = df.isna().sum().to_dict()
                    total_nulls = int(sum(null_counts.values()))
                    dtypes = {col: str(dt) for col, dt in df.dtypes.items()}

                    # Duplicate strategy: exact for <150 000 rows; sampled for larger files.
                    if num_rows < 150_000:
                        dup_count = int(df.duplicated().sum())
                        dup_type  = "exact"
                    else:
                        dup_count = int(df.head(100_000).duplicated().sum())
                        dup_type  = "sampled (first 100k rows)"
                except Exception as exc:
                    parse_error = str(exc)
                    print(f"  [WARN] Could not parse '{rel_path_str}': {exc}")
            else:
                if fname.endswith(".pcap.csv"):
                    print(f"  [WARN] '{rel_path_str}' failed UTF-8 validation — skipped.")

            rec = {
                "file":        rel_path_str,
                "size_bytes":  file_size,
                "kind":        kind,
                "scenario":    scenario,
                "label":       label,
                "label_str":   label_str,
                "rows":        num_rows,
                "cols":        num_cols,
                "columns":     columns,
                "null_counts": {k: v for k, v in null_counts.items() if v > 0},
                "total_nulls": total_nulls,
                "duplicates":  dup_count,
                "dup_type":    dup_type,
                "dtypes":      dtypes,
                "valid_csv":   is_valid_csv_file,
                "parse_error": parse_error
            }
            file_records.append(rec)

            if kind == "stateless" and is_valid_csv_file and not parse_error:
                stateless_total_rows += num_rows
                if label == 1:
                    stateless_attack_rows += num_rows
                else:
                    stateless_benign_rows += num_rows
                stateless_scenarios[scenario] = stateless_scenarios.get(scenario, 0) + num_rows
                col_tuple = tuple(columns)
                stateless_schemas.setdefault(col_tuple, []).append(rel_path_str)
            elif kind == "stateful" and is_valid_csv_file and not parse_error:
                stateful_total_rows += num_rows
                col_tuple = tuple(columns)
                stateful_schemas.setdefault(col_tuple, []).append(rel_path_str)

            print(f"  [{kind.upper():9s}] {rel_path_str} → {num_rows:,} rows, {num_cols} cols, "
                  f"{total_nulls} NaNs, {dup_count} dups ({dup_type})")

    total_files    = len(file_records)
    stateless_files = [r for r in file_records if r["kind"] == "stateless"]
    stateful_files  = [r for r in file_records if r["kind"] == "stateful"]

    # ------------------------------------------------------------------
    # Guard: no stateless files discovered
    # ------------------------------------------------------------------
    if not stateless_files:
        print("WARNING: No stateless feature files were discovered.")

    # Guard against zero-division in class balance
    sl_total = stateless_total_rows
    benign_pct = (stateless_benign_rows / sl_total * 100) if sl_total > 0 else 0.0
    attack_pct = (stateless_attack_rows / sl_total * 100) if sl_total > 0 else 0.0

    # ------------------------------------------------------------------
    # Write Markdown Report
    # ------------------------------------------------------------------
    with open(REPORT_PATH, "w", encoding="utf-8") as out:
        out.write("# CIC-Bell-DNS-EXF-2021 Dataset Exploration Report\n\n")
        out.write(f"**Dataset Location**: `archive/`  \n")
        out.write(f"*All statistics below are calculated dynamically from the current archive contents.*\n\n")

        # --- 1. Executive Summary ---
        out.write("## 1. Executive Summary\n\n")
        out.write(f"- **Total Discovered Files**: {total_files}\n")
        out.write(f"- **Stateless Feature Files**: {len(stateless_files)}\n")
        out.write(f"- **Stateful Feature Files**: {len(stateful_files)}\n")
        out.write(f"- **Total Stateless Rows**: {sl_total:,}\n")
        out.write(f"- **Total Stateful Rows**: {stateful_total_rows:,}\n")
        if sl_total > 0:
            out.write(
                f"- **Stateless Class Balance**: "
                f"Benign = {stateless_benign_rows:,} ({benign_pct:.2f}%), "
                f"Attack = {stateless_attack_rows:,} ({attack_pct:.2f}%)\n\n"
            )
        else:
            out.write("- **Stateless Class Balance**: No stateless rows found.\n\n")

        out.write("### Attack Scenario Breakdown (Stateless)\n\n")
        if stateless_scenarios and sl_total > 0:
            out.write("| Scenario | Row Count | Percentage |\n")
            out.write("| :--- | :--- | :--- |\n")
            for sc, cnt in sorted(stateless_scenarios.items()):
                out.write(f"| {sc} | {cnt:,} | {cnt / sl_total * 100:.2f}% |\n")
        else:
            out.write("*No stateless data found.*\n")
        out.write("\n")

        # --- 2. File Format ---
        out.write("## 2. File Format and Storage Observations\n\n")
        out.write("- **Naming convention**: All feature files have filenames ending with `.pcap.csv`.\n")
        out.write("- **Physical format**: Plaintext comma-delimited CSV files (validated as "
                  "UTF-8 parseable). They are *not* raw binary PCAP captures.\n")
        out.write("- **Source generator**: These CSVs were pre-extracted by the Canadian Institute "
                  "for Cybersecurity (CIC) from original packet captures.\n")
        out.write("- **Label Column**: Neither stateless nor stateful files contain an in-band "
                  "target column. **Labels are derived from folder placement** "
                  "(`Attacks` → label 1, `Benign` → label 0).\n\n")

        # --- 3. Schema Consistency ---
        out.write("## 3. Schema Consistency Analysis\n\n")
        out.write(f"### Stateless Schema Consistency ({len(stateless_schemas)} distinct schema(s) found)\n\n")
        for cols, file_list in stateless_schemas.items():
            out.write(f"**Columns ({len(cols)})**: `{list(cols)}`\n\n")
            # Compare against expected
            obs  = list(cols)
            miss = [c for c in EXPECTED_STATELESS_SCHEMA if c not in obs]
            xtra = [c for c in obs if c not in EXPECTED_STATELESS_SCHEMA]
            if miss:
                out.write(f"⚠️ **Missing expected columns**: {miss}\n\n")
            if xtra:
                out.write(f"ℹ️ **Unexpected columns** (not in expected schema): {xtra}\n\n")
            if not miss and not xtra and obs == EXPECTED_STATELESS_SCHEMA:
                out.write("✅ Schema matches expected stateless schema exactly.\n\n")
            out.write(f"Found in {len(file_list)} file(s):\n")
            for fl in file_list:
                out.write(f"- `{fl}`\n")
            out.write("\n")

        out.write(f"### Stateful Schema Consistency ({len(stateful_schemas)} distinct schema(s) found)\n\n")
        for cols, file_list in stateful_schemas.items():
            out.write(f"**Columns ({len(cols)})**: `{list(cols)}`\n\n")
            out.write(f"Found in {len(file_list)} file(s):\n")
            for fl in file_list:
                out.write(f"- `{fl}`\n")
            out.write("\n")

        # --- 4. File-by-File Inventory ---
        out.write("## 4. File-by-File Inventory\n\n")
        out.write("| File | Kind | Scenario | Rows | Cols | Size (KB) | NaNs | Duplicates |\n")
        out.write("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
        for r in file_records:
            dup_label = f"{r['duplicates']} ({r['dup_type']})" if r["dup_type"] != "N/A" else "N/A"
            out.write(
                f"| `{r['file']}` | {r['kind']} | {r['scenario']} | "
                f"{r['rows']:,} | {r['cols']} | {r['size_bytes'] / 1024:.1f} | "
                f"{r['total_nulls']} | {dup_label} |\n"
            )
        out.write("\n")

        # --- 5. Stateless Feature Data Types ---
        out.write("## 5. Stateless Feature Data Types and Values\n\n")

        valid_stateless = [r for r in stateless_files if r["valid_csv"] and not r["parse_error"] and r["rows"] > 0]
        if valid_stateless:
            sample_rec = valid_stateless[0]
            sample_df  = pd.read_csv(
                str(ARCHIVE_DIR / sample_rec["file"]), nrows=100, low_memory=False
            )
            out.write(
                "| Column | Observed Dtype | Sample Value | Live PCAP Compatible? | Rationale |\n"
                "| :--- | :--- | :--- | :--- | :--- |\n"
            )
            for col in sample_df.columns:
                val   = str(sample_df[col].iloc[0]) if len(sample_df) > 0 else "N/A"
                dtype = str(sample_df[col].dtype)
                if col == "timestamp":
                    compat = "NO — EXCLUDED"
                    reason = "Temporal data leakage risk: packet capture date/time is excluded from the live 14-feature representation."
                elif col == "longest_word":
                    compat = "TRANSFORM → longest_word_len"
                    reason = ("Project-level feature engineering: the raw domain token is converted to its "
                              "character length. This avoids domain-string memorization and enables live PCAP compatibility.")
                elif col == "sld":
                    compat = "TRANSFORM → sld_len"
                    reason = ("Project-level feature engineering: the raw SLD token is converted to its "
                              "character length.  NaN → 0.")
                else:
                    compat = "YES — DIRECT"
                    reason = "Directly computable from DNS query string in a live PCAP packet."
                out.write(f"| `{col}` | `{dtype}` | `{val}` | {compat} | {reason} |\n")
            out.write("\n")
        else:
            out.write("*No valid stateless files found — data-type section cannot be generated.*\n\n")

        # --- 6. Stateful vs. Stateless for Live PCAP ---
        out.write("## 6. Stateful vs. Stateless Analysis for Live PCAP\n\n")
        out.write(
            "### Stateless Features\n"
            "The stateless 14-feature live representation is designed to be fully reproducible "
            "from individual DNS query strings extracted from live PCAP/PCAPNG files without "
            "requiring external data sources.\n\n"
            "**Source dataset fields** (15 columns including `timestamp`):\n"
            f"`{EXPECTED_STATELESS_SCHEMA}`\n\n"
            "**Live model representation** (14 numerical features, `timestamp` excluded):\n"
            f"`{LIVE_FEATURES}`\n\n"
            "**Feature engineering transformations** (project-level, NOT original CIC column names):\n"
            "- `longest_word` → `longest_word_len` (character length of the cleaned domain token)\n"
            "- `sld` → `sld_len` (character length of the second-level domain string; NaN → 0)\n\n"
            "### Stateful Features\n"
        )
        if stateful_schemas:
            first_key = next(iter(stateful_schemas))
            out.write(
                f"The stateful feature files contain {len(first_key)} columns and represent "
                "stateful/windowed DNS characteristics (e.g., per-IP query counts, TTL statistics, "
                "country/ASN diversity). These require persistent aggregation over time windows or "
                "external WHOIS/GeoIP enrichment that is not reliably available for arbitrary "
                "uploaded PCAPs.  Stateful features are therefore **excluded from the live "
                "NetSentinel prediction pipeline** to avoid fabricating missing context.\n"
            )
        else:
            out.write(
                "No stateful files were discovered in the current archive scan.\n"
            )
        out.write("\n")

    print(f"\nReport successfully generated at: {REPORT_PATH}")


if __name__ == "__main__":
    explore_archive()
