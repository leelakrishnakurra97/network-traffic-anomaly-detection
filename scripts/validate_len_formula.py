"""
NetSentinel — Empirical 'len' Feature Validation Script
=========================================================
Validates the CIC-Bell-DNS-EXF-2021 stateless feature relationship:

    len == subdomain_length + sld_len + 1

where sld_len uses NetSentinel's project-level transformation:

    NaN → 0
    otherwise → len(str(sld).strip())

This transformation is the same one used in scripts/prepare_dataset.py.

Script properties:
    - READ-ONLY: archive/ is never modified.
    - All statistics are calculated dynamically; no values are hard-coded.
    - Exits with status 0 only if total_mismatches == 0.
    - Relative file paths are displayed for clarity.

Scientific wording:
    "The relationship was empirically validated across the checked
     CIC-Bell-DNS-EXF-2021 stateless rows using NetSentinel's sld_len
     transformation."

    This does NOT claim the formula is a universal DNS definition.
"""

import os
import sys
import pandas as pd
from pathlib import Path

# ---------------------------------------------------------------------------
# Robust path resolution — works from any working directory
# ---------------------------------------------------------------------------
SCRIPT_DIR  = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent          # CN_FINAL/
ARCHIVE_DIR = PROJECT_DIR / "archive"

REQUIRED_COLUMNS = ["sld", "subdomain_length", "len"]


def clean_sld(val) -> int:
    """
    Exact equivalent of the transformation used in scripts/prepare_dataset.py.

        NaN -> 0
        otherwise -> len(str(val).strip())

    NOTE: We do NOT use df["sld"].astype(str).apply(len) because that would
    convert NaN to the 4-character string 'nan' and count surrounding
    whitespace.
    """
    if pd.isna(val):
        return 0
    return len(str(val).strip())


def validate():
    if not ARCHIVE_DIR.exists():
        print(f"Error: Archive directory '{ARCHIVE_DIR}' not found.")
        sys.exit(1)

    print("=" * 70)
    print("NETSENTINEL - Empirical 'len' Feature Validation")
    print("Formula:  len == subdomain_length + sld_len + 1")
    print("(sld_len = len(str(sld).strip()), NaN -> 0)")
    print("=" * 70)

    total_rows    = 0
    total_matches = 0

    # Discover all stateless *.pcap.csv files recursively.
    stateless_files = []
    for root, _dirs, files in os.walk(ARCHIVE_DIR):
        for fname in sorted(files):
            if "stateless" in fname.lower() and fname.endswith(".pcap.csv"):
                stateless_files.append(Path(root) / fname)

    if not stateless_files:
        print("Error: No stateless *.pcap.csv files found in archive/.")
        sys.exit(1)

    print(f"Stateless files discovered: {len(stateless_files)}\n")

    for full_path in stateless_files:
        rel_path = str(full_path.relative_to(ARCHIVE_DIR)).replace("\\", "/")

        # Load CSV
        try:
            df = pd.read_csv(full_path, low_memory=False)
        except Exception as exc:
            print(f"Error: Cannot read '{rel_path}': {exc}")
            sys.exit(1)

        # Validate required columns
        missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
        if missing:
            print(f"Error: '{rel_path}' is missing required columns: {missing}")
            sys.exit(1)

        rows = len(df)
        if rows == 0:
            print(f"  {rel_path}: 0 rows — skipping.")
            continue

        # Apply the same sld_len transformation as prepare_dataset.py.
        sld_len_series = df["sld"].apply(clean_sld)

        # Convert subdomain_length and len to numeric (must not fail silently).
        subdomain_num = pd.to_numeric(df["subdomain_length"], errors="coerce")
        len_num       = pd.to_numeric(df["len"], errors="coerce")

        invalid_subdomain = int(subdomain_num.isna().sum())
        invalid_len       = int(len_num.isna().sum())

        if invalid_subdomain > 0 or invalid_len > 0:
            print(f"Error: '{rel_path}' has non-numeric values that cannot be validated:")
            if invalid_subdomain > 0:
                print(f"  'subdomain_length': {invalid_subdomain} invalid value(s)")
            if invalid_len > 0:
                print(f"  'len': {invalid_len} invalid value(s)")
            sys.exit(1)

        # Calculate expected len and compare.
        calculated_len  = subdomain_num + sld_len_series + 1
        mismatch_mask   = len_num != calculated_len
        mismatch_count  = int(mismatch_mask.sum())
        match_count     = rows - mismatch_count
        match_pct       = (match_count / rows * 100) if rows > 0 else 0.0

        total_rows    += rows
        total_matches += match_count

        print(f"  {rel_path}:")
        print(f"    {match_count:,} / {rows:,} rows match ({match_pct:.2f}%)")

        # Show a sample of mismatches if any (up to 10 rows).
        if mismatch_count > 0:
            sample_df = df[mismatch_mask].head(10).copy()
            sample_df["_sld_len_used"]    = sld_len_series[mismatch_mask].head(10)
            sample_df["_calculated_len"]  = calculated_len[mismatch_mask].head(10)
            sample_df["_actual_len"]      = len_num[mismatch_mask].head(10)
            sample_df["_difference"]      = (len_num - calculated_len)[mismatch_mask].head(10)
            display_cols = ["sld", "_sld_len_used", "subdomain_length", "_actual_len",
                            "_calculated_len", "_difference"]
            print(f"    [MISMATCH] {mismatch_count:,} mismatch(es) - sample (up to 10 rows):")
            print(sample_df[display_cols].to_string(index=True))
            print()

    # ------------------------------------------------------------------
    # Final summary
    # ------------------------------------------------------------------
    total_mismatches = total_rows - total_matches

    if total_rows == 0:
        print("\nError: No rows were found across all stateless files.")
        sys.exit(1)

    match_rate = (total_matches / total_rows * 100) if total_rows > 0 else 0.0

    print("\n" + "=" * 70)
    print("NETSENTINEL - EMPIRICAL 'len' FEATURE VALIDATION")
    print("=" * 70)
    print(f"Stateless files checked  : {len(stateless_files)}")
    print(f"Total rows checked       : {total_rows:,}")
    print(f"Total matches            : {total_matches:,}")
    print(f"Total mismatches         : {total_mismatches:,}")
    print(f"Empirical match rate     : {match_rate:.4f}%")
    print()

    if total_mismatches == 0:
        print("SUCCESS:")
        print("  The relationship 'len = subdomain_length + sld_len + 1' was empirically")
        print("  verified across all checked CIC-Bell-DNS-EXF-2021 stateless rows")
        print("  using NetSentinel's sld_len transformation.")
        print()
        print("  NOTE: This is an empirical observation on the current dataset.")
        print("  It is NOT claimed to be a universal DNS definition.")
        sys.exit(0)
    else:
        print("FAILURE:")
        print(f"  {total_mismatches:,} discrepancy(ies) were detected.")
        print("  Review the mismatch samples reported above.")
        sys.exit(1)


if __name__ == "__main__":
    validate()
