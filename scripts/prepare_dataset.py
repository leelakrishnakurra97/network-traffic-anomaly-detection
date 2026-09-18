"""
Dataset Preparation Script for NetSentinel
===========================================
Processes stateless feature CSV files from CN_FINAL/archive/.

Data leakage prevention:
    - Excludes timestamp, filenames, directory names, and identifiers.
    - Converts raw tokens 'sld' and 'longest_word' into structural length
      features (sld_len, longest_word_len) to avoid domain memorisation.
    - Derives binary label (0 = Benign, 1 = Attack) strictly from directory
      origin — NEVER from CSV content.
    - Performs stratified 80/20 train/test split (random_state=42).
    - Saves processed datasets to data/processed_data.joblib.

Source CSV files in archive/ are NEVER modified.
"""

import os
import sys
import time
import argparse
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
import joblib

# ---------------------------------------------------------------------------
# Robust path resolution — works from any working directory
# ---------------------------------------------------------------------------
SCRIPT_DIR  = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent          # CN_FINAL/
ARCHIVE_DIR = PROJECT_DIR / "archive"
OUTPUT_DIR  = PROJECT_DIR / "data"
OUTPUT_FILE = OUTPUT_DIR / "processed_data.joblib"

# Exact live feature representation — 14 numerical features in exact order.
FEATURE_COLUMNS = [
    "FQDN_count",
    "subdomain_length",
    "upper",
    "lower",
    "numeric",
    "entropy",
    "special",
    "labels",
    "labels_max",
    "labels_average",
    "longest_word_len",
    "sld_len",
    "len",
    "subdomain"
]

# Required source columns that must be present in every stateless CSV.
REQUIRED_SOURCE_COLUMNS = [
    "timestamp", "FQDN_count", "subdomain_length", "upper", "lower",
    "numeric", "entropy", "special", "labels", "labels_max",
    "labels_average", "longest_word", "sld", "len", "subdomain"
]

# Features that must NOT appear in the final X matrix (leakage guard).
LEAKAGE_COLUMNS = {
    "timestamp", "target", "filename", "file", "filepath",
    "directory", "scenario", "label", "label_str",
    "longest_word", "sld"
}


def clean_longest_word(val) -> int:
    """
    Convert the raw 'longest_word' source token to its character length.

    CIC source: string token (e.g., 'DESKTOP-3JF04TC').
    NetSentinel transformation: character length of the stripped string.

    NaN → 0
    '12345' → 5   (character length of the string, NOT the numeric value)
    'google' → 6
    """
    if pd.isna(val):
        return 0
    return len(str(val).strip())


def clean_sld(val) -> int:
    """
    Convert the raw 'sld' source token to its character length.

    NaN → 0
    'google' → 6
    """
    if pd.isna(val):
        return 0
    return len(str(val).strip())


def prepare_dataset(sample_size=150000, random_state=42):
    print("=" * 60)
    print("NETSENTINEL — Dataset Preparation Pipeline")
    print("=" * 60)

    # ------------------------------------------------------------------
    # Validate inputs
    # ------------------------------------------------------------------
    if sample_size is not None and sample_size < 0:
        print(f"Error: --sample-size must be >= 0 (got {sample_size}).")
        sys.exit(1)

    if not ARCHIVE_DIR.exists():
        print(f"Error: Archive directory '{ARCHIVE_DIR}' not found!")
        sys.exit(1)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # 1. Discover stateless feature files
    # ------------------------------------------------------------------
    stateless_files = []
    for root, _dirs, files in os.walk(ARCHIVE_DIR):
        for f in sorted(files):
            if "stateless" in f.lower() and f.endswith(".pcap.csv"):
                stateless_files.append(Path(root) / f)

    print(f"Discovered {len(stateless_files)} stateless feature file(s).")
    if not stateless_files:
        print("Error: No stateless feature files found in archive/.")
        sys.exit(1)

    # ------------------------------------------------------------------
    # 2. Load files with strict label derivation and column validation
    # ------------------------------------------------------------------
    dfs = []
    t0  = time.time()

    for full_path in stateless_files:
        norm_path = str(full_path).replace("\\", "/")
        rel_path  = str(full_path.relative_to(ARCHIVE_DIR)).replace("\\", "/")

        # Strict label derivation from directory only.
        if "/Attacks/" in norm_path or norm_path.replace(str(PROJECT_DIR).replace("\\", "/"), "").lstrip("/").startswith("archive/Attacks/"):
            is_attack = True
        else:
            is_attack = "/Attacks/" in norm_path
        # More robust: split on the archive-relative portion
        archive_rel = str(full_path.relative_to(ARCHIVE_DIR)).replace("\\", "/")
        if "/Attacks/" in archive_rel or archive_rel.startswith("Attacks/"):
            is_attack = True
        elif "/Benign/" in archive_rel or archive_rel.startswith("Benign/"):
            is_attack = False
        else:
            print(f"Error: Could not derive label for '{rel_path}'.")
            print(f"  File is not under an 'Attacks' or 'Benign' directory.")
            print("  Do not silently assign a label — stopping preparation.")
            sys.exit(1)

        label = 1 if is_attack else 0

        # Read CSV
        try:
            df = pd.read_csv(full_path, low_memory=False)
        except Exception as exc:
            print(f"Error: Cannot read '{rel_path}': {exc}")
            sys.exit(1)

        if len(df) == 0:
            print(f"Error: '{rel_path}' contains zero rows.")
            sys.exit(1)

        # Validate required columns
        missing_cols = [c for c in REQUIRED_SOURCE_COLUMNS if c not in df.columns]
        if missing_cols:
            print(f"Error: '{rel_path}' is missing required columns: {missing_cols}")
            print("Stopping preparation — do not train on incomplete data.")
            sys.exit(1)

        df["target"] = label
        dfs.append(df)
        print(f"  Loaded {len(df):,} rows from {rel_path} (Label={label}, {'Attack' if label else 'Benign'})")

    combined_df = pd.concat(dfs, ignore_index=True)
    t1 = time.time()
    print(f"\nTotal source rows loaded: {len(combined_df):,} in {t1 - t0:.2f}s")
    print(
        f"Source class distribution: "
        f"Benign (0) = {(combined_df['target'] == 0).sum():,} "
        f"({(combined_df['target'] == 0).mean() * 100:.2f}%), "
        f"Attack (1) = {(combined_df['target'] == 1).sum():,} "
        f"({(combined_df['target'] == 1).mean() * 100:.2f}%)"
    )

    # ------------------------------------------------------------------
    # 3. Optional stratified sampling
    # ------------------------------------------------------------------
    if sample_size is not None and sample_size > 0 and sample_size < len(combined_df):
        print(f"\nStratified sampling: {sample_size:,} rows (random_state={random_state})...")
        sample_df, _ = train_test_split(
            combined_df,
            train_size=sample_size,
            stratify=combined_df["target"],
            random_state=random_state
        )
    else:
        if sample_size and sample_size > len(combined_df):
            print(f"\nRequested sample_size ({sample_size:,}) >= available rows "
                  f"({len(combined_df):,}) — using full dataset.")
        sample_df = combined_df
    print(f"Sampled rows for processing: {len(sample_df):,}")

    # ------------------------------------------------------------------
    # 4. Feature engineering
    # ------------------------------------------------------------------
    print("\nApplying feature engineering (no source files are modified)...")
    print("  - Excluded 'timestamp' to prevent temporal leakage.")

    # Work on a copy to avoid modifying combined_df / source data.
    work_df = sample_df.copy()

    # Track original NaNs before numeric conversion
    orig_nan_counts = {col: int(work_df[col].isna().sum()) for col in FEATURE_COLUMNS
                       if col not in ("longest_word_len", "sld_len") and col in work_df.columns}

    # Transform longest_word → longest_word_len
    work_df["longest_word_len"] = work_df["longest_word"].apply(clean_longest_word)
    print("  - Transformed 'longest_word' → 'longest_word_len' (character length; avoids domain memorisation).")
    print("    NOTE: longest_word_len is a NetSentinel project-level engineered feature.")
    print("    It is NOT the original CIC 'longest_word' column.")

    # Transform sld → sld_len
    work_df["sld_len"] = work_df["sld"].apply(clean_sld)
    print("  - Transformed 'sld' → 'sld_len' (character length; NaN → 0).")
    print("    NOTE: sld_len is a NetSentinel project-level engineered feature.")
    print("    It is NOT the original CIC 'sld' column.")

    # ------------------------------------------------------------------
    # 5. Empirical len formula validation
    #    len == subdomain_length + sld_len + 1
    # ------------------------------------------------------------------
    print("\nValidating formula: len == subdomain_length + sld_len + 1 ...")
    calc_len = work_df["subdomain_length"].astype(float) + work_df["sld_len"].astype(float) + 1
    actual_len = pd.to_numeric(work_df["len"], errors="coerce")
    mismatch_mask = actual_len != calc_len
    mismatch_count = int(mismatch_mask.sum())
    if mismatch_count > 0:
        print(f"  ERROR: {mismatch_count:,} row(s) do not satisfy len == subdomain_length + sld_len + 1.")
        print("  Stopping preparation — do NOT silently overwrite 'len'.")
        print("  Review the dataset or the sld_len / subdomain_length transformation.")
        sys.exit(1)
    else:
        print(f"  ✓ Validation passed: all {len(work_df):,} rows satisfy the formula.")

    # ------------------------------------------------------------------
    # 6. Build final feature matrix X
    # ------------------------------------------------------------------
    X = work_df[FEATURE_COLUMNS].copy()

    # Convert all features to numeric; track conversion-generated NaNs separately.
    conv_nan_counts = {}
    for col in FEATURE_COLUMNS:
        before = int(X[col].isna().sum())
        X[col] = pd.to_numeric(X[col], errors="coerce")
        after = int(X[col].isna().sum())
        conv_nan_counts[col] = after - before
        if conv_nan_counts[col] > 0:
            print(f"  [WARN] Column '{col}': {conv_nan_counts[col]} value(s) failed numeric conversion (now NaN).")

    # Fill remaining NaNs with 0 (after reporting them).
    total_fill = int(X.isna().sum().sum())
    if total_fill > 0:
        print(f"  [INFO] Filling {total_fill} NaN value(s) with 0 in feature matrix.")
    X = X.fillna(0)

    # Validate feature order before proceeding.
    assert list(X.columns) == FEATURE_COLUMNS, (
        f"Feature order mismatch! Got {list(X.columns)}, expected {FEATURE_COLUMNS}"
    )

    # Leakage check — ensure no forbidden columns are in X.
    leaked = [c for c in X.columns if c in LEAKAGE_COLUMNS]
    if leaked:
        print(f"Error: Leakage columns detected in feature matrix: {leaked}")
        sys.exit(1)

    y = work_df["target"].astype(int).values
    print(f"\nFinal Feature Matrix X: {X.shape}, Target y: {y.shape}")

    # ------------------------------------------------------------------
    # 7. Validate class distribution before split
    # ------------------------------------------------------------------
    unique_y = set(y.tolist())
    if not {0, 1}.issubset(unique_y):
        print(f"Error: Both classes (0 and 1) must be present in training data. Found: {unique_y}")
        sys.exit(1)

    # ------------------------------------------------------------------
    # 8. Stratified 80/20 Train/Test split
    # ------------------------------------------------------------------
    print("Performing 80/20 stratified train/test split (random_state=42)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.20,
        stratify=y,
        random_state=random_state
    )

    # Verify both classes present in both splits.
    for split_name, y_split in [("train", y_train), ("test", y_test)]:
        unique_split = set(y_split.tolist())
        if not {0, 1}.issubset(unique_split):
            print(f"Error: {split_name} split is missing a class. Found: {unique_split}")
            sys.exit(1)

    train_benign = int((y_train == 0).sum())
    train_attack = int((y_train == 1).sum())
    test_benign  = int((y_test  == 0).sum())
    test_attack  = int((y_test  == 1).sum())

    print(f"  Training : {len(X_train):,} samples (Benign: {train_benign:,}, Attack: {train_attack:,})")
    print(f"  Testing  : {len(X_test):,}  samples (Benign: {test_benign:,},  Attack: {test_attack:,})")

    # Sanity check: totals must add up.
    assert train_benign + train_attack == len(X_train)
    assert test_benign  + test_attack  == len(X_test)

    # ------------------------------------------------------------------
    # 9. Save payload
    # ------------------------------------------------------------------
    payload = {
        "X_train":              X_train,
        "X_test":               X_test,
        "y_train":              y_train,
        "y_test":               y_test,
        "feature_names":        FEATURE_COLUMNS,
        "total_source_rows":    len(combined_df),
        "sampled_rows":         len(sample_df),
        "random_state":         random_state,
        "train_samples":        len(X_train),
        "test_samples":         len(X_test),
        "class_distribution": {
            "total_benign":  int((combined_df["target"] == 0).sum()),
            "total_attack":  int((combined_df["target"] == 1).sum()),
            "train_benign":  train_benign,
            "train_attack":  train_attack,
            "test_benign":   test_benign,
            "test_attack":   test_attack
        },
        # Useful metadata for traceability
        "dataset_name":         "CIC-Bell-DNS-EXF-2021",
        "sampling_enabled":     (sample_size is not None and sample_size > 0 and sample_size < len(combined_df)),
        "source_file_count":    len(stateless_files),
        "stateless_file_count": len(stateless_files),
        "feature_engineering_description": (
            "longest_word → longest_word_len (character length, NaN → 0); "
            "sld → sld_len (character length, NaN → 0); "
            "timestamp excluded (temporal leakage prevention)."
        ),
        "len_validation_mismatches": mismatch_count
    }

    joblib.dump(payload, OUTPUT_FILE)
    print(f"\nProcessed data saved to: {OUTPUT_FILE}")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Prepare CIC-Bell-DNS-EXF-2021 dataset for NetSentinel"
    )
    parser.add_argument(
        "--sample-size", type=int, default=150000,
        help="Number of rows to sample (default: 150000, 0 for all rows)"
    )
    args = parser.parse_args()
    sample_size = None if args.sample_size == 0 else args.sample_size
    prepare_dataset(sample_size=sample_size)
