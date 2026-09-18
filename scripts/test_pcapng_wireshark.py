"""
NetSentinel PCAPNG Parsing Verification Script
================================================
Verifies the complete live pipeline using actual Wireshark-generated PCAPNG files.

PIPELINE UNDER TEST:
    PCAPNG → NetSentinel parser → DNS queries → 14 live features
    → Random Forest + Isolation Forest (model v1)
    → Rule Engine → Hybrid Risk Score

IMPORTANT:
    - This script does NOT retrain any model.
    - This script does NOT modify any model artifact.
    - This script does NOT modify PCAPNG files.
    - This script does NOT modify archive/ or database records.
    - This script verifies functional compatibility ONLY.
    - It does NOT measure classifier accuracy, precision, recall, or F1.
    - A successful run does NOT prove the model is accurate.

Model loading:
    ModelManager is initialised and v1 is loaded directly.
    active_version.json is NOT modified.
"""

import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Robust path resolution
# ---------------------------------------------------------------------------
SCRIPT_DIR     = Path(__file__).resolve().parent
WORKSPACE_ROOT = SCRIPT_DIR.parent          # CN_FINAL/
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from backend.app.dns.pcap_extractor import (
    extract_dns_with_telemetry,
    FEATURE_COLUMNS,
    InvalidPCAPError,
    NoDNSTrafficError
)
from backend.app.ml.model_loader import ModelManager
from backend.app.ml.rule_engine import RuleEngine
from backend.app.ml.risk_scorer import RiskScorer

# Expected live feature representation (14 features, exact order).
EXPECTED_FEATURES = [
    "FQDN_count", "subdomain_length", "upper", "lower", "numeric",
    "entropy", "special", "labels", "labels_max", "labels_average",
    "longest_word_len", "sld_len", "len", "subdomain"
]

# RF classification threshold (project-defined; not a universal security threshold).
RF_ATTACK_THRESHOLD = 0.5


def run_verification(filepath: str, test_title: str) -> dict:
    """
    Run the full live pipeline on a single PCAPNG file and return a result dict.
    A failure in one step is reported but execution continues to gather all info.
    """
    result = {
        "title":               test_title,
        "file":                filepath,
        "file_exists":         False,
        "file_format":         "unknown",
        "endian":              "unknown",
        "interfaces":          [],
        "packets_processed":   0,
        "dns_packets":         0,
        "queries_extracted":   0,
        "feature_rows":        0,
        "feature_schema_valid": False,
        "extraction_ok":       False,
        "model_version":       "N/A",
        "model_success":       False,
        "risk_success":        False,
        "errors":              []
    }

    print("=" * 80)
    print(f"TEST: {test_title}")
    print(f"File: {filepath}")

    # ------------------------------------------------------------------
    # 1. File existence check
    # ------------------------------------------------------------------
    if not os.path.isfile(filepath):
        msg = f"FAILED — file not found: {filepath}"
        print(msg)
        result["errors"].append(msg)
        print("=" * 80 + "\n")
        return result

    result["file_exists"] = True
    print(f"Size: {os.path.getsize(filepath):,} bytes")
    print("=" * 80)

    # ------------------------------------------------------------------
    # 2. DNS extraction with telemetry
    # ------------------------------------------------------------------
    feature_df    = None
    query_records = None
    telemetry     = {}

    try:
        feature_df, query_records, telemetry = extract_dns_with_telemetry(filepath)
        result["extraction_ok"] = True
    except InvalidPCAPError as exc:
        msg = f"Extraction: FAILED (InvalidPCAPError) — {exc}"
        print(msg)
        result["errors"].append(msg)
    except NoDNSTrafficError as exc:
        msg = f"Extraction: FAILED (NoDNSTrafficError) — {exc}"
        print(msg)
        result["errors"].append(msg)
    except Exception as exc:
        msg = f"Extraction: FAILED (unexpected) — {exc}"
        print(msg)
        result["errors"].append(msg)

    # Populate telemetry fields regardless of success
    result["file_format"]       = telemetry.get("format", "unknown")
    result["endian"]            = telemetry.get("endian", "unknown")
    result["interfaces"]        = telemetry.get("interfaces", [])
    result["packets_processed"] = telemetry.get("packets_processed", 0)
    result["dns_packets"]       = telemetry.get("dns_packets", 0)

    if result["extraction_ok"] and feature_df is not None and query_records is not None:
        result["queries_extracted"] = len(query_records)
        result["feature_rows"]      = len(feature_df)

        # Validate feature row count == query record count.
        if len(feature_df) != len(query_records):
            msg = (f"Feature schema: FAILED — feature_df rows ({len(feature_df)}) "
                   f"!= query_records ({len(query_records)})")
            print(msg)
            result["errors"].append(msg)
            result["extraction_ok"] = False

    print(f"- Format detected      : {result['file_format']}")
    print(f"- Endian detected      : {result['endian']}")

    # Interface summary — handle 0 or multiple interfaces safely.
    interfaces = result["interfaces"]
    if interfaces:
        for intf in interfaces:
            print(f"  Interface ID {intf.get('id', '?')}: "
                  f"LinkType={intf.get('linktype', '?')} ({intf.get('linktype_name', '?')}), "
                  f"tsresol_scale={intf.get('tsresol_scale', '?')}")
    else:
        print("- Interfaces           : None detected")

    print(f"- Packets processed    : {result['packets_processed']}")
    print(f"- DNS packets          : {result['dns_packets']}")
    print(f"- Queries extracted    : {result['queries_extracted']}")
    print(f"- Feature rows         : {result['feature_rows']}")

    # Extraction status
    if result["extraction_ok"]:
        print("- Extraction           : PASS")
    else:
        print("- Extraction           : FAIL")

    if not result["extraction_ok"] or feature_df is None:
        print("- Feature schema       : SKIPPED (extraction failed)")
        print("- Model v1             : SKIPPED")
        print("- Risk scoring         : SKIPPED")
        print("=" * 80 + "\n")
        return result

    # ------------------------------------------------------------------
    # 3. Feature schema validation
    # ------------------------------------------------------------------
    observed_cols = list(feature_df.columns)
    if observed_cols == EXPECTED_FEATURES:
        result["feature_schema_valid"] = True
        print("- Feature schema       : PASS")
    else:
        msg = f"Feature schema FAILED — got {observed_cols}, expected {EXPECTED_FEATURES}"
        print(f"- Feature schema       : FAIL")
        print(f"  {msg}")
        result["errors"].append(msg)

    # ------------------------------------------------------------------
    # 4. Empty DNS capture guard
    # ------------------------------------------------------------------
    if len(feature_df) == 0:
        print("- Model v1             : SKIPPED (no DNS queries extracted)")
        print("- Risk scoring         : SKIPPED")
        result["errors"].append("No DNS queries extracted — model and risk scoring skipped.")
        print("=" * 80 + "\n")
        return result

    # ------------------------------------------------------------------
    # 5. Model inference — load v1 directly without modifying active_version.json
    # ------------------------------------------------------------------
    try:
        model_mgr = ModelManager()
        if not model_mgr.load_active_model("v1"):
            msg = "Model v1: FAILED — load_active_model('v1') returned False"
            print(f"- Model v1             : FAIL")
            result["errors"].append(msg)
            print("- Risk scoring         : SKIPPED")
            print("=" * 80 + "\n")
            return result

        if model_mgr.active_version != "v1":
            msg = f"Model v1: FAILED — active_version is '{model_mgr.active_version}', expected 'v1'"
            print(f"- Model v1             : FAIL  ({msg})")
            result["errors"].append(msg)
            print("- Risk scoring         : SKIPPED")
            print("=" * 80 + "\n")
            return result

        preds = model_mgr.predict(feature_df)
        result["model_version"] = preds.get("model_version", "unknown")

        # Validate expected keys
        required_pred_keys = [
            "predicted_class", "rf_probability", "if_anomaly_score",
            "rf_mean_prob", "rf_max_prob", "per_query_rf", "per_query_if", "model_version"
        ]
        missing_keys = [k for k in required_pred_keys if k not in preds]
        if missing_keys:
            msg = f"Model v1: FAILED — missing prediction keys: {missing_keys}"
            print(f"- Model v1             : FAIL")
            result["errors"].append(msg)
        else:
            # Score range validation
            range_ok = True
            rf_probs = preds["per_query_rf"]
            if_scores = preds["per_query_if"]

            if len(rf_probs) != len(feature_df):
                msg = f"per_query_rf length ({len(rf_probs)}) != feature_df rows ({len(feature_df)})"
                result["errors"].append(msg)
                range_ok = False

            if len(if_scores) != len(feature_df):
                msg = f"per_query_if length ({len(if_scores)}) != feature_df rows ({len(feature_df)})"
                result["errors"].append(msg)
                range_ok = False

            bad_rf = [p for p in rf_probs if not (0.0 <= p <= 1.0)]
            bad_if = [s for s in if_scores if not (0.0 <= s <= 1.0)]
            if bad_rf:
                msg = f"RF probabilities out of [0,1]: {bad_rf[:5]}"
                result["errors"].append(msg)
                range_ok = False
            if bad_if:
                msg = f"IF scores out of [0,1]: {bad_if[:5]}"
                result["errors"].append(msg)
                range_ok = False

            if not (0.0 <= preds["rf_probability"] <= 1.0):
                result["errors"].append(f"Overall rf_probability out of range: {preds['rf_probability']}")
                range_ok = False
            if not (0.0 <= preds["if_anomaly_score"] <= 1.0):
                result["errors"].append(f"Overall if_anomaly_score out of range: {preds['if_anomaly_score']}")
                range_ok = False

            if preds["model_version"] != "v1":
                result["errors"].append(f"model_version in prediction is '{preds['model_version']}', expected 'v1'")
                range_ok = False

            if range_ok:
                result["model_success"] = True

            attack_count = sum(1 for p in rf_probs if p >= RF_ATTACK_THRESHOLD)
            print(f"- Model v1             : {'PASS' if result['model_success'] else 'FAIL'}")
            print(f"  * Model version      : {preds['model_version']}")
            print(f"  * Predicted class    : {preds['predicted_class']}")
            print(f"  * RF attack prob     : {preds['rf_probability']:.4f}")
            print(f"  * IF anomaly score   : {preds['if_anomaly_score']:.4f}")
            print(f"  * RF attack queries  : {attack_count}/{len(feature_df)} "
                  f"(threshold={RF_ATTACK_THRESHOLD}, project-defined)")

    except Exception as exc:
        msg = f"Model v1: FAILED (unexpected) — {exc}"
        print(f"- Model v1             : FAIL")
        result["errors"].append(msg)
        print("- Risk scoring         : SKIPPED")
        print("=" * 80 + "\n")
        return result

    if not result["model_success"]:
        print("- Risk scoring         : SKIPPED (model failure)")
        print("=" * 80 + "\n")
        return result

    # ------------------------------------------------------------------
    # 6. Per-query Rule Engine + Hybrid Risk Scoring
    # ------------------------------------------------------------------
    try:
        rule_engine  = RuleEngine()
        risk_scorer  = RiskScorer()
        hybrid_scores = []
        rule_score_ok = True

        for i, rec in enumerate(query_records):
            rule_res   = rule_engine.evaluate_query(rec["query"], rec["features"])
            rule_score = rule_res["rule_score"]

            if not (0.0 <= rule_score <= 1.0):
                result["errors"].append(f"Rule score out of [0,1] at query {i}: {rule_score}")
                rule_score_ok = False

            hybrid_res = risk_scorer.compute_risk(
                rf_attack_probability=float(preds["per_query_rf"][i]),
                if_anomaly_score=float(preds["per_query_if"][i]),
                rule_score=float(rule_score)
            )
            score = hybrid_res["risk_score"]

            if not (0 <= score <= 100):
                result["errors"].append(f"Hybrid risk score out of [0,100] at query {i}: {score}")
                rule_score_ok = False

            hybrid_scores.append(score)

        if rule_score_ok and hybrid_scores:
            avg_hybrid = sum(hybrid_scores) / len(hybrid_scores)
            result["risk_success"] = True
            print(f"- Risk scoring         : PASS")
            print(f"  * Avg per-query Hybrid Risk Score : {avg_hybrid:.2f}/100")
            print(f"  * (This is NOT overall NetSentinel hybrid score — it is the")
            print(f"     per-query average using individual RF/IF/rule components.)")
        else:
            print(f"- Risk scoring         : FAIL")

    except Exception as exc:
        msg = f"Risk scoring: FAILED (unexpected) — {exc}"
        print(f"- Risk scoring         : FAIL ({exc})")
        result["errors"].append(msg)

    print("=" * 80 + "\n")
    return result


def main():
    benign_pcapng = str(WORKSPACE_ROOT / "uploads" / "sample_pcaps" / "wireshark_dns_sample.pcapng")
    attack_pcapng = str(WORKSPACE_ROOT / "uploads" / "sample_pcaps" / "wireshark_dns_attack.pcapng")

    print("NETSENTINEL — PCAPNG PIPELINE VERIFICATION\n")
    print("NOTE: This script verifies functional compatibility only.")
    print("      It does NOT measure classifier accuracy.")
    print("      Successful execution does NOT prove the model is accurate.\n")

    # Both tests run independently — a failure in one does not stop the other.
    res1 = run_verification(benign_pcapng,  "Wireshark-Generated Benign DNS PCAPNG")
    res2 = run_verification(attack_pcapng,  "Wireshark-Generated DNS Exfiltration PCAPNG")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("=" * 80)
    print("VERIFICATION SUMMARY")
    print("=" * 80)

    def _status(ok): return "PASS" if ok else "FAIL"

    for label, res in [("Benign PCAPNG", res1), ("Attack PCAPNG", res2)]:
        print(f"\n{label}:")
        print(f"  File found         : {_status(res['file_exists'])}")
        print(f"  Extraction         : {_status(res['extraction_ok'])}")
        print(f"  Feature schema     : {_status(res['feature_schema_valid'])}")
        print(f"  Model v1           : {_status(res['model_success'])}")
        print(f"  Risk scoring       : {_status(res['risk_success'])}")
        if res["errors"]:
            print(f"  Errors             :")
            for e in res["errors"]:
                print(f"    - {e}")

    all_pass = all([
        res1["extraction_ok"], res1["feature_schema_valid"], res1["model_success"], res1["risk_success"],
        res2["extraction_ok"], res2["feature_schema_valid"], res2["model_success"], res2["risk_success"]
    ])
    print(f"\nOverall verification: {'PASS' if all_pass else 'FAIL'}")
    print("=" * 80)

    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
