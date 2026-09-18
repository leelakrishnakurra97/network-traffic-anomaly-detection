"""
Automated unit tests for ML pipeline, Rule Engine, and Hybrid Risk Scorer.
"""

import pandas as pd
from backend.app.ml.model_loader import model_manager
from backend.app.ml.rule_engine import RuleEngine
from backend.app.ml.risk_scorer import RiskScorer
from backend.app.dns.pcap_extractor import extract_features_from_domain

def test_model_loading_and_prediction():
    assert model_manager.active_version is not None
    assert model_manager.rf_model is not None
    assert model_manager.iso_model is not None

    # Test benign domain prediction
    feats = extract_features_from_domain("www.google.com")
    df = pd.DataFrame([feats])
    pred = model_manager.predict(df)

    assert "predicted_class" in pred
    assert "rf_probability" in pred
    assert 0.0 <= pred["rf_probability"] <= 1.0
    assert 0.0 <= pred["if_anomaly_score"] <= 1.0

def test_rule_engine_heuristics():
    rules = RuleEngine()

    # Normal domain should trigger 0 rules
    benign_feats = extract_features_from_domain("www.example.org")
    res_b = rules.evaluate_query("www.example.org", benign_feats)
    assert res_b["rule_score"] == 0.0
    assert len(res_b["triggered_rules"]) == 0

    # Highly suspicious tunneling query
    evil_domain = "0123456789abcdef0123456789abcdef0123456789abcdef.tunnel.attacker-c2.net"
    evil_feats = extract_features_from_domain(evil_domain)
    res_e = rules.evaluate_query(evil_domain, evil_feats)
    assert res_e["rule_score"] > 0.0
    assert len(res_e["triggered_rules"]) >= 2
    rule_ids = [r["rule_id"] for r in res_e["triggered_rules"]]
    assert "RULE_LONG_SUBDOMAIN" in rule_ids

def test_risk_scorer_formula_and_ranges():
    scorer = RiskScorer(weight_rf=0.55, weight_if=0.25, weight_rules=0.20)

    # 1. Zero risk test
    low_risk = scorer.compute_risk(0.0, 0.0, 0.0)
    assert low_risk["risk_score"] == 0
    assert low_risk["risk_level"] == "LOW RISK"

    # 2. Maximum risk test
    high_risk = scorer.compute_risk(1.0, 1.0, 1.0)
    assert high_risk["risk_score"] == 100
    assert high_risk["risk_level"] == "CRITICAL THREAT"

    # 3. Known weighted test: 0.55*1.0 + 0.25*0.0 + 0.20*0.5 = 0.65 -> 65
    mid_risk = scorer.compute_risk(1.0, 0.0, 0.5)
    assert mid_risk["risk_score"] == 65
    assert mid_risk["risk_level"] == "HIGH RISK"

def test_model_manager_empty_dataframe_raises_value_error():
    import pytest
    with pytest.raises(ValueError) as exc:
        model_manager.predict(pd.DataFrame())
    assert "No DNS feature rows available" in str(exc.value)

def test_model_manager_missing_features_raises_value_error():
    import pytest
    incomplete_df = pd.DataFrame([{"FQDN_count": 12, "entropy": 3.1}])
    with pytest.raises(ValueError) as exc:
        model_manager.predict(incomplete_df)
    assert "Missing required feature columns" in str(exc.value)

def test_model_manager_rf_attack_class_handling():
    classes = list(model_manager.rf_model.classes_)
    assert 1 in classes
    assert classes.index(1) == 1

def test_risk_scorer_weight_validation():
    import pytest
    # Negative weight
    with pytest.raises(ValueError) as exc1:
        RiskScorer(weight_rf=-0.1, weight_if=0.6, weight_rules=0.5)
    assert "must be non-negative" in str(exc1.value)

    # Weights not summing to 1
    with pytest.raises(ValueError) as exc2:
        RiskScorer(weight_rf=0.5, weight_if=0.3, weight_rules=0.1)
    assert "must sum to 1.0" in str(exc2.value)

    # Non-finite weight
    with pytest.raises(ValueError) as exc3:
        RiskScorer(weight_rf=float("nan"), weight_if=0.5, weight_rules=0.5)
    assert "must be a finite real number" in str(exc3.value)

def test_risk_scorer_score_validation():
    import pytest
    scorer = RiskScorer()

    # NaN / Inf / -Inf must raise ValueError
    for bad_val in [float("nan"), float("inf"), float("-inf")]:
        with pytest.raises(ValueError) as exc:
            scorer.compute_risk(bad_val, 0.5, 0.5)
        assert "must be a finite number" in str(exc.value)

    # Clamping finite scores below 0 or above 1
    res = scorer.compute_risk(-0.5, 1.5, 0.5)
    assert res["components"]["random_forest"]["probability"] == 0.0
    assert res["components"]["isolation_forest"]["anomaly_score"] == 1.0
    assert res["risk_score"] == 35

def test_risk_scorer_level_boundaries():
    scorer = RiskScorer()
    assert scorer.get_risk_level(29)["level"] == "LOW RISK"
    assert scorer.get_risk_level(30)["level"] == "MODERATE RISK"
    assert scorer.get_risk_level(59)["level"] == "MODERATE RISK"
    assert scorer.get_risk_level(60)["level"] == "HIGH RISK"
    assert scorer.get_risk_level(79)["level"] == "HIGH RISK"
    assert scorer.get_risk_level(80)["level"] == "CRITICAL THREAT"

# ===========================================================================
# RuleEngine — configuration validation tests
# ===========================================================================

def test_rule_engine_config_negative_entropy_threshold_raises():
    import pytest
    with pytest.raises(ValueError, match="entropy_threshold"):
        RuleEngine(entropy_threshold=-1.0)

def test_rule_engine_config_nan_threshold_raises():
    import pytest, math
    with pytest.raises(ValueError, match="entropy_threshold"):
        RuleEngine(entropy_threshold=float("nan"))

def test_rule_engine_config_ratio_out_of_range_raises():
    import pytest
    with pytest.raises(ValueError, match="numeric_ratio_threshold"):
        RuleEngine(numeric_ratio_threshold=1.5)

# ===========================================================================
# RuleEngine — feature validation tests
# ===========================================================================

def test_rule_engine_feature_nan_entropy_raises():
    import pytest
    rules = RuleEngine()
    bad_feats = {"entropy": float("nan"), "subdomain_length": 5,
                 "FQDN_count": 10, "numeric": 2, "labels": 3}
    with pytest.raises(ValueError, match="entropy"):
        rules.evaluate_query("example.com", bad_feats)

def test_rule_engine_feature_inf_raises():
    import pytest
    rules = RuleEngine()
    bad_feats = {"entropy": float("inf"), "subdomain_length": 5,
                 "FQDN_count": 10, "numeric": 2, "labels": 3}
    with pytest.raises(ValueError, match="entropy"):
        rules.evaluate_query("example.com", bad_feats)

def test_rule_engine_feature_negative_labels_raises():
    import pytest
    rules = RuleEngine()
    bad_feats = {"entropy": 2.5, "subdomain_length": 5,
                 "FQDN_count": 10, "numeric": 2, "labels": -1}
    with pytest.raises(ValueError, match="labels"):
        rules.evaluate_query("example.com", bad_feats)

# ===========================================================================
# RuleEngine — strict > boundary (value == threshold must NOT trigger)
# ===========================================================================

def test_rule_engine_strict_gt_at_entropy_threshold():
    """A domain with entropy == threshold must NOT trigger RULE_HIGH_ENTROPY."""
    rules = RuleEngine(entropy_threshold=3.8)
    feats = {"entropy": 3.8, "subdomain_length": 5,
             "FQDN_count": 10, "numeric": 0, "labels": 2}
    res = rules.evaluate_query("example.com", feats)
    rule_ids = [r["rule_id"] for r in res["triggered_rules"]]
    assert "RULE_HIGH_ENTROPY" not in rule_ids

def test_rule_engine_strict_gt_above_entropy_threshold():
    """A domain with entropy > threshold MUST trigger RULE_HIGH_ENTROPY."""
    rules = RuleEngine(entropy_threshold=3.8)
    feats = {"entropy": 3.81, "subdomain_length": 5,
             "FQDN_count": 10, "numeric": 0, "labels": 2}
    res = rules.evaluate_query("example.com", feats)
    rule_ids = [r["rule_id"] for r in res["triggered_rules"]]
    assert "RULE_HIGH_ENTROPY" in rule_ids

def test_rule_engine_strict_gt_at_label_depth_threshold():
    """labels == threshold must NOT trigger RULE_DEEP_LABEL_HIERARCHY."""
    rules = RuleEngine(label_depth_threshold=5)
    feats = {"entropy": 2.0, "subdomain_length": 5,
             "FQDN_count": 10, "numeric": 0, "labels": 5}
    res = rules.evaluate_query("a.b.c.d.e.com", feats)
    rule_ids = [r["rule_id"] for r in res["triggered_rules"]]
    assert "RULE_DEEP_LABEL_HIERARCHY" not in rule_ids

# ===========================================================================
# RuleEngine — hex / Base32 pattern detection
# ===========================================================================

def test_rule_engine_hex_pattern_detected():
    """A subdomain with ≥16 hex chars should trigger RULE_HEX_BASE32_ENCODING."""
    rules = RuleEngine()
    hex_domain = "0123456789abcdef.evil.com"
    feats = extract_features_from_domain(hex_domain)
    res = rules.evaluate_query(hex_domain, feats)
    rule_ids = [r["rule_id"] for r in res["triggered_rules"]]
    assert "RULE_HEX_BASE32_ENCODING" in rule_ids

def test_rule_engine_base32_pattern_detected():
    """A subdomain with ≥20 Base32 chars should trigger RULE_HEX_BASE32_ENCODING."""
    rules = RuleEngine()
    b32_domain = "ABCDEFG2HIJKLMN2OPQR.evil.com"
    feats = extract_features_from_domain(b32_domain)
    res = rules.evaluate_query(b32_domain, feats)
    rule_ids = [r["rule_id"] for r in res["triggered_rules"]]
    assert "RULE_HEX_BASE32_ENCODING" in rule_ids

# ===========================================================================
# RuleEngine — batch deduplication
# ===========================================================================

def test_rule_engine_batch_deduplication():
    """evaluate_batch must deduplicate triggered rule IDs."""
    rules = RuleEngine()
    evil_domain = "0123456789abcdef0123456789abcdef.tunnel.attacker-c2.net"
    evil_feats = extract_features_from_domain(evil_domain)
    # Pass the same triggering record twice.
    records = [
        {"query": evil_domain, "features": evil_feats},
        {"query": evil_domain, "features": evil_feats},
    ]
    res = rules.evaluate_batch(records)
    rule_ids = [r["rule_id"] for r in res["triggered_rules"]]
    # Each rule ID appears at most once (deduplicated).
    assert len(rule_ids) == len(set(rule_ids))
    assert res["triggered_count"] == len(rule_ids)

def test_rule_engine_batch_empty_returns_zero():
    """evaluate_batch with empty list must return rule_score=0.0."""
    rules = RuleEngine()
    res = rules.evaluate_batch([])
    assert res["rule_score"] == 0.0
    assert res["triggered_rules"] == []
    assert res["triggered_count"] == 0
