"""
DNS Security Rule Engine for NetSentinel
Heuristic rule evaluation based on DNS structural characteristics.

All thresholds are NetSentinel project-defined configurable heuristics and
contribute to the hybrid risk score.  They are NOT claimed to be universal
cybersecurity standards or official CIC-Bell-DNS-EXF-2021 thresholds.

API
---
evaluate_query(domain, features) -> {"rule_score": float, "triggered_rules": list, "triggered_count": int}
evaluate_batch(query_records)    -> {"rule_score": float, "triggered_rules": list, "triggered_count": int}
"""

import re
import math
from typing import List, Dict, Any


class RuleEngine:
    """
    Configurable DNS security heuristic engine.
    Calculates a normalized rule penalty score between 0.0 and 1.0.

    Five heuristic rules are evaluated per query:
        RULE_HIGH_ENTROPY          weight=0.25
        RULE_LONG_SUBDOMAIN        weight=0.25
        RULE_HIGH_NUMERIC_RATIO    weight=0.15
        RULE_HEX_BASE32_ENCODING   weight=0.20
        RULE_DEEP_LABEL_HIERARCHY  weight=0.15
    Total weight = 1.00.

    Configuration
    -------------
    All thresholds are project-defined heuristics. Changing them does NOT
    constitute model retraining; it adjusts heuristic sensitivity only.
    """

    def __init__(
        self,
        entropy_threshold: float = 3.8,
        subdomain_length_threshold: int = 30,
        numeric_ratio_threshold: float = 0.4,
        label_depth_threshold: int = 5,
        longest_word_threshold: int = 35  # Reserved: not used in active rules; kept for forward compatibility.
    ):
        # --- threshold validation ---
        # entropy_threshold
        if not math.isfinite(entropy_threshold) or entropy_threshold < 0:
            raise ValueError(
                f"entropy_threshold must be a finite non-negative number, got {entropy_threshold!r}"
            )
        # subdomain_length_threshold
        if not math.isfinite(subdomain_length_threshold) or subdomain_length_threshold < 0:
            raise ValueError(
                f"subdomain_length_threshold must be a finite non-negative number, got {subdomain_length_threshold!r}"
            )
        # numeric_ratio_threshold
        if not math.isfinite(numeric_ratio_threshold) or not (0.0 <= numeric_ratio_threshold <= 1.0):
            raise ValueError(
                f"numeric_ratio_threshold must be a finite number in [0.0, 1.0], got {numeric_ratio_threshold!r}"
            )
        # label_depth_threshold
        if not math.isfinite(label_depth_threshold) or label_depth_threshold < 0:
            raise ValueError(
                f"label_depth_threshold must be a finite non-negative number, got {label_depth_threshold!r}"
            )
        # longest_word_threshold (reserved — validate for safety)
        if not math.isfinite(longest_word_threshold) or longest_word_threshold < 0:
            raise ValueError(
                f"longest_word_threshold must be a finite non-negative number, got {longest_word_threshold!r}"
            )

        self.entropy_threshold = entropy_threshold
        self.subdomain_length_threshold = subdomain_length_threshold
        self.numeric_ratio_threshold = numeric_ratio_threshold
        self.label_depth_threshold = label_depth_threshold
        # longest_word_threshold is reserved configuration kept for API compatibility.
        # It is not used in any active rule evaluation.
        self.longest_word_threshold = longest_word_threshold

        # Rule weights — must all be non-negative, finite, and sum to 1.0.
        self.weights = {
            "RULE_HIGH_ENTROPY":         0.25,
            "RULE_LONG_SUBDOMAIN":       0.25,
            "RULE_HIGH_NUMERIC_RATIO":   0.15,
            "RULE_HEX_BASE32_ENCODING":  0.20,
            "RULE_DEEP_LABEL_HIERARCHY": 0.15
        }
        # Validate weights
        for rule_id, w in self.weights.items():
            if not math.isfinite(w) or w < 0:
                raise ValueError(
                    f"Weight for {rule_id!r} must be a finite non-negative number, got {w!r}"
                )
        weight_sum = sum(self.weights.values())
        if not math.isclose(weight_sum, 1.0, rel_tol=1e-9, abs_tol=1e-9):
            raise ValueError(
                f"Rule weights must sum to 1.0 (got {weight_sum})"
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate_query(self, domain: str, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate a single DNS query against security heuristics.

        Parameters
        ----------
        domain   : The DNS query name (FQDN, without trailing dot).
        features : Feature dictionary produced by extract_features_from_domain().
                   Required keys: entropy, subdomain_length, FQDN_count, numeric, labels.

        Returns
        -------
        {
            "rule_score":      float in [0.0, 1.0],
            "triggered_rules": list of rule dicts,
            "triggered_count": int
        }

        Raises
        ------
        ValueError if required feature values are NaN, infinite, or semantically invalid.
        """
        triggered = []
        rule_score = 0.0

        # --- Feature extraction & validation ---
        try:
            entropy = float(features.get("entropy", 0.0))
        except (TypeError, ValueError):
            raise ValueError("Feature 'entropy' must be convertible to float.")
        if not math.isfinite(entropy):
            raise ValueError(f"Feature 'entropy' must be a finite number, got {entropy!r}")

        try:
            sub_len = int(features.get("subdomain_length", 0))
        except (TypeError, ValueError):
            raise ValueError("Feature 'subdomain_length' must be convertible to int.")
        if not math.isfinite(sub_len):
            raise ValueError(f"Feature 'subdomain_length' must be finite, got {sub_len!r}")
        if sub_len < 0:
            raise ValueError(f"Feature 'subdomain_length' must be non-negative, got {sub_len!r}")

        try:
            fqdn_cnt_raw = int(features.get("FQDN_count", 1))
        except (TypeError, ValueError):
            raise ValueError("Feature 'FQDN_count' must be convertible to int.")
        if not math.isfinite(fqdn_cnt_raw):
            raise ValueError(f"Feature 'FQDN_count' must be finite, got {fqdn_cnt_raw!r}")
        if fqdn_cnt_raw < 0:
            raise ValueError(f"Feature 'FQDN_count' must be non-negative, got {fqdn_cnt_raw!r}")
        # Guard against zero-division in numeric ratio
        fqdn_cnt = max(1, fqdn_cnt_raw)

        try:
            numeric = int(features.get("numeric", 0))
        except (TypeError, ValueError):
            raise ValueError("Feature 'numeric' must be convertible to int.")
        if not math.isfinite(numeric):
            raise ValueError(f"Feature 'numeric' must be finite, got {numeric!r}")
        if numeric < 0:
            raise ValueError(f"Feature 'numeric' must be non-negative, got {numeric!r}")

        try:
            labels = int(features.get("labels", 0))
        except (TypeError, ValueError):
            raise ValueError("Feature 'labels' must be convertible to int.")
        if not math.isfinite(labels):
            raise ValueError(f"Feature 'labels' must be finite, got {labels!r}")
        if labels < 0:
            raise ValueError(f"Feature 'labels' must be non-negative, got {labels!r}")

        # ------------------------------------------------------------------
        # Rule 1 — High Domain Shannon Entropy
        # Threshold comparison is strict (>): a value exactly equal to the
        # threshold does NOT trigger this rule.
        # ------------------------------------------------------------------
        if entropy > self.entropy_threshold:
            triggered.append({
                "rule_id":     "RULE_HIGH_ENTROPY",
                "title":       "Elevated Domain Shannon Entropy",
                "description": (
                    f"Domain entropy ({entropy:.2f}) exceeds the configured threshold "
                    f"({self.entropy_threshold:.2f}), which is a heuristic indicator of "
                    "possible encryption, obfuscation, or algorithmically generated labels."
                ),
                "severity": "MEDIUM",
                "weight":   self.weights["RULE_HIGH_ENTROPY"]
            })
            rule_score += self.weights["RULE_HIGH_ENTROPY"]

        # ------------------------------------------------------------------
        # Rule 2 — Unusually Long Subdomain
        # Long subdomains may encode data chunks in DNS exfiltration scenarios.
        # ------------------------------------------------------------------
        if sub_len > self.subdomain_length_threshold:
            triggered.append({
                "rule_id":     "RULE_LONG_SUBDOMAIN",
                "title":       "Abnormally Long Subdomain Payload",
                "description": (
                    f"Subdomain length ({sub_len} chars) exceeds the configured limit "
                    f"({self.subdomain_length_threshold} chars). Unusually long subdomains "
                    "are a heuristic indicator of potential data-carrying label abuse."
                ),
                "severity": "HIGH",
                "weight":   self.weights["RULE_LONG_SUBDOMAIN"]
            })
            rule_score += self.weights["RULE_LONG_SUBDOMAIN"]

        # ------------------------------------------------------------------
        # Rule 3 — High Numeric Character Ratio
        # Only meaningful when FQDN has more than 12 characters (avoids
        # false positives on very short labels).
        # ------------------------------------------------------------------
        num_ratio = numeric / fqdn_cnt
        if num_ratio > self.numeric_ratio_threshold and fqdn_cnt > 12:
            triggered.append({
                "rule_id":     "RULE_HIGH_NUMERIC_RATIO",
                "title":       "High Numeric Character Density",
                "description": (
                    f"Numeric characters account for {num_ratio * 100:.1f}% of the domain "
                    f"string, exceeding the configured threshold "
                    f"({self.numeric_ratio_threshold * 100:.0f}%). Elevated numeric density "
                    "may be consistent with encoded or machine-generated payloads."
                ),
                "severity": "MEDIUM",
                "weight":   self.weights["RULE_HIGH_NUMERIC_RATIO"]
            })
            rule_score += self.weights["RULE_HIGH_NUMERIC_RATIO"]

        # ------------------------------------------------------------------
        # Rule 4 — Hexadecimal / Base32 Encoding Pattern
        # Detects long runs of hex digits or Base32 characters in the
        # subdomain portion of the FQDN.
        #
        # Patterns detected:
        #   Hexadecimal : ≥16 consecutive hex characters  ([0-9a-fA-F]{16,})
        #   Base32      : ≥20 consecutive Base32 alphabet  ([A-Za-z2-7]{20,})
        #
        # Note: Base64 is NOT reliably distinguished from ordinary alpha
        # subdomains by regex alone; this rule does NOT claim Base64 detection.
        # ------------------------------------------------------------------
        labels_list = domain.split(".")
        if len(labels_list) > 2:
            subdomain_str = ".".join(labels_list[:-2])
            has_hex = bool(re.search(r"\b[0-9a-fA-F]{16,}\b", subdomain_str))
            has_b32 = bool(re.search(r"\b[A-Za-z2-7]{20,}\b", subdomain_str))
            if has_hex or has_b32:
                triggered.append({
                    "rule_id":     "RULE_HEX_BASE32_ENCODING",
                    "title":       "Encoded Data Payload Pattern Detected",
                    "description": (
                        "The subdomain portion contains repetitive hexadecimal or Base32 "
                        "character blocks. Such patterns are a heuristic indicator of "
                        "potential binary data encoding in DNS labels."
                    ),
                    "severity": "HIGH",
                    "weight":   self.weights["RULE_HEX_BASE32_ENCODING"]
                })
                rule_score += self.weights["RULE_HEX_BASE32_ENCODING"]

        # ------------------------------------------------------------------
        # Rule 5 — Deep Label Hierarchy
        # Threshold comparison is strict (>): a value exactly equal to the
        # threshold does NOT trigger this rule.
        # ------------------------------------------------------------------
        if labels > self.label_depth_threshold:
            triggered.append({
                "rule_id":     "RULE_DEEP_LABEL_HIERARCHY",
                "title":       "Excessive DNS Label Depth",
                "description": (
                    f"Domain contains {labels} distinct labels, which surpasses the "
                    f"configured threshold ({self.label_depth_threshold}). Excessive label "
                    "depth is a heuristic indicator of atypical query structure."
                ),
                "severity": "LOW",
                "weight":   self.weights["RULE_DEEP_LABEL_HIERARCHY"]
            })
            rule_score += self.weights["RULE_DEEP_LABEL_HIERARCHY"]

        normalized_score = min(1.0, max(0.0, rule_score))
        return {
            "rule_score":      normalized_score,
            "triggered_rules": triggered,
            "triggered_count": len(triggered)
        }

    def evaluate_batch(self, query_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Evaluate an entire PCAP capture consisting of multiple DNS queries.

        Aggregates rule findings across all observed queries using a 70/30
        blended heuristic: 70% weight on the peak (worst-case) query score
        and 30% on the average score across the capture.

        Each rule ID is deduplicated in the output: if a rule fires for
        multiple queries only one entry appears in triggered_rules.

        Parameters
        ----------
        query_records : list produced by extract_dns_from_pcap().
                        Each record must contain "query" and "features" keys.

        Returns
        -------
        {
            "rule_score":      float in [0.0, 1.0],
            "triggered_rules": deduplicated list of rule dicts,
            "triggered_count": int
        }
        """
        if not query_records:
            return {"rule_score": 0.0, "triggered_rules": [], "triggered_count": 0}

        all_triggered_ids: set = set()
        unique_triggered: List[Dict] = []
        max_rule_score = 0.0
        sum_scores = 0.0

        for rec in query_records:
            res = self.evaluate_query(rec["query"], rec["features"])
            score = res["rule_score"]
            sum_scores += score
            if score > max_rule_score:
                max_rule_score = score
            for r in res["triggered_rules"]:
                if r["rule_id"] not in all_triggered_ids:
                    all_triggered_ids.add(r["rule_id"])
                    unique_triggered.append(r)

        # Hybrid PCAP rule score: blends peak severity with query density.
        # This is a NetSentinel project-defined heuristic (70/30 blend).
        avg_score = sum_scores / len(query_records)
        aggregated_score = min(1.0, (0.7 * max_rule_score) + (0.3 * avg_score))

        return {
            "rule_score":      round(aggregated_score, 4),
            "triggered_rules": unique_triggered,
            "triggered_count": len(unique_triggered)
        }
