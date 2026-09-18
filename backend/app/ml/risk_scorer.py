"""
Hybrid Risk Scoring Engine for NetSentinel
Combines three complementary analytical signals:
1. Supervised Random Forest Attack Probability: P_RF in [0.0, 1.0]
2. Unsupervised Isolation Forest Anomaly Score: S_IF in [0.0, 1.0]
3. Heuristic DNS Security Rule Engine Penalty: S_Rules in [0.0, 1.0]

Formula:
  Raw Risk = 100.0 * (w_rf * P_RF + w_if * S_IF + w_rules * S_Rules)
  Final Risk Score = int(round(clamp(Raw Risk, 0.0, 100.0)))

Detection Semantics:
  The resulting score is a composite hybrid risk assessment. A high score indicates
  elevated calculated risk across supervised, anomaly, and heuristic dimensions.
  It does NOT mathematically prove DNS exfiltration, tunneling, or host compromise,
  and should guide investigation and analyst validation rather than automated irreversible actions.
"""

import math
from typing import Dict, Any

class RiskScorer:
    """
    Computes composite hybrid risk scores and explainable component breakdowns
    for NetSentinel DNS traffic evaluations.
    """
    def __init__(
        self,
        weight_rf: float = 0.55,
        weight_if: float = 0.25,
        weight_rules: float = 0.20
    ):
        for name, w in [("weight_rf", weight_rf), ("weight_if", weight_if), ("weight_rules", weight_rules)]:
            if not isinstance(w, (int, float)) or not math.isfinite(w):
                raise ValueError(f"Weight '{name}' must be a finite real number, got {w}")
            if w < 0.0:
                raise ValueError(f"Weight '{name}' must be non-negative (>= 0), got {w}")

        total_weight = weight_rf + weight_if + weight_rules
        if not math.isclose(total_weight, 1.0, rel_tol=1e-9, abs_tol=1e-9):
            raise ValueError(
                f"Weights must sum to 1.0 (within 1e-9 tolerance), got sum={total_weight:.10f} "
                f"(w_rf={weight_rf}, w_if={weight_if}, w_rules={weight_rules})"
            )

        self.weight_rf = float(weight_rf)
        self.weight_if = float(weight_if)
        self.weight_rules = float(weight_rules)

    @staticmethod
    def _validate_score(value: Any, name: str) -> float:
        """
        Validates that input scores are finite numbers, rejects NaN and +/-Infinity,
        and clamps finite numeric inputs to [0.0, 1.0].
        """
        try:
            val = float(value)
        except (TypeError, ValueError):
            raise ValueError(f"Input score '{name}' must be a numeric value, got {type(value).__name__}: {value}")

        if not math.isfinite(val):
            raise ValueError(f"Input score '{name}' must be a finite number, got {val}")

        return min(1.0, max(0.0, val))

    def get_risk_level(self, score: int) -> Dict[str, str]:
        """
        Maps a 0-100 risk score to NetSentinel project-defined presentation categories
        and investigation recommendations.

        Note: Categorical boundaries (80/60/30) are NetSentinel project presentation
        thresholds and are NOT official CIC-Bell-DNS-EXF-2021 or universal industry standards.
        """
        if score >= 80:
            return {
                "level": "CRITICAL THREAT",
                "color": "rose",
                "badge": "CRITICAL",
                "action": "High-risk DNS behavior detected across multiple analytical signals. Investigate source host activity and destination domains immediately; containment may be appropriate after analyst validation."
            }
        elif score >= 60:
            return {
                "level": "HIGH RISK",
                "color": "orange",
                "badge": "HIGH",
                "action": "Elevated DNS anomaly and threat signals detected. Audit querying client, inspect destination nameservers, and review payload patterns to determine if containment or filtering is required."
            }
        elif score >= 30:
            return {
                "level": "MODERATE RISK",
                "color": "amber",
                "badge": "MODERATE",
                "action": "Anomalous DNS patterns observed exceeding baseline expectations. Monitor host for continuous beaconing or secondary threat indicators."
            }
        else:
            return {
                "level": "LOW RISK",
                "color": "emerald",
                "badge": "BENIGN",
                "action": "Traffic assessed as low risk with standard structural DNS characteristics. Routine monitoring recommended; not a guarantee of benign intent."
            }

    def compute_risk(
        self,
        rf_attack_probability: float,
        if_anomaly_score: float,
        rule_score: float
    ) -> Dict[str, Any]:
        """
        Calculates the final composite hybrid risk score and explainable component breakdown.
        """
        p_rf = self._validate_score(rf_attack_probability, "rf_attack_probability")
        s_if = self._validate_score(if_anomaly_score, "if_anomaly_score")
        s_rule = self._validate_score(rule_score, "rule_score")

        raw_score = 100.0 * (
            (self.weight_rf * p_rf) +
            (self.weight_if * s_if) +
            (self.weight_rules * s_rule)
        )

        risk_score = int(round(min(100.0, max(0.0, raw_score))))
        level_info = self.get_risk_level(risk_score)

        return {
            "risk_score": risk_score,
            "risk_level": level_info["level"],
            "badge": level_info["badge"],
            "color": level_info["color"],
            "action_recommendation": level_info["action"],
            "components": {
                "random_forest": {
                    "probability": round(p_rf, 4),
                    "weight": self.weight_rf,
                    "contribution_points": round(self.weight_rf * p_rf * 100.0, 1)
                },
                "isolation_forest": {
                    "anomaly_score": round(s_if, 4),
                    "weight": self.weight_if,
                    "contribution_points": round(self.weight_if * s_if * 100.0, 1)
                },
                "rule_engine": {
                    "rule_score": round(s_rule, 4),
                    "weight": self.weight_rules,
                    "contribution_points": round(self.weight_rules * s_rule * 100.0, 1)
                }
            }
        }
