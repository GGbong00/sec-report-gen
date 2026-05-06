"""
CVSS v3.1 Base Score Calculator Module.

Provides functions to parse CVSS v3.1 vector strings, compute base scores
according to the specification, validate vectors, and retrieve available
metric options for UI dropdowns.

Reference: https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional, Tuple


# ============================================================
# CVSS v3.1 Metric Definitions
# ============================================================

CVSS_VERSION = "3.1"

# Attack Vector (AV) metric values and weights
AV_METRICS: Dict[str, float] = {
    "N": 0.85,   # Network
    "A": 0.62,   # Adjacent
    "L": 0.55,   # Local
    "P": 0.20,   # Physical
}

# Attack Complexity (AC) metric values and weights
AC_METRICS: Dict[str, float] = {
    "L": 0.77,   # Low
    "H": 0.44,   # High
}

# Privileges Required (PR) base metric values (before scope modification)
PR_METRICS: Dict[str, float] = {
    "N": 0.85,   # None
    "L": 0.62,   # Low
    "H": 0.27,   # High
}

# User Interaction (UI) metric values and weights
UI_METRICS: Dict[str, float] = {
    "N": 0.85,   # None
    "R": 0.62,   # Required
}

# Scope (S) metric
SCOPE_VALUES: Dict[str, str] = {
    "U": "Unchanged",
    "C": "Changed",
}

# CIA Impact metric values and weights
CIA_METRICS: Dict[str, float] = {
    "H": 0.56,   # High
    "L": 0.22,   # Low
    "N": 0.0,    # None
}

# Full metric definitions for UI dropdowns
CVSS_METRICS: Dict[str, Dict[str, Any]] = {
    "AV": {
        "name": "Attack Vector",
        "name_zh": "攻击向量",
        "required": True,
        "values": {
            "N": {"label": "Network", "label_zh": "网络", "weight": 0.85},
            "A": {"label": "Adjacent", "label_zh": "相邻", "weight": 0.62},
            "L": {"label": "Local", "label_zh": "本地", "weight": 0.55},
            "P": {"label": "Physical", "label_zh": "物理", "weight": 0.20},
        },
    },
    "AC": {
        "name": "Attack Complexity",
        "name_zh": "攻击复杂度",
        "required": True,
        "values": {
            "L": {"label": "Low", "label_zh": "低", "weight": 0.77},
            "H": {"label": "High", "label_zh": "高", "weight": 0.44},
        },
    },
    "PR": {
        "name": "Privileges Required",
        "name_zh": "所需权限",
        "required": True,
        "values": {
            "N": {"label": "None", "label_zh": "无", "weight": 0.85},
            "L": {"label": "Low", "label_zh": "低", "weight": 0.62},
            "H": {"label": "High", "label_zh": "高", "weight": 0.27},
        },
    },
    "UI": {
        "name": "User Interaction",
        "name_zh": "用户交互",
        "required": True,
        "values": {
            "N": {"label": "None", "label_zh": "无", "weight": 0.85},
            "R": {"label": "Required", "label_zh": "需要", "weight": 0.62},
        },
    },
    "S": {
        "name": "Scope",
        "name_zh": "影响范围",
        "required": True,
        "values": {
            "U": {"label": "Unchanged", "label_zh": "不变", "weight": None},
            "C": {"label": "Changed", "label_zh": "改变", "weight": None},
        },
    },
    "C": {
        "name": "Confidentiality Impact",
        "name_zh": "机密性影响",
        "required": True,
        "values": {
            "H": {"label": "High", "label_zh": "高", "weight": 0.56},
            "L": {"label": "Low", "label_zh": "低", "weight": 0.22},
            "N": {"label": "None", "label_zh": "无", "weight": 0.0},
        },
    },
    "I": {
        "name": "Integrity Impact",
        "name_zh": "完整性影响",
        "required": True,
        "values": {
            "H": {"label": "High", "label_zh": "高", "weight": 0.56},
            "L": {"label": "Low", "label_zh": "低", "weight": 0.22},
            "N": {"label": "None", "label_zh": "无", "weight": 0.0},
        },
    },
    "A": {
        "name": "Availability Impact",
        "name_zh": "可用性影响",
        "required": True,
        "values": {
            "H": {"label": "High", "label_zh": "高", "weight": 0.56},
            "L": {"label": "Low", "label_zh": "低", "weight": 0.22},
            "N": {"label": "None", "label_zh": "无", "weight": 0.0},
        },
    },
}

# Severity rating thresholds
SEVERITY_THRESHOLDS: List[Tuple[float, str]] = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
    (0.0, "none"),
]

# Valid metric order in a CVSS vector string
REQUIRED_METRICS_ORDER: List[str] = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]

# Regex pattern for validating CVSS v3.1 vector strings
CVSS_VECTOR_PATTERN = re.compile(
    r"^CVSS:3\.1"
    r"(?:/AV:[NAPL])"
    r"(?:/AC:[LH])"
    r"(?:/PR:[NLH])"
    r"(?:/UI:[NR])"
    r"(?:/S:[UC])"
    r"(?:/C:[NLH])"
    r"(?:/I:[NLH])"
    r"(?:/A:[NLH])"
    r"$"
)


class CVSSCalculator:
    """CVSS v3.1 Base Score Calculator.

    Parses CVSS v3.1 vector strings and computes base scores according
    to the CVSS v3.1 specification.
    """

    @staticmethod
    def parse_vector(vector_string: str) -> Optional[Dict[str, str]]:
        """Parse a CVSS v3.1 vector string into its component metrics.

        Args:
            vector_string: A CVSS v3.1 vector string, e.g.
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

        Returns:
            A dictionary mapping metric abbreviations to their values,
            e.g. {"AV": "N", "AC": "L", ...}, or None if parsing fails.
        """
        if not vector_string or not isinstance(vector_string, str):
            return None

        vector_string = vector_string.strip()

        # Check prefix
        if not vector_string.startswith("CVSS:3.1"):
            return None

        # Split by "/" and skip the prefix
        parts = vector_string.split("/")
        if len(parts) < 9:  # prefix + 8 metrics
            return None

        metrics = {}
        for part in parts[1:]:  # Skip "CVSS:3.1"
            if ":" not in part:
                return None
            key, value = part.split(":", 1)
            key = key.strip().upper()
            value = value.strip().upper()
            if key not in CVSS_METRICS:
                return None
            if value not in CVSS_METRICS[key]["values"]:
                return None
            metrics[key] = value

        # Verify all required metrics are present
        for required in REQUIRED_METRICS_ORDER:
            if required not in metrics:
                return None

        return metrics

    @staticmethod
    def _roundup(value: float) -> float:
        """Round up to 1 decimal place per CVSS spec.

        Uses the "roundup" function from the specification:
        roundup(x) = ceiling(x * 10) / 10

        Args:
            value: The float value to round up.

        Returns:
            The value rounded up to 1 decimal place.
        """
        return math.ceil(value * 10) / 10.0

    @staticmethod
    def calculate_base_score(metrics: Dict[str, str]) -> float:
        """Calculate the CVSS v3.1 base score from parsed metrics.

        Implements the full calculation per the CVSS v3.1 specification:
        - ISS = 1 - [(1-C) * (1-I) * (1-A)]
        - If Scope Unchanged: Impact = 6.42 * ISS
        - If Scope Changed: Impact = 7.52 * [ISS - 0.029] - 3.25 * [ISS - 0.02]^15
        - If Impact <= 0: baseScore = 0
        - Else: baseScore = min(10, roundup(Impact + Exploitability))
        - Exploitability = 8.22 * AV * AC * PR * UI

        Args:
            metrics: A dictionary of metric key-value pairs, e.g.
                {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
                 "S": "U", "C": "H", "I": "H", "A": "H"}

        Returns:
            The calculated base score as a float (0.0 to 10.0).
        """
        # Extract metric values
        av = AV_METRICS[metrics["AV"]]
        ac = AC_METRICS[metrics["AC"]]
        pr_base = PR_METRICS[metrics["PR"]]
        ui = UI_METRICS[metrics["UI"]]
        scope_changed = metrics["S"] == "C"
        c = CIA_METRICS[metrics["C"]]
        i = CIA_METRICS[metrics["I"]]
        a = CIA_METRICS[metrics["A"]]

        # Apply scope modification to Privileges Required
        if scope_changed:
            if metrics["PR"] == "N":
                pr = 0.85
            elif metrics["PR"] == "L":
                pr = 0.68
            else:  # PR == "H"
                pr = 0.50
        else:
            pr = pr_base

        # Calculate Impact Sub-Score (ISS)
        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

        # Calculate Impact based on Scope
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss

        # If impact is 0 or less, base score is 0
        if impact <= 0:
            return 0.0

        # Calculate Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Calculate base score
        base_score = CVSSCalculator._roundup(impact + exploitability)

        # Cap at 10.0
        return min(10.0, base_score)

    @staticmethod
    def calculate(vector_string: str) -> float:
        """Calculate the CVSS v3.1 base score from a vector string.

        This is the main entry point that combines parsing and calculation.

        Args:
            vector_string: A CVSS v3.1 vector string.

        Returns:
            The calculated base score as a float, or 0.0 if the vector
            is invalid.
        """
        metrics = CVSSCalculator.parse_vector(vector_string)
        if metrics is None:
            return 0.0
        return CVSSCalculator.calculate_base_score(metrics)


# ============================================================
# Public API Functions
# ============================================================

def calculate_cvss_score(vector_string: str) -> float:
    """Calculate the CVSS v3.1 base score from a vector string.

    Args:
        vector_string: A CVSS v3.1 vector string, e.g.
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    Returns:
        The calculated base score as a float (0.0 to 10.0).
        Returns 0.0 if the vector string is invalid.
    """
    return CVSSCalculator.calculate(vector_string)


def get_cvss_severity(score: float) -> str:
    """Get the severity rating for a given CVSS score.

    Rating thresholds per CVSS v3.1 specification:
    - Critical: 9.0 - 10.0
    - High: 7.0 - 8.9
    - Medium: 4.0 - 6.9
    - Low: 0.1 - 3.9
    - None: 0.0

    Args:
        score: The CVSS base score (float).

    Returns:
        The severity rating string: 'critical', 'high', 'medium', 'low', or 'none'.
    """
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score > 0.0:
        return "low"
    else:
        return "none"


def validate_cvss_vector(vector_string: str) -> bool:
    """Validate a CVSS v3.1 vector string.

    Checks that the vector string:
    - Starts with "CVSS:3.1"
    - Contains all 8 required base metrics in valid order
    - Uses only valid metric values

    Args:
        vector_string: The CVSS vector string to validate.

    Returns:
        True if the vector string is valid, False otherwise.
    """
    if not vector_string or not isinstance(vector_string, str):
        return False

    # Use regex for fast validation
    if not CVSS_VECTOR_PATTERN.match(vector_string.strip()):
        return False

    # Also verify via parser for completeness
    return CVSSCalculator.parse_vector(vector_string.strip()) is not None


def get_cvss_metrics() -> dict:
    """Get all available CVSS v3.1 metric options for UI dropdowns.

    Returns a dictionary with metric abbreviations as keys, each containing:
    - name: English metric name
    - name_zh: Chinese metric name
    - required: Whether the metric is required
    - values: Dict of value abbreviations to labels and weights

    Returns:
        A dictionary of all CVSS v3.1 metric definitions.
    """
    return CVSS_METRICS
