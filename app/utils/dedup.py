"""
Vulnerability Deduplication Engine Module.

Provides functions to find duplicate vulnerabilities using multiple
matching strategies and merge them into canonical records.

Matching criteria (in priority order):
1. Exact match: same vuln_id (CVE) + same target
2. High similarity: same target + same port + name similarity > 0.8
3. Medium similarity: same target + name similarity > 0.7
"""

from __future__ import annotations

import difflib
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple


# ============================================================
# Severity ordering for comparison
# ============================================================

SEVERITY_ORDER: Dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "": 0,
}


def _get_severity_level(severity: str) -> int:
    """Get numeric severity level for comparison.

    Args:
        severity: The severity string (e.g. 'critical', 'high', etc.)

    Returns:
        Numeric severity level (higher = more severe).
    """
    return SEVERITY_ORDER.get((severity or "").strip().lower(), 0)


def _get_highest_severity(severities: List[str]) -> str:
    """Get the highest severity from a list of severity strings.

    Args:
        severities: List of severity strings.

    Returns:
        The highest severity string.
    """
    if not severities:
        return "info"
    return max(severities, key=lambda s: _get_severity_level(s))


def _calculate_name_similarity(name1: str, name2: str) -> float:
    """Calculate similarity ratio between two vulnerability names.

    Uses difflib.SequenceMatcher for fuzzy string matching.
    Names are normalized (lowercased, stripped) before comparison.

    Args:
        name1: First vulnerability name.
        name2: Second vulnerability name.

    Returns:
        Similarity ratio between 0.0 and 1.0.
    """
    if not name1 or not name2:
        return 0.0

    n1 = name1.strip().lower()
    n2 = name2.strip().lower()

    if n1 == n2:
        return 1.0

    return difflib.SequenceMatcher(None, n1, n2).ratio()


def _combine_cve_ids(vulns: List[Dict[str, Any]]) -> str:
    """Combine all unique CVE IDs from a list of vulnerabilities.

    Args:
        vulns: List of vulnerability dictionaries.

    Returns:
        Comma-separated string of unique CVE IDs.
    """
    cve_ids: Set[str] = set()
    for v in vulns:
        vuln_id = (v.get("vuln_id") or "").strip()
        if vuln_id:
            for cve in vuln_id.split(","):
                cve = cve.strip()
                if cve:
                    cve_ids.add(cve)

    return ", ".join(sorted(cve_ids)) if cve_ids else ""


def _combine_scanner_sources(vulns: List[Dict[str, Any]]) -> str:
    """Combine all unique scanner sources from a list of vulnerabilities.

    Args:
        vulns: List of vulnerability dictionaries.

    Returns:
        Comma-separated string of unique scanner sources.
    """
    sources: Set[str] = set()
    for v in vulns:
        source = (v.get("scanner_source") or "").strip()
        if source:
            for s in source.split(","):
                s = s.strip()
                if s:
                    sources.add(s)

    return ", ".join(sorted(sources)) if sources else ""


def _get_earliest_created_at(vulns: List[Dict[str, Any]]) -> str:
    """Get the earliest created_at timestamp from a list of vulnerabilities.

    Args:
        vulns: List of vulnerability dictionaries.

    Returns:
        The earliest created_at string, or the current time if none found.
    """
    timestamps: List[str] = []
    for v in vulns:
        ts = (v.get("created_at") or "").strip()
        if ts:
            timestamps.append(ts)

    if not timestamps:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        return min(timestamps, key=lambda t: datetime.strptime(t, "%Y-%m-%d %H:%M:%S"))
    except ValueError:
        try:
            return min(timestamps, key=lambda t: datetime.strptime(t, "%Y-%m-%d"))
        except ValueError:
            return timestamps[0]


def _get_most_complete_description(vulns: List[Dict[str, Any]]) -> str:
    """Get the most complete (longest non-empty) description from a list.

    Args:
        vulns: List of vulnerability dictionaries.

    Returns:
        The longest non-empty description string.
    """
    descriptions = [(v.get("description") or "").strip() for v in vulns]
    descriptions = [d for d in descriptions if d]
    if not descriptions:
        return ""
    return max(descriptions, key=len)


def _get_most_complete_field(vulns: List[Dict[str, Any]], field: str) -> str:
    """Get the most complete (longest non-empty) value for a given field.

    Args:
        vulns: List of vulnerability dictionaries.
        field: The field name to extract.

    Returns:
        The longest non-empty value for the field.
    """
    values = [(v.get(field) or "").strip() for v in vulns]
    values = [v for v in values if v]
    if not values:
        return ""
    return max(values, key=len)


# ============================================================
# Core Deduplication Functions
# ============================================================

def find_duplicates(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Find groups of duplicate vulnerabilities.

    Matching criteria (in priority order):
    1. Exact match: same vuln_id (CVE) + same target
    2. High similarity: same target + same port + name similarity > 0.8
    3. Medium similarity: same target + name similarity > 0.7

    Each vulnerability can only belong to one group. Groups are formed
    using the highest-priority matching criterion available.

    Args:
        vulnerabilities: List of vulnerability dictionaries. Each dict
            should have at least 'id', 'name', 'target', 'port', 'vuln_id'
            fields.

    Returns:
        A list of group dictionaries, each containing:
        - canonical: The representative vulnerability dict
        - duplicates: List of duplicate vulnerability dicts
        - match_type: String describing the match type
          ('exact', 'high_similarity', 'medium_similarity')
        - similarity: Float similarity score
    """
    if not vulnerabilities:
        return []

    groups: List[Dict[str, Any]] = []
    assigned: Set[str] = set()  # Track IDs already assigned to a group

    # Pass 1: Exact matches (same vuln_id + same target)
    exact_groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for vuln in vulnerabilities:
        vid = (vuln.get("vuln_id") or "").strip().lower()
        target = (vuln.get("target") or "").strip().lower()

        if vid and target:
            key = (vid, target)
            if key not in exact_groups:
                exact_groups[key] = []
            exact_groups[key].append(vuln)

    # Create groups from exact matches (groups with 2+ vulns)
    for idx, (key, vulns) in enumerate(exact_groups.items()):
        if len(vulns) >= 2:
            # Sort by created_at to pick the earliest as canonical
            vulns_sorted = sorted(
                vulns,
                key=lambda v: v.get("created_at", ""),
            )
            groups.append({
                "canonical": vulns_sorted[0],
                "duplicates": vulns_sorted[1:],
                "match_type": "exact",
                "similarity": 1.0,
            })
            for v in vulns:
                assigned.add(v.get("id") or f"_auto_{idx}_{hash(str(v.get('name','')) + v.get('target',''))}")

    # Get remaining vulnerabilities not yet assigned
    remaining = [v for v in vulnerabilities if v.get("id", "") not in assigned]

    # Pass 2: High similarity (same target + same port + name > 0.8)
    for i, vuln_a in enumerate(remaining):
        if vuln_a.get("id", "") in assigned:
            continue

        target_a = (vuln_a.get("target") or "").strip().lower()
        port_a = str(vuln_a.get("port") or "").strip()

        if not target_a:
            continue

        match_group = [vuln_a]

        for j, vuln_b in enumerate(remaining):
            if i == j or vuln_b.get("id", "") in assigned:
                continue

            target_b = (vuln_b.get("target") or "").strip().lower()
            port_b = str(vuln_b.get("port") or "").strip()

            if target_a != target_b:
                continue

            if port_a and port_b and port_a != port_b:
                continue

            name_a = (vuln_a.get("name") or "").strip()
            name_b = (vuln_b.get("name") or "").strip()

            similarity = _calculate_name_similarity(name_a, name_b)

            if similarity > 0.8:
                match_group.append(vuln_b)
                assigned.add(vuln_b.get("id", ""))

        if len(match_group) >= 2:
            match_group_sorted = sorted(
                match_group,
                key=lambda v: v.get("created_at", ""),
            )
            # Calculate average similarity for the group
            similarities = []
            for k in range(1, len(match_group_sorted)):
                sim = _calculate_name_similarity(
                    match_group_sorted[0].get("name", ""),
                    match_group_sorted[k].get("name", ""),
                )
                similarities.append(sim)
            avg_similarity = sum(similarities) / len(similarities) if similarities else 0.8

            groups.append({
                "canonical": match_group_sorted[0],
                "duplicates": match_group_sorted[1:],
                "match_type": "high_similarity",
                "similarity": round(avg_similarity, 4),
            })
            assigned.add(vuln_a.get("id", ""))

    # Refresh remaining
    remaining = [v for v in vulnerabilities if v.get("id", "") not in assigned]

    # Pass 3: Medium similarity (same target + name > 0.7)
    for i, vuln_a in enumerate(remaining):
        if vuln_a.get("id", "") in assigned:
            continue

        target_a = (vuln_a.get("target") or "").strip().lower()

        if not target_a:
            continue

        match_group = [vuln_a]

        for j, vuln_b in enumerate(remaining):
            if i == j or vuln_b.get("id", "") in assigned:
                continue

            target_b = (vuln_b.get("target") or "").strip().lower()

            if target_a != target_b:
                continue

            name_a = (vuln_a.get("name") or "").strip()
            name_b = (vuln_b.get("name") or "").strip()

            similarity = _calculate_name_similarity(name_a, name_b)

            if similarity > 0.7:
                match_group.append(vuln_b)
                assigned.add(vuln_b.get("id", ""))

        if len(match_group) >= 2:
            match_group_sorted = sorted(
                match_group,
                key=lambda v: v.get("created_at", ""),
            )
            similarities = []
            for k in range(1, len(match_group_sorted)):
                sim = _calculate_name_similarity(
                    match_group_sorted[0].get("name", ""),
                    match_group_sorted[k].get("name", ""),
                )
                similarities.append(sim)
            avg_similarity = sum(similarities) / len(similarities) if similarities else 0.7

            groups.append({
                "canonical": match_group_sorted[0],
                "duplicates": match_group_sorted[1:],
                "match_type": "medium_similarity",
                "similarity": round(avg_similarity, 4),
            })
            assigned.add(vuln_a.get("id", ""))

    return groups


def merge_vulnerabilities(group: Dict[str, Any]) -> Dict[str, Any]:
    """Merge a duplicate group into a single canonical vulnerability.

    Merge rules:
    - Keep the most complete description (longest non-empty)
    - Combine all scanner_source into comma-separated string
    - Keep highest severity
    - Keep all CVE IDs combined
    - Keep the earliest created_at
    - Keep canonical's id
    - For other fields, keep the most complete (longest non-empty) value

    Args:
        group: A group dictionary from find_duplicates(), containing:
            - canonical: The canonical vulnerability dict
            - duplicates: List of duplicate vulnerability dicts
            - match_type: String describing the match type
            - similarity: Float similarity score

    Returns:
        A merged vulnerability dictionary with combined data from all
        duplicates in the group.
    """
    canonical = group.get("canonical", {})
    duplicates = group.get("duplicates", [])

    if not duplicates:
        return dict(canonical)

    all_vulns = [canonical] + duplicates

    merged = dict(canonical)  # Start with canonical as base

    # Keep canonical's id
    merged["id"] = canonical.get("id", "")

    # Combine CVE IDs
    merged["vuln_id"] = _combine_cve_ids(all_vulns)

    # Keep the name from canonical (it's the representative)
    merged["name"] = canonical.get("name", "")

    # Keep highest severity
    all_severities = [v.get("severity", "info") for v in all_vulns]
    merged["severity"] = _get_highest_severity(all_severities)

    # Keep target from canonical
    merged["target"] = canonical.get("target", "")

    # Keep port from canonical
    merged["port"] = canonical.get("port", "")

    # Keep protocol from canonical or most complete
    merged["protocol"] = _get_most_complete_field(all_vulns, "protocol")

    # Keep most complete description
    merged["description"] = _get_most_complete_description(all_vulns)

    # Keep most complete impact
    merged["impact"] = _get_most_complete_field(all_vulns, "impact")

    # Keep most complete solution
    merged["solution"] = _get_most_complete_field(all_vulns, "solution")

    # Keep most complete poc_steps
    merged["poc_steps"] = _get_most_complete_field(all_vulns, "poc_steps")

    # Keep most complete evidence
    merged["evidence"] = _get_most_complete_field(all_vulns, "evidence")

    # Combine scanner sources
    merged["scanner_source"] = _combine_scanner_sources(all_vulns)

    # Keep earliest created_at
    merged["created_at"] = _get_earliest_created_at(all_vulns)

    # Merge custom tags
    all_tags: list = []
    for v in all_vulns:
        tags = v.get("custom_tags", [])
        if isinstance(tags, list):
            all_tags.extend(tags)
        elif isinstance(tags, str) and tags.strip():
            all_tags.extend([t.strip() for t in tags.split(",") if t.strip()])
    merged["custom_tags"] = list(set(all_tags)) if all_tags else []

    return merged
