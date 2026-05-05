"""
policy_engine.py — Cross-Border Policy Engine and Access Control for CollabHub
===============================================================================
Implements two layers of policy enforcement:

  1. DATA TRANSFER POLICY: Evaluate whether data of a given classification
     can flow from a source country to a researcher's destination country,
     based on EU adequacy decisions (GDPR Chapter V).

  2. STUDY-BASED ACCESS CONTROL: Verify that a researcher has been explicitly
     assigned to the study associated with a requested dataset.

WHY a dedicated policy module (not inline role logic):
  Centralising policy decisions means the same rules apply regardless of which
  code path triggers a data access. Inline checks are easy to forget or bypass;
  a single evaluate_transfer() function is a single point of enforcement.
  This follows the "Policy Decision Point" pattern from XACML/ABAC architectures.

WHY GDPR adequacy lists hard-coded (not a DB table):
  Adequacy decisions change rarely (every few years via EU Commission decision).
  A hard-coded set is easy to audit, version-control, and unit-test.
  A DB table would require admin UI to maintain and could be accidentally edited.
  Alternative: External policy file (JSON/YAML) — considered; rejected because
  it adds a file dependency and hot-reload complexity for rarely-changing data.
"""

import json
from typing import Tuple, List, Optional

# ── Adequacy Decisions ─────────────────────────────────────────────────────
# Adequacy countries are countries where the EU has evaluated their laws and confirmed adequacy of data protection. 
# Transfers to these countries are generally permitted under GDPR without additional safeguards. 
# This list includes EU member states (which are automatically considered adequate), EEA countries, and non-EU countries with adequacy decisions.
# Countries with EU adequacy decisions (GDPR Art. 45) or EEA membership.
# WHY ISO 3166-1 alpha-2 codes: Standard 2-letter codes are unambiguous and
# match the country field in user/organisation records.
ADEQUACY_COUNTRIES = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
    "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
    "PL", "PT", "RO", "SK", "SI", "ES", "SE",   # EU member states
    "IS", "LI", "NO",                           # EEA Iceland, Liechtenstein, Norway
    "CH", "JP", "CA", "NZ", "IL", "UY", "AR",   # Adequacy decisions
    "GB",                                       # UK (post-Brexit adequacy)
}

# Countries where transfer of pseudonymised research data is conditionally allowed
CONDITIONAL_COUNTRIES = {
    "US": "Standard Contractual Clauses(SCC) required",
    "AU": "Appropriate safeguards required",
    "SG": "Appropriate safeguards required",
    "KR": "Adequacy pending — SCCs required",
}

# Data classification levels
DATA_CLASSES = {
    "pseudonymised": 1,
    "anonymised": 0,
    "sensitive": 2,
    "pii": 3,
}

# Role-based restrictions
ROLE_MAX_DATA_CLASS = {
    "researcher": "pseudonymised",
    "clinician": "sensitive",
    "auditor": "pseudonymised",
    "admin": "sensitive",
}


def evaluate_transfer(
    source_country: str,
    destination_country: str,
    data_class: str,
    role: str,
    study_legal_basis_countries: Optional[List[str]] = None
) -> Tuple[bool, str]:
    """
    Evaluate whether a cross-border data transfer is permissible.

    Checks (in order):
      1. Role ceiling — researcher cannot receive PII regardless of geography
      2. Legal basis — if admin has recorded legal basis for this study in the
         destination country, transfer is permitted (GDPR Art. 6 / Art. 49 basis)
      3. Adequacy — destination in EU adequacy list → permitted
      4. Conditional — destination in conditional list → denied with guidance
      5. Default deny for all other destinations

    Args:
        source_country:              ISO 3166-1 alpha-2 code of data origin
        destination_country:         ISO 3166-1 alpha-2 code of researcher location
        data_class:                  'pseudonymised', 'anonymised', 'sensitive', 'pii'
        role:                        user role
        study_legal_basis_countries: list of ISO codes for which admin has
                                     confirmed legal basis in this specific study
    Returns:
        (allowed: bool, reason: str)

    WHY legal basis overrides adequacy check:
        GDPR Art. 46 allows transfers to non-adequacy countries where appropriate
        safeguards exist (standard contractual clauses, binding corporate rules,
        or explicit consent for the specific research). When the admin records a
        country in study_legal_basis_countries, they are asserting that such
        safeguards have been established for this specific study.
    """
    src = source_country.upper() if source_country else "XX"
    dst = destination_country.upper() if destination_country else "XX"

    # Check role data class ceiling first — applies regardless of geography
    max_class = ROLE_MAX_DATA_CLASS.get(role, "pseudonymised")
    if DATA_CLASSES.get(data_class, 99) > DATA_CLASSES.get(max_class, 0):
        return False, (
            f"Role '{role}' is not permitted to access '{data_class}' data. "
            f"Maximum permitted class: '{max_class}'."
        )

    # Same country is always permitted for non-PII data classes
    if src == dst:
        return True, f"Same country transfer ({src}) — permitted."

    # ── Legal basis check ─────────────────────────────────────────────────────
    # If the study admin has recorded a legal basis for the destination country,
    # the transfer is permitted even if that country lacks an adequacy decision.
    # This implements GDPR Art. 46 (appropriate safeguards) / Art. 49 derogations.
    if study_legal_basis_countries and dst in [c.upper() for c in study_legal_basis_countries]:
        if data_class != "pii":  # PII ceiling is absolute regardless of legal basis
            return True, (
                f"Transfer {src}\u2192{dst} of {data_class} data: Permitted — "
                f"recorded legal basis established for this study in {dst} "
                f"(GDPR Art. 46 / appropriate safeguards)."
            )

    # PII can never cross borders in this platform
    if data_class == "pii":
        return False, "PII data transfer across borders is prohibited under GDPR Art. 9."

    # Sensitive data: source must be adequacy country and destination must match
    if data_class == "sensitive":
        if dst not in ADEQUACY_COUNTRIES:
            return False, (
                f"Sensitive data cannot be transferred to '{dst}': "
                f"No EU adequacy decision or equivalent protection."
            )

    # Pseudonymised data rules
    if data_class == "pseudonymised":
        if dst in ADEQUACY_COUNTRIES:
            return True, f"Transfer {src}→{dst} of pseudonymised data: Permitted (adequacy/EEA)."
        if dst in CONDITIONAL_COUNTRIES:
            return False, (
                f"Transfer {src}→{dst} of pseudonymised data: CONDITIONAL — "
                f"{CONDITIONAL_COUNTRIES[dst]}. Manual review required."
            )
        return False, (
            f"Transfer {src}→{dst} of pseudonymised data: DENIED — "
            f"Destination country lacks adequate protection framework."
        )

    # Anonymised data — generally permissible
    if data_class == "anonymised":
        return True, f"Transfer {src}→{dst} of anonymised data: Permitted."

    return False, f"Unknown data class '{data_class}' — transfer denied by default."


def check_study_access(user_id: str, dataset_id: str, conn) -> Tuple[bool, str]:
    """
    Verify that a researcher has explicit study-based access to a dataset.

    Access model: Dataset → linked to Study → Study → linked to Researcher.
    A researcher can only access a dataset if ALL of the following hold:
      a) The dataset has status 'assigned' (has been linked to a study by clinician)
      b) The dataset is linked to an active/completed study
      c) The researcher is listed in study_researchers for that study

    WHY study-based (not direct dataset-researcher grants):
      Study-based access ensures structured governance. Direct grants could
      allow ad-hoc sharing that bypasses the study approval process.
    WHY check dataset status: An unassigned or revoked dataset should not be
      accessible even if the researcher is in the study.
    """
    row = conn.execute("""
        SELECT d.study_id, d.status as ds_status, s.status as st_status
        FROM datasets d
        LEFT JOIN studies s ON d.study_id = s.study_id
        WHERE d.dataset_id = ?
    """, (dataset_id,)).fetchone()

    if not row:
        return False, "Dataset not found."
    if row["ds_status"] != "assigned":
        return False, f"Dataset status is '{row['ds_status']}' — must be 'assigned'."
    if not row["study_id"]:
        return False, "Dataset is not linked to any study."
    if row["st_status"] not in ("verified", "completed"):
        return False, f"Study status is '{row['st_status']}' — must be 'verified' or 'completed'."

    # Check researcher is assigned to the study
    assignment = conn.execute("""
        SELECT 1 FROM study_researchers
        WHERE study_id = ? AND user_id = ?
    """, (row["study_id"], user_id)).fetchone()

    if not assignment:
        return False, "You are not assigned to the study associated with this dataset."

    return True, "Access granted."


def check_user_status(user_row) -> Tuple[bool, str]:
    """Verify user and their organisation are in valid state."""
    if not user_row:
        return False, "User not found."
    if user_row["status"] == "suspended":
        return False, "Your account has been suspended. Contact the administrator."
    if user_row["status"] == "unverified":
        return False, "Your account is pending verification by the administrator."
    if user_row["status"] == "invited":
        return False, "Your registration is incomplete."
    return True, "OK"
