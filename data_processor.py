"""
data_processor.py — Dataset Ingestion Pipeline for CollabHub
=============================================================
Implements the multi-stage pipeline that transforms raw hospital CSV data into
two separate encrypted streams: a PII vault and a pseudonymised research file.

PIPELINE STAGES:
  1. Sanitisation  — detect malicious payloads (SQL/script injection)
  2. Consent check — discard records without valid patient consent
  3. CH-UID gen    — assign a CollabHub unique identifier to each patient
  4. Segregation   — split record into PII fields and research fields
  5. Pseudonymise  — replace quasi-identifiers with deterministic tokens

WHY PYTHON-BASED PIPELINE (not SQL transforms):
  In production this pipeline would run in a DMZ (demilitarised zone) on
  data received from external parties before it touches internal systems.
  Python gives fine-grained control over field-level logic, regex-based
  injection detection, and deterministic pseudonymisation via hashlib.
  Alternative: dbt/SQL-based ELT — rejected because the sanitisation and
  consent checks require imperative logic not expressible in SQL WHERE clauses.
"""

import json
import re
import hashlib
import secrets
from datetime import datetime, date
from typing import Tuple, Dict, List


# ── PII field definitions ──────────────────────────────────────────────────

# PII_FIELDS: canonical set of field names classified as personal identifiable
# information under GDPR Art. 4(1). Any CSV column whose lowercase name appears
# here (or contains a substring from the OR-list in segregate_record) is routed
# exclusively to the PII vault. This list is intentionally conservative —
# false-positive PII classification is safer than a false negative.
# WHY a set (not a list): O(1) membership test for each field per record.
# Alternative: regex-based field classification — considered but rejected
# because explicit enumeration is easier to audit and less error-prone.
PII_FIELDS = {
    "first_name", "middle_name", "last_name", "surname",
    "date_of_birth", "dob", "place_of_birth",
    "nationality", "mothers_maiden_name",
    "address_line1", "address_line2", "postcode", "zip_code",
    "patient_id", "nhs_number", "ssn", "national_id",
    "phone", "email", "full_name", "name", "country"
}

# Fields that go to research data (pseudonymised)
PSEUDONYMISE_IN_RESEARCH = {"city", "gender", "ethnicity"}

# Consent fields
CONSENT_FIELD = "patient_consent"
CONSENT_DATE_FIELD = "consent_date"


def sanitise_record(record: dict) -> Tuple[bool, str]:
    """
    Stage 1: Detect malicious payload patterns in a CSV record before ingestion.
    Returns (is_safe: bool, reason: str).

    WHY regex-based detection: Provides a fast, deterministic check for known
    injection signatures without executing the content. This mirrors DMZ
    WAF (Web Application Firewall) rules applied to inbound data.
    WHY reject the whole record (not sanitise): Modifying the data would
    violate data integrity — we must store exactly what was consented to.
    Discarding is the safe choice; clinical data with injection strings
    indicates either a compromised hospital system or deliberate attack.
    Alternative: Parameterised query insertion (prevents SQL injection in DB
    writes) — used in addition, not instead: we want to detect AND reject
    malicious records before they touch any system component.
    """
    record_str = json.dumps(record)
    # Check for script injection patterns
    dangerous_patterns = [
        r"<script", r"javascript:", r"eval\s*\(", r"exec\s*\(",
        r"__import__", r"subprocess", r"os\.system",
        r"DROP\s+TABLE", r"DELETE\s+FROM", r"INSERT\s+INTO",
        r"UNION\s+SELECT", r";\s*--", r"'\s*OR\s*'1'\s*=\s*'1"
    ]
    for pattern in dangerous_patterns:
        if re.search(pattern, record_str, re.IGNORECASE):
            return False, f"Malicious pattern detected: {pattern}"
    return True, "OK"


def parse_consent_date(date_str: str):
    """Parse consent date, return date object or None."""
    if not date_str:
        return None
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%d-%m-%Y"):
        try:
            return datetime.strptime(date_str.strip(), fmt).date()
        except ValueError:
            continue
    return None


def compute_age_at_consent(dob_str: str, consent_date) -> int:
    """Compute integer age on consent date from DOB string."""
    if not dob_str or not consent_date:
        return None
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%d-%m-%Y"):
        try:
            dob = datetime.strptime(dob_str.strip(), fmt).date()
            age = consent_date.year - dob.year - (
                (consent_date.month, consent_date.day) < (dob.month, dob.day)
            )
            return age
        except ValueError:
            continue
    return None


def pseudonymise_value(value: str, ch_uid: str, field: str) -> str:
    """Pseudonymise a value deterministically using HMAC-SHA256."""
    seed = f"{ch_uid}:{field}:{value}"
    return "PSE-" + hashlib.sha256(seed.encode()).hexdigest()[:12].upper()


def generate_ch_uid() -> str:
    return "CH-" + secrets.token_hex(8).upper()


def segregate_record(record: dict, ch_uid: str) -> Tuple[dict, dict]:
    """
    Split record into PII vault entry and Research Data entry.
    Returns (pii_entry, research_entry).
    """
    pii_entry = {"ch_uid": ch_uid}
    research_entry = {"ch_uid": ch_uid}

    # Extract consent info
    consent_given = str(record.get(CONSENT_FIELD, "")).strip().lower()
    consent_date_str = record.get(CONSENT_DATE_FIELD, "")
    consent_date = parse_consent_date(str(consent_date_str))

    # Compute age from DOB
    dob_str = record.get("date_of_birth") or record.get("dob", "")
    age = compute_age_at_consent(str(dob_str), consent_date)

    for field, value in record.items():
        field_lower = field.lower()
        val_str = str(value) if value is not None else ""

        if field_lower in (CONSENT_FIELD, CONSENT_DATE_FIELD):
            # Keep consent info in research entry (date only)
            if field_lower == CONSENT_DATE_FIELD:
                research_entry["consent_date"] = val_str
            continue

        if field_lower in PII_FIELDS or any(pii in field_lower for pii in
                                             ["name", "address", "birth", "id", "nationality",
                                              "maiden", "phone", "email", "postcode", "zip",
                                              "nhs", "ssn"]):
            # Goes to PII vault
            pii_entry[field_lower] = val_str
        elif field_lower == "city":
            # Pseudonymised in research data
            research_entry["city_pseudo"] = pseudonymise_value(val_str, ch_uid, "city")
        elif field_lower in PSEUDONYMISE_IN_RESEARCH:
            research_entry[field_lower + "_pseudo"] = pseudonymise_value(val_str, ch_uid, field_lower)
        else:
            # Non-PII goes directly to research data
            research_entry[field_lower] = val_str

    # Add derived age field to research entry
    if age is not None:
        research_entry["age_at_consent"] = age

    # Store consent date in research
    research_entry["consent_date"] = str(consent_date) if consent_date else ""

    return pii_entry, research_entry


def process_dataset(raw_records: list) -> dict:
    """
    Full ingestion pipeline: sanitise → consent filter → CH-UID assign → segregate.
    Returns a dict with pii_records, research_records, stats, and errors.

    WHY record-level loop (not bulk SQL): Each record has independent consent,
    sanitisation, and segregation logic. A single malicious or non-consented
    record must not affect others — record-level processing ensures isolation.
    WHY collect errors not raise: Partial ingestion is correct behaviour;
    a single bad record should not abort the entire dataset. Errors are
    returned for audit logging.
    """
    pii_records = []
    research_records = []
    processed = 0
    discarded = 0
    errors = []

    for idx, record in enumerate(raw_records):
        processed += 1

        # Sanitise
        is_safe, reason = sanitise_record(record)
        if not is_safe:
            discarded += 1
            errors.append(f"Record {idx}: {reason}")
            continue

        # Consent check
        consent_val = str(record.get(CONSENT_FIELD, "")).strip().lower()
        consent_date_str = str(record.get(CONSENT_DATE_FIELD, "")).strip()

        if consent_val not in ("yes", "true", "1", "y"):
            discarded += 1
            errors.append(f"Record {idx}: No patient consent (value='{consent_val}')")
            continue

        if not consent_date_str or not parse_consent_date(consent_date_str):
            discarded += 1
            errors.append(f"Record {idx}: Invalid or missing consent date")
            continue

        # Generate CH-UID
        ch_uid = generate_ch_uid()

        # Segregate
        pii_entry, research_entry = segregate_record(record, ch_uid)
        pii_records.append(pii_entry)
        research_records.append(research_entry)

    ingested = len(pii_records)
    discarded_total = processed - ingested

    return {
        "pii_records": pii_records,
        "research_records": research_records,
        "stats": {
            "processed": processed,
            "ingested": ingested,
            "discarded": discarded_total
        },
        "errors": errors
    }


def validate_csv_schema(headers: list) -> Tuple[bool, str]:
    """Check that required consent fields are present."""
    headers_lower = [h.lower() for h in headers]
    if CONSENT_FIELD not in headers_lower:
        return False, f"Missing required field: '{CONSENT_FIELD}'"
    if CONSENT_DATE_FIELD not in headers_lower:
        return False, f"Missing required field: '{CONSENT_DATE_FIELD}'"
    return True, "OK"
