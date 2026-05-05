"""
hospital_stub.py - Simulates hospital encrypting patient data with CollabHub's
incoming public key (PGP-style one-time session key encryption).

This is run SEPARATELY from the main CollabHub system.
Usage: python hospital_stub.py

It reads the CollabHub incoming data public key and produces an
encrypted payload file that the clinician uploads via the main system.
"""

import os
import sys
import json
import csv
import io
import random
from datetime import date, timedelta, datetime, timezone

# Add parent directory for imports
sys.path.insert(0, os.path.dirname(__file__))

from crypto_utils import (generate_dek, aes_encrypt, rsa_wrap_key,
                           load_public_key, b64e, secure_random_id)
from database import get_conn

STUB_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "data", "stub_output")

# ── Synthetic patient data generator ─────────────────────────────────────

FIRST_NAMES = ["Alice", "Bob", "Catherine", "David", "Eleanor", "Frank",
               "Grace", "Henry", "Isabella", "James", "Karen", "Liam",
               "Margaret", "Nathan", "Olivia", "Peter", "Quinn", "Rachel",
               "Samuel", "Teresa", "Uma", "Victor", "Wendy", "Xavier",
               "Yasmine", "Zachary"]

LAST_NAMES = ["Smith", "Jones", "Williams", "Brown", "Taylor", "Davies",
              "Evans", "Wilson", "Thomas", "Roberts", "Johnson", "Walker",
              "Wright", "Robinson", "Thompson", "White", "Hughes", "Edwards",
              "Green", "Hall", "Lewis", "Harris", "Clarke", "Patel", "Jackson"]

CITIES = ["London", "Manchester", "Birmingham", "Leeds", "Glasgow",
          "Edinburgh", "Cardiff", "Bristol", "Liverpool", "Sheffield",
          "Berlin", "Munich", "Hamburg", "Frankfurt", "Cologne"]

NATIONALITIES = ["British", "German", "French", "Italian", "Spanish",
                 "Polish", "Dutch", "Belgian", "Swedish", "Danish"]

CONDITIONS = ["Hypertension", "Type 2 Diabetes", "Asthma", "COPD",
              "Atrial Fibrillation", "Coronary Artery Disease",
              "Heart Failure", "Chronic Kidney Disease", "Anaemia",
              "Hypothyroidism", "Depression", "Anxiety Disorder",
              "Osteoarthritis", "Rheumatoid Arthritis", "Epilepsy"]

MEDICATIONS = ["Metformin", "Amlodipine", "Atorvastatin", "Ramipril",
               "Bisoprolol", "Warfarin", "Levothyroxine", "Omeprazole",
               "Salbutamol", "Sertraline", "Lisinopril", "Furosemide"]

BLOOD_TYPES = ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]


def random_date(start_year=1945, end_year=2005) -> str:
    start = date(start_year, 1, 1)
    end = date(end_year, 12, 31)
    delta = end - start
    return (start + timedelta(days=random.randint(0, delta.days))).strftime("%Y-%m-%d")


def random_consent_date() -> str:
    start = date(2019, 1, 1)
    end = date(2024, 12, 31)
    delta = end - start
    return (start + timedelta(days=random.randint(0, delta.days))).strftime("%Y-%m-%d")


def generate_patient_record(include_consent_rate: float = 0.65) -> dict:
    """Generate a synthetic patient record."""
    first = random.choice(FIRST_NAMES)
    last = random.choice(LAST_NAMES)
    city = random.choice(CITIES)
    country_code = "GB" if city in ["London", "Manchester", "Birmingham", "Leeds",
                                     "Glasgow", "Edinburgh", "Cardiff", "Bristol",
                                     "Liverpool", "Sheffield"] else "DE"
    dob = random_date()
    patient_id = f"PAT-{random.randint(100000, 999999)}"
    nhs_num = f"{random.randint(100, 999)}-{random.randint(100, 999)}-{random.randint(1000, 9999)}"
    address1 = f"{random.randint(1, 200)} {random.choice(['High Street', 'Church Lane', 'Oak Avenue', 'Mill Road', 'Park Drive'])}"
    postcode = f"{random.choice(['SW', 'SE', 'NW', 'E', 'N', 'W', 'EC'])}{random.randint(1,9)} {random.randint(1,9)}{random.choice('ABCDEFGHJKLMNPQRSTUVWXY')}{random.choice('ABCDEFGHJKLMNPQRSTUVWXY')}"

    # Consent: some records won't have consent
    has_consent = random.random() < include_consent_rate
    consent_val = "Yes" if has_consent else random.choice(["No", "", "Unknown"])
    consent_date = random_consent_date() if has_consent else (
        "" if random.random() < 0.3 else random_consent_date()
    )

    condition = random.choice(CONDITIONS)
    medication = random.choice(MEDICATIONS)

    return {
        "patient_id": patient_id,
        "nhs_number": nhs_num,
        "first_name": first,
        "last_name": last,
        "date_of_birth": dob,
        "place_of_birth": random.choice(CITIES),
        "nationality": random.choice(NATIONALITIES),
        "mothers_maiden_name": random.choice(LAST_NAMES),
        "address_line1": address1,
        "address_line2": random.choice(["", "Flat 2", "Unit B", "Ground Floor"]),
        "city": city,
        "postcode": postcode,
        "country": country_code,
        "gender": random.choice(["Male", "Female", "Non-binary"]),
        "blood_type": random.choice(BLOOD_TYPES),
        "ethnicity": random.choice(["White British", "Asian British", "Black British",
                                    "Mixed", "Other", "White European"]),
        "primary_condition": condition,
        "secondary_condition": random.choice(CONDITIONS + [""]),
        "current_medication": medication,
        "icd10_code": f"{random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}{random.randint(10, 99)}.{random.randint(0, 9)}",
        "admission_count": random.randint(0, 10),
        "bmi": round(random.uniform(18.0, 40.0), 1),
        "systolic_bp": random.randint(100, 180),
        "diastolic_bp": random.randint(60, 110),
        "hba1c": round(random.uniform(4.5, 12.0), 1) if condition == "Type 2 Diabetes" else "",
        "patient_consent": consent_val,
        "consent_date": consent_date,
    }


def generate_hospital_dataset(num_records: int = 10) -> list:
    return [generate_patient_record() for _ in range(num_records)]


def records_to_csv(records: list) -> bytes:
    """Convert list of dicts to CSV bytes."""
    if not records:
        return b""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=records[0].keys())
    writer.writeheader()
    writer.writerows(records)
    return output.getvalue().encode("utf-8")


def encrypt_and_package(records: list, collab_pub_pem: str, dataset_name: str) -> dict:
    """
    PGP-style encryption:
    1. Generate one-time session key (AES-256)
    2. Encrypt CSV data with session key
    3. Wrap session key with CollabHub incoming data public key
    4. Package as JSON payload
    """
    collab_pub = load_public_key(collab_pub_pem.encode())

    # Generate one-time session key
    session_key = generate_dek()

    # Encrypt CSV
    csv_bytes = records_to_csv(records)
    encrypted_data = aes_encrypt(session_key, csv_bytes)

    # Wrap session key with CollabHub public key
    wrapped_session_key = rsa_wrap_key(collab_pub, session_key)

    return {
        "dataset_name": dataset_name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "num_records": len(records),
        "wrapped_session_key": b64e(wrapped_session_key),
        "encrypted_data": b64e(encrypted_data),
    }


def run_stub():
    """Interactive stub to simulate hospital data upload."""
    print("\n" + "=" * 70)
    print("  HOSPITAL DATA STUB — CollabHub Simulation")
    print("  Simulates a hospital encrypting and submitting patient data")
    print("=" * 70)

    # Check for active incoming data key in system
    conn = get_conn()
    sys_key = conn.execute(
        "SELECT pub_pem, key_name FROM system_keys WHERE key_type='INCOMING_DATA' AND status='active' ORDER BY created_at DESC LIMIT 1"
    ).fetchone()
    conn.close()

    if not sys_key:
        print("\n  ERROR: No active Collab-Hub-Incoming-Data-key-pair found.")
        print("  Admin must generate this key first via Admin Console > Entity Management.")
        return

    print(f"\n  Using CollabHub key: {sys_key['key_name']}")
    print("\n  Generating synthetic patient dataset...")

    num_records = 10  # As specified
    records = generate_hospital_dataset(num_records)

    dataset_name = f"Hospital-Dataset-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

    print(f"  Generated {num_records} records for dataset: {dataset_name}")
    print("  Encrypting with one-time session key (AES-256-GCMSIV)...")
    print("  Wrapping session key with CollabHub RSA-4096 public key...")

    try:
        payload = encrypt_and_package(records, sys_key["pub_pem"], dataset_name)
    except Exception as e:
        print(f"\n  ERROR: Encryption failed: {e}")
        return

    # Save output
    os.makedirs(STUB_OUTPUT_DIR, exist_ok=True)
    output_file = os.path.join(STUB_OUTPUT_DIR,
                               f"hospital_payload_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json")

    # Also save raw records for demo mode
    payload["raw_records"] = records

    with open(output_file, "w") as f:
        json.dump(payload, f, indent=2)

    # Remove raw records from the actual payload (they'd only be in encrypted form)
    print(f"\n  ✔ Encrypted payload saved to:")
    print(f"    {output_file}")
    print(f"\n  Payload contents:")
    print(f"    - Wrapped session key : {payload['wrapped_session_key'][:40]}...")
    print(f"    - Encrypted data      : {payload['encrypted_data'][:40]}...")
    print(f"    - Records             : {payload['num_records']}")
    print(f"\n  → Clinician should use this file path in the Upload Dataset menu.")
    print("=" * 70)


if __name__ == "__main__":
    run_stub()
