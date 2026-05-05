"""
role_clinician.py — Clinician Role Menu and Actions
====================================================
Implements all authorised actions for the Clinician role. Clinicians are
hospital-bound actors — they originate data and control its initial
distribution. They never access research findings or other hospitals' data.

GDPR COMPLIANCE DESIGN:
  Before any upload, the clinician must acknowledge a comprehensive GDPR
  consent statement. This creates an auditable record that the clinician
  was aware of the cross-border research use at upload time, addressing
  the "transparency" requirement of GDPR Art. 5(1)(a).

UPLOAD PIPELINE (PGP-style hybrid encryption):
  1. Hospital encrypts CSV with a one-time AES session key
  2. Hospital wraps session key with CollabHub RSA public key (incoming data key)
  3. Clinician uploads the encrypted payload to CollabHub
  4. CollabHub decrypts session key with incoming data private key
  5. CollabHub decrypts CSV and runs ingestion pipeline
  6. Two encrypted output files are produced (PII vault, research data)
  7. Two sets of wrapped DEKs are produced (org key for PII; clinician+master for research)

WHY PGP-STYLE (not TLS only):
  TLS protects data in transit but not at rest on CollabHub servers. PGP-style
  encryption ensures the hospital-encrypted payload can ONLY be decrypted by
  CollabHub — even a network observer with a TLS MITM certificate cannot read it.
"""

import csv
import json
import os
from datetime import datetime, timezone

from database import get_conn, write_audit_event
from ui_utils import (print_header, info, success, error, warn,
                      prompt, pause, choose, confirm_yn, print_table)
from key_manager import (load_user_rsa_private, load_system_key_public,
                         load_system_key_private, load_org_rsa_public,
                         save_wrapped_dek, load_wrapped_dek,
                         save_researcher_dek, load_user_rsa_public)
from crypto_utils import (aes_encrypt, aes_decrypt, generate_dek,
                           rsa_wrap_key, rsa_unwrap_key, secure_random_id,
                           generate_dataset_id, b64e, b64d)
from data_processor import process_dataset, validate_csv_schema
from policy_engine import evaluate_transfer

DATASETS_DIR = os.path.join(os.path.dirname(__file__), "datasets")

GDPR_CONSENT_TEXT = """
  ┌─────────────────────────────────────────────────────────────────────────┐
  │             CLINICIAN DATA UPLOAD — GDPR CONSENT STATEMENT              │
  ├─────────────────────────────────────────────────────────────────────────┤
  │  Before proceeding, please confirm you understand and agree to the      │
  │  following:                                                              │
  │                                                                          │
  │  • The patient dataset you are uploading will be used for cross-border  │
  │    clinical research across multiple independent organisations.          │
  │                                                                          │
  │  • You have obtained and hold on record the explicit, informed consent   │
  │    of each patient whose data is included, in compliance with            │
  │    GDPR Article 9 (Special Category Data) and applicable national law.  │
  │                                                                          │
  │  • You are authorised by your employing hospital institution to upload   │
  │    this data to the CollabHub platform.                                  │
  │                                                                          │
  │  • Patient data will undergo automated PII segregation — raw            │
  │    identifiable data will NOT be accessible to researchers.              │
  │                                                                          │
  │  • Records without valid patient consent markers will be automatically  │
  │    excluded from the research dataset.                                   │
  │                                                                          │
  │  • This upload will be logged in an immutable audit trail.              │
  │                                                                          │
  │  • You understand that misuse of this facility may result in legal       │
  │    proceedings under GDPR and your hospital's data governance policies. │
  └─────────────────────────────────────────────────────────────────────────┘
"""


def clinician_menu(user: dict, password: str):
    while True:
        print_header(f"CLINICIAN CONSOLE  ▸  {user['full_name']}")
        choice = choose([
            "Upload Patient Dataset",
            "List My Hospital's Datasets",
            "List Studies",
            "Assign Dataset to Study",
            "Logout"
        ], "Select action")

        if choice == 1:
            upload_patient_dataset(user, password)
        elif choice == 2:
            list_datasets(user)
        elif choice == 3:
            list_studies(user)
        elif choice == 4:
            assign_dataset_to_study(user, password)
        elif choice == 5:
            write_audit_event(user["user_id"], "clinician", "Clinician Menu",
                              "LOGOUT", "Clinician logged out")
            info("Logged out. Returning to main menu.")
            pause()
            break
        else:
            pause()


def upload_patient_dataset(user: dict, password: str):
    print_header("UPLOAD PATIENT DATASET")

    # GDPR Consent acknowledgement
    print(GDPR_CONSENT_TEXT)
    ack = prompt("I have read and agree to all the above statements [Y/N]")
    if ack.lower() not in ("y", "yes"):
        warn("Upload cancelled. Clinician consent not provided.")
        pause()
        return

    # Check for active incoming data key
    conn = get_conn()
    sys_key = conn.execute(
        "SELECT key_id, priv_enc FROM system_keys WHERE key_type='INCOMING_DATA' AND status='active' ORDER BY created_at DESC LIMIT 1"
    ).fetchone()
    org = conn.execute(
        "SELECT org_id, org_name, org_type, status, country FROM organisations WHERE org_id=?",
        (user["org_id"],)
    ).fetchone()
    conn.close()

    if not sys_key:
        error("No active Collab-Hub-Incoming-Data-key-pair found. Ask admin to generate one.")
        pause()
        return

    if not org or org["status"] != "verified":
        error("Your hospital organisation is not verified. Contact administrator.")
        pause()
        return

    if org["org_type"] != "hospital":
        error("Only clinicians from hospital organisations can upload patient data.")
        pause()
        return

    # Get path to encrypted CSV from hospital stub
    info("The hospital stub should have produced an encrypted payload file.")
    info("This file contains the CSV encrypted with a one-time session key,")
    info("and the session key wrapped with CollabHub's incoming data public key.")
    file_path = prompt("Enter path to encrypted hospital data file (or 'demo' for test data)")

    if file_path.lower() == "demo":
        # Use demo stub data
        records, session_key_wrapped = _load_demo_data(user)
        dataset_name = f"DEMO-{org['org_name']}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    else:
        if not os.path.exists(file_path):
            error(f"File not found: {file_path}")
            pause()
            return
        try:
            with open(file_path, "rb") as f:
                payload = json.load(f)
            session_key_wrapped = b64d(payload["wrapped_session_key"])
            encrypted_data = b64d(payload["encrypted_data"])
            dataset_name = payload.get("dataset_name", f"Dataset-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}")
        except Exception as e:
            error(f"Failed to parse encrypted file: {e}")
            pause()
            return

        # Decrypt session key with incoming data private key
        try:
            incoming_priv = load_system_key_private("Collab-Hub-Incoming-Data-key-pair")
            session_key = rsa_unwrap_key(incoming_priv, session_key_wrapped)
            decrypted_csv_bytes = aes_decrypt(session_key, encrypted_data)
            records = _parse_csv_bytes(decrypted_csv_bytes)
        except Exception as e:
            error(f"Decryption failed: {e}")
            pause()
            return

    if not records:
        error("No records found in dataset.")
        pause()
        return

    # Validate schema
    headers = list(records[0].keys()) if records else []
    valid, reason = validate_csv_schema(headers)
    if not valid:
        error(f"Schema validation failed: {reason}")
        pause()
        return

    info(f"Processing {len(records)} records through sanitisation and consent pipeline...")

    # Write upload audit event
    write_audit_event(user["user_id"], "clinician", "Upload Patient Dataset",
                      "DATASET_UPLOAD_INITIATED",
                      f"Clinician initiated upload of dataset '{dataset_name}' from {org['org_name']}",
                      "dataset", None)

    # Process dataset
    result = process_dataset(records)
    stats = result["stats"]
    pii_records = result["pii_records"]
    research_records = result["research_records"]

    info(f"Processing complete:")
    info(f"  Records processed : {stats['processed']}")
    info(f"  Records ingested  : {stats['ingested']}")
    info(f"  Records discarded : {stats['discarded']}")

    if result["errors"]:
        warn("Discarded records:")
        for e in result["errors"][:5]:
            print(f"     • {e}")
        if len(result["errors"]) > 5:
            print(f"     ... and {len(result['errors']) - 5} more.")

    if not research_records:
        warn("No consented records to store. Upload aborted.")
        pause()
        return

    # Generate dataset IDs
    dataset_id = generate_dataset_id()
    pii_dataset_id = generate_dataset_id()

    # Create dataset directories
    ds_dir = os.path.join(DATASETS_DIR, dataset_id)
    os.makedirs(ds_dir, exist_ok=True)

    # ── Encrypt PII vault ────────────────────────────────────────────────
    pii_dek = generate_dek()
    pii_plaintext = json.dumps(pii_records).encode()
    pii_encrypted = aes_encrypt(pii_dek, pii_plaintext)
    pii_file_path = os.path.join(ds_dir, f"{pii_dataset_id}_pii_vault.enc")
    with open(pii_file_path, "wb") as f:
        f.write(pii_encrypted)

    # Wrap PII DEK with hospital org public key
    try:
        org_pub = load_org_rsa_public(org["org_id"])
        pii_dek_wrapped = rsa_wrap_key(org_pub, pii_dek)
        pii_dek_path = os.path.join(ds_dir, f"{pii_dataset_id}_pii_dek.wrapped")
        with open(pii_dek_path, "wb") as f:
            f.write(pii_dek_wrapped)
    except Exception as e:
        error(f"Failed to wrap PII DEK with hospital key: {e}")
        pause()
        return

    # ── Encrypt Research Data ────────────────────────────────────────────
    research_dek = generate_dek()
    research_plaintext = json.dumps(research_records).encode()
    research_encrypted = aes_encrypt(research_dek, research_plaintext)
    research_file_path = os.path.join(ds_dir, f"{dataset_id}_research_data.enc")
    with open(research_file_path, "wb") as f:
        f.write(research_encrypted)

    # ── Wrap Research DEK: TWO INDEPENDENT wraps of the raw 32-byte DEK ────
    # WHY two independent wraps (not nested):
    #   RSA-4096-OAEP max plaintext = 446 bytes. An RSA ciphertext is 512 bytes.
    #   Wrapping the clinician-wrapped DEK (512 bytes) with the master key would
    #   exceed this limit and raise "Encryption failed". The correct design is
    #   two INDEPENDENT wraps of the same raw research_dek (32 bytes each).
    #   clinician copy → primary path for assign_dataset_to_study
    #   master copy    → fallback path for recovery if clinician key is lost

    # Wrap 1: clinician's RSA public key (primary)
    try:
        clinician_pub = load_user_rsa_public(user["user_id"])
        research_dek_wrapped_clinician = rsa_wrap_key(clinician_pub, research_dek)
    except Exception as e:
        error(f"Failed to wrap research DEK with clinician key: {e}")
        pause()
        return

    # Wrap 2: master RSA public key (independent fallback — wraps raw DEK, NOT the clinician output)
    try:
        master_pub = load_system_key_public("Collab-Hub-Master-Key-unassigned-datasets")
        research_dek_wrapped_master = rsa_wrap_key(master_pub, research_dek)   # raw DEK, not clinician output
    except Exception as e:
        error(f"Failed to wrap research DEK with master key: {e}")
        pause()
        return

    # Save both wrapped copies as separate files
    research_dek_clin_path   = os.path.join(ds_dir, f"{dataset_id}_research_dek_clin.wrapped")
    research_dek_master_path = os.path.join(ds_dir, f"{dataset_id}_research_dek_master.wrapped")
    with open(research_dek_clin_path, "wb") as f:
        f.write(research_dek_wrapped_clinician)
    with open(research_dek_master_path, "wb") as f:
        f.write(research_dek_wrapped_master)

    # ── Store metadata in DB ─────────────────────────────────────────────
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    conn.execute("""
        INSERT INTO datasets
        (dataset_id, pii_dataset_id, dataset_name, source_org_id, study_id,
         uploaded_by, status, encrypted_research_path, encrypted_pii_path,
         wrapped_research_dek_path, wrapped_master_dek_path, wrapped_pii_dek_path,
         records_processed, records_ingested, records_discarded,
         created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (dataset_id, pii_dataset_id, dataset_name, org["org_id"], None,
          user["user_id"], "unverified",
          research_file_path, pii_file_path,
          research_dek_clin_path, research_dek_master_path, pii_dek_path,
          stats["processed"], stats["ingested"], stats["discarded"],
          now, now))
    conn.commit()
    conn.close()

    # ── Audit events ─────────────────────────────────────────────────────
    write_audit_event(user["user_id"], "clinician", "Upload Patient Dataset",
                      "PII_VAULT_WRITTEN",
                      f"PII vault file written: {pii_dataset_id} ({len(pii_records)} records)",
                      "dataset", pii_dataset_id)

    write_audit_event(user["user_id"], "clinician", "Upload Patient Dataset",
                      "RESEARCH_DATA_WRITTEN",
                      f"Research data file written: {dataset_id} ({len(research_records)} records, "
                      f"{stats['discarded']} discarded for consent)",
                      "dataset", dataset_id)

    success(f"Dataset uploaded successfully!")
    info(f"  Research Dataset ID : {dataset_id}")
    info(f"  PII Dataset ID      : {pii_dataset_id}")
    info(f"  Status              : unverified (admin must verify before assignment)")
    pause()


def list_datasets(user: dict):
    print_header("MY HOSPITAL'S DATASETS")
    conn = get_conn()
    datasets = conn.execute("""
        SELECT d.dataset_id, d.pii_dataset_id, d.dataset_name, d.status,
               d.records_ingested, d.records_discarded, d.created_at,
               s.study_name
        FROM datasets d
        LEFT JOIN studies s ON d.study_id = s.study_id
        WHERE d.source_org_id = (
            SELECT org_id FROM users WHERE user_id=?
        )
        ORDER BY d.created_at DESC
    """, (user["user_id"],)).fetchall()
    conn.close()

    if not datasets:
        info("No datasets found for your hospital.")
        pause()
        return

    print_table(
        ["#", "Dataset ID", "Name", "Status", "Ingested", "Discarded", "Study", "Created"],
        [(i + 1, d["dataset_id"], d["dataset_name"], d["status"],
          d["records_ingested"], d["records_discarded"],
          d["study_name"] or "Unassigned", d["created_at"][:10])
         for i, d in enumerate(datasets)]
    )

    write_audit_event(user["user_id"], "clinician", "List Datasets",
                      "VIEW", "Clinician viewed hospital dataset list",
                      "organisation", user["org_id"])
    pause()


def list_studies(user: dict):
    print_header("AVAILABLE STUDIES")
    conn = get_conn()
    studies = conn.execute(
        "SELECT study_id, study_name, description, status FROM studies ORDER BY status, study_name"
    ).fetchall()
    conn.close()

    if not studies:
        info("No studies found.")
        pause()
        return

    print_table(
        ["#", "Study ID", "Name", "Status", "Description"],
        [(i + 1, s["study_id"], s["study_name"], s["status"],
          (s["description"] or "")[:40])
         for i, s in enumerate(studies)]
    )

    write_audit_event(user["user_id"], "clinician", "List Studies",
                      "VIEW", "Clinician viewed study list")
    pause()


def assign_dataset_to_study(user: dict, password: str):
    print_header("ASSIGN DATASET TO STUDY")

    conn = get_conn()
    # Show verified datasets from this hospital not yet assigned to a study
    datasets = conn.execute("""
        SELECT d.dataset_id, d.dataset_name, d.status, d.wrapped_research_dek_path
        FROM datasets d
        WHERE d.source_org_id = (SELECT org_id FROM users WHERE user_id=?)
        AND d.status = 'verified'
        AND d.study_id IS NULL
    """, (user["user_id"],)).fetchall()

    if not datasets:
        info("No verified unassigned datasets available. Datasets must be verified by admin first.")
        conn.close()
        pause()
        return

    print_table(["#", "Dataset ID", "Name", "Status"],
                [(i + 1, d["dataset_id"], d["dataset_name"], d["status"])
                 for i, d in enumerate(datasets)])

    didx = prompt("Select dataset # to assign")
    try:
        didx = int(didx)
    except ValueError:
        conn.close()
        pause()
        return
    if didx < 1 or didx > len(datasets):
        conn.close()
        pause()
        return
    dataset = datasets[didx - 1]

    # Select verified study
    studies = conn.execute(
        "SELECT study_id, study_name, legal_basis_countries "
        "FROM studies WHERE status='verified' ORDER BY study_name"
    ).fetchall()
    if not studies:
        conn.close()
        info("No verified studies available.")
        pause()
        return

    print_table(["#", "Study ID", "Name"],
                [(i + 1, s["study_id"], s["study_name"]) for i, s in enumerate(studies)])
    sidx = prompt("Select study # to assign dataset to")
    try:
        sidx = int(sidx)
    except ValueError:
        conn.close()
        pause()
        return
    if sidx < 1 or sidx > len(studies):
        conn.close()
        pause()
        return
    study = studies[sidx - 1]

    # Check cross-border policy
    clinician_org = conn.execute(
        "SELECT country FROM organisations WHERE org_id=(SELECT org_id FROM users WHERE user_id=?)",
        (user["user_id"],)
    ).fetchone()
    src_country = clinician_org["country"] if clinician_org else "XX"
    
    researchers = conn.execute("""
    SELECT 
        u.user_id,
        u.full_name,
        o.country,
        u.rsa_pub_pem
    FROM study_researchers sr
    JOIN users u ON sr.user_id = u.user_id
    JOIN organisations o ON u.org_id = o.org_id
    WHERE sr.study_id = ? 
      AND u.status = 'verified'
    """, (study["study_id"],)).fetchall()


    if not researchers:
        conn.close()
        warn("Cannot assign Dataset to Study as there is currently no aligned researcher for this study.")
        info("Please ask admin to assign researchers to this study first.")
        write_audit_event(user["user_id"], "clinician", "Assign Dataset to Study",
                          "ASSIGNMENT_FAILED_NO_RESEARCHERS",
                          f"Dataset assignment blocked: no researchers assigned to study '{study['study_name']}'",
                          "dataset", dataset["dataset_id"])
        pause()
        return

    # Cross-border policy check for each researcher
    # Parse study legal basis countries — stored as JSON array in DB.
    # These are countries for which the study admin has recorded an explicit
    # legal basis (GDPR Art. 46 / SCCs), permitting transfers that would
    # otherwise be blocked by the adequacy check alone.
    import json as _json
    raw_lbc = study["legal_basis_countries"] or "[]"
    try:
        study_legal_basis_countries = _json.loads(raw_lbc)
    except (ValueError, TypeError):
        study_legal_basis_countries = []

    # Cross-border policy check for each researcher
    blocked = []
    allowed = []
    for r in researchers:
        dst_country = r["country"] or "XX"
        ok, reason = evaluate_transfer(
            src_country, dst_country, "pseudonymised", "researcher",
            study_legal_basis_countries=study_legal_basis_countries
        )
        if ok:
            allowed.append(r)
        else:
            blocked.append((r, reason))

    if blocked:
        warn("Cross-border policy restrictions:")
        for r, reason in blocked:
            warn(f"  {r['full_name']} ({r['country']}): {reason}")

    if not allowed:
        error("Cross-border policy prevents sharing with ALL assigned researchers. Assignment blocked.")
        write_audit_event(user["user_id"], "clinician", "Assign Dataset to Study",
                          "ASSIGNMENT_FAILED_POLICY",
                          f"Dataset assignment blocked by cross-border policy for ALL researchers "
                          f"in study '{study['study_name']}'",
                          "dataset", dataset["dataset_id"])
        conn.close()
        pause()
        return

    info(f"Will grant access to {len(allowed)} researcher(s):")
    for r in allowed:
        info(f"  • {r['full_name']} ({r['country']})")

    if not confirm_yn("Proceed with assignment?"):
        conn.close()
        pause()
        return

    # CRYPTOGRAPHIC ASSIGNMENT LOGIC:
    # To give each researcher their own encrypted copy of the DEK, we must:
    #   1. Recover the plaintext DEK (unwrap with clinician's RSA private key)
    #   2. Re-encrypt (wrap) the DEK with each researcher's RSA public key
    # This means the clinician's password is required at assignment time.
    # WHY re-wrap (not share): Each researcher gets an independently encrypted
    # copy. Revoking one researcher's access (future feature) requires only
    # deleting their entry in researcher_dataset_keys and their key file —
    # other researchers are unaffected.
    # WHY clinician-wrapped as primary (not master key):
    # The clinician is the data originator and should be the primary access
    # grantee. The master key is a fallback for lost/compromised clinician keys.
    # ── DEK Recovery: clinician key primary, master key fallback ────────────
    # Two independent DEK copies protect against single-key compromise.
    # Close conn NOW before sequential writes to avoid SQLite "database is locked"
    dataset_id   = dataset["dataset_id"]
    dataset_name = dataset["dataset_name"]
    study_id_val = study["study_id"]
    study_name   = study["study_name"]

    master_path_row = conn.execute(
        "SELECT wrapped_master_dek_path FROM datasets WHERE dataset_id=?", (dataset_id,)
    ).fetchone()
    master_dek_path = master_path_row["wrapped_master_dek_path"] if master_path_row else None
    conn.close()  # ← prevent lock contention with subsequent write_audit_event calls

    research_dek    = None
    recovery_method = "clinician_key"

    try:  # Primary: clinician private key
        clinician_priv       = load_user_rsa_private(user["user_id"], password)
        clinician_wrapped    = load_wrapped_dek(dataset["wrapped_research_dek_path"])
        research_dek         = rsa_unwrap_key(clinician_priv, clinician_wrapped)

    except Exception as e1:
        warn(f"Clinician key DEK unwrap failed ({e1}). Trying master key fallback...")
        write_audit_event(user["user_id"], "clinician", "Assign Dataset to Study",
                          "DEK_UNWRAP_CLINICIAN_FAILED",
                          f"Clinician key DEK unwrap failed for {dataset_id}: {type(e1).__name__}",
                          "dataset", dataset_id)
        if master_dek_path:
            try:  # Fallback: master key
                master_priv      = load_system_key_private("Collab-Hub-Master-Key-unassigned-datasets")
                master_wrapped   = load_wrapped_dek(master_dek_path)
                research_dek     = rsa_unwrap_key(master_priv, master_wrapped)
                recovery_method  = "master_key_fallback"
                warn("DEK recovered via master key (defence-in-depth fallback activated).")
                write_audit_event(user["user_id"], "clinician", "Assign Dataset to Study",
                                  "DEK_RECOVERED_VIA_MASTER",
                                  f"Master key fallback used for DEK recovery on {dataset_id}",
                                  "dataset", dataset_id)
            except Exception as e2:
                error(f"Both clinician and master key DEK unwrap failed: {e2}")
                write_audit_event(user["user_id"], "clinician", "Assign Dataset to Study",
                                  "DEK_UNWRAP_TOTAL_FAILURE",
                                  f"All DEK recovery paths failed for {dataset_id}",
                                  "dataset", dataset_id)
                pause()
                return
        else:
            error("Cannot recover DEK — master key path not recorded.")
            write_audit_event(user["user_id"], "clinician", "Assign Dataset to Study",
                              "DEK_UNWRAP_FAILED",
                              f"DEK unwrap failed, no master key path for {dataset_id}",
                              "dataset", dataset_id)
            pause()
            return

    # ── Re-wrap DEK for each researcher (separate connections, no lock) ───────
    now = datetime.now(timezone.utc).isoformat()
    granted = 0
    for researcher in allowed:
        try:
            r_pub             = load_user_rsa_public(researcher["user_id"])
            res_wrapped_dek   = rsa_wrap_key(r_pub, research_dek)
            rdkey_path        = save_researcher_dek(dataset_id, researcher["user_id"], res_wrapped_dek)
            rdkey_id          = secure_random_id("RDK-")

            wconn = get_conn()
            wconn.execute("""
                INSERT OR REPLACE INTO researcher_dataset_keys
                (rdkey_id, dataset_id, user_id, wrapped_dek_path, created_at)
                VALUES (?,?,?,?,?)
            """, (rdkey_id, dataset_id, researcher["user_id"], rdkey_path, now))
            wconn.commit()
            wconn.close()

            write_audit_event(user["user_id"], "clinician", "Assign Dataset to Study",
                              "RESEARCHER_DEK_ISSUED",
                              f"Research DEK (via {recovery_method}) issued to "
                              f"'{researcher['full_name']}' for dataset '{dataset_id}'",
                              "dataset", dataset_id, study_id=study_id_val)
            granted += 1
        except Exception as e:
            warn(f"Failed to wrap DEK for researcher {researcher['full_name']}: {e}")
            write_audit_event(user["user_id"], "clinician", "Assign Dataset to Study",
                              "RESEARCHER_DEK_ISSUE_FAILED",
                              f"DEK issuance failed for {researcher['user_id']}: {type(e).__name__}",
                              "dataset", dataset_id)

    uconn = get_conn()
    uconn.execute("""
        UPDATE datasets SET study_id=?, status='assigned', updated_at=? WHERE dataset_id=?
    """, (study_id_val, now, dataset_id))
    uconn.commit()
    uconn.close()

    write_audit_event(user["user_id"], "clinician", "Assign Dataset to Study",
                      "DATASET_ASSIGNED_TO_STUDY",
                      f"Dataset '{dataset_name}' assigned to study '{study_name}'; "
                      f"DEK issued to {granted}/{len(allowed)} researchers",
                      "dataset", dataset_id, study_id=study_id_val)

    if granted < len(allowed):
        warn(f"Dataset assigned. {granted}/{len(allowed)} researcher DEKs issued.")
    else:
        success(f"Dataset '{dataset_name}' assigned to study '{study_name}'.")
        info(f"Access granted to {granted} researcher(s).")
    pause()
    pause()


def _load_demo_data(user: dict):
    """Load demo data from hospital stub output directory."""
    stub_dir = os.path.join(os.path.dirname(__file__), "data", "stub_output")
    # Find latest stub file for this hospital's org
    conn = get_conn()
    org = conn.execute(
        "SELECT org_name FROM organisations WHERE org_id=(SELECT org_id FROM users WHERE user_id=?)",
        (user["user_id"],)
    ).fetchone()
    conn.close()

    org_name = org["org_name"].replace(" ", "_") if org else "Hospital"
    # Look for existing stub data
    for fname in sorted(os.listdir(stub_dir), reverse=True) if os.path.exists(stub_dir) else []:
        if fname.endswith(".json"):
            try:
                with open(os.path.join(stub_dir, fname)) as f:
                    payload = json.load(f)
                # Just return the raw records for demo
                return payload.get("raw_records", []), None
            except Exception:
                pass
    return [], None


def _parse_csv_bytes(csv_bytes: bytes) -> list:
    """Parse CSV bytes into list of dicts."""
    import io
    text = csv_bytes.decode("utf-8")
    reader = csv.DictReader(io.StringIO(text))
    return [dict(row) for row in reader]
