"""
role_researcher.py — Researcher Role Menu and Actions
=====================================================
Implements all authorised actions for the Researcher role. Researchers
consume pseudonymised datasets for analysis and produce digitally signed
findings. They never access raw PII.

ACCESS CONTROL MODEL:
  Dataset access is governed by researcher_dataset_keys table:
  - Clinician assigns dataset to study → system wraps DEK per researcher
  - Researcher's private RSA key unwraps their personal DEK copy
  - Policy engine (check_study_access) enforces study membership check
  - Revoked datasets return no DEK entry → decryption impossible

SIGNING WORKFLOW:
  Findings are signed with Ed25519 over a canonical JSON payload
  containing finding_id, study_id, dataset_id, researcher_id,
  finding_text and signed_at. This allows the auditor to reconstruct
  the same payload from stored database fields and verify authenticity
  and integrity of the finding record. 
"""
import json
from datetime import datetime, timezone

from database import get_conn, write_audit_event
from ui_utils import (print_header, info, success, error, warn,
                      prompt, pause, choose, confirm_yn, print_table)
from key_manager import load_user_rsa_private, load_user_ed_private, load_user_ed_public
from crypto_utils import (aes_decrypt, ed25519_sign, secure_random_id, b64e, b64d)
from policy_engine import check_study_access


def researcher_menu(user: dict, password: str):
    while True:
        print_header(f"RESEARCHER CONSOLE  ▸  {user['full_name']}")
        choice = choose([
            "List Accessible Datasets",
            "Decrypt and Analyse Dataset",
            "View My Signed Findings",
            "Logout"
        ], "Select action")

        if choice == 1:
            list_accessible_datasets(user)
        elif choice == 2:
            decrypt_and_analyse(user, password)
        elif choice == 3:
            view_findings(user)
        elif choice == 4:
            write_audit_event(user["user_id"], "researcher", "Researcher Menu",
                              "LOGOUT", "Researcher logged out")
            info("Logged out. Returning to main menu.")
            pause()
            break
        else:
            pause()


def list_accessible_datasets(user: dict):
    print_header("ACCESSIBLE DATASETS")
    conn = get_conn()
    datasets = conn.execute("""
        SELECT d.dataset_id, d.dataset_name, d.status, d.records_ingested,
               s.study_name, s.study_id, d.created_at
        FROM researcher_dataset_keys rdk
        JOIN datasets d ON rdk.dataset_id = d.dataset_id
        LEFT JOIN studies s ON d.study_id = s.study_id
        WHERE rdk.user_id = ?
        AND d.status NOT IN ('revoked', 'suspended')
        ORDER BY d.created_at DESC
    """, (user["user_id"],)).fetchall()
    conn.close()

    if not datasets:
        info("You have no accessible datasets at this time.")
        info("Datasets are assigned to you when a clinician links them to your study.")
        pause()
        return

    print_table(
        ["#", "Dataset ID", "Name", "Study", "Status", "Records", "Uploaded"],
        [(i + 1, d["dataset_id"], d["dataset_name"],
          d["study_name"] or "-", d["status"],
          d["records_ingested"], d["created_at"][:10])
         for i, d in enumerate(datasets)]
    )

    write_audit_event(user["user_id"], "researcher", "List Accessible Datasets",
                      "VIEW", "Researcher viewed accessible datasets list")
    pause()


def decrypt_and_analyse(user: dict, password: str):
    print_header("DECRYPT AND ANALYSE DATASET")

    conn = get_conn()
    datasets = conn.execute("""
        SELECT d.dataset_id, d.dataset_name, d.status, d.encrypted_research_path,
               s.study_name, s.study_id, rdk.wrapped_dek_path
        FROM researcher_dataset_keys rdk
        JOIN datasets d ON rdk.dataset_id = d.dataset_id
        LEFT JOIN studies s ON d.study_id = s.study_id
        WHERE rdk.user_id = ?
        AND d.status = 'assigned'
        ORDER BY d.created_at DESC
    """, (user["user_id"],)).fetchall()

    if not datasets:
        info("No decryptable datasets available (must be 'assigned' status).")
        conn.close()
        pause()
        return

    print_table(
        ["#", "Dataset ID", "Name", "Study"],
        [(i + 1, d["dataset_id"], d["dataset_name"], d["study_name"] or "-")
         for i, d in enumerate(datasets)]
    )

    idx = prompt("Select dataset # to decrypt (or 0 to cancel)")
    try:
        idx = int(idx)
    except ValueError:
        conn.close()
        pause()
        return
    if idx == 0 or idx > len(datasets):
        conn.close()
        pause()
        return
    dataset = dict(datasets[idx - 1])

    # Policy check
    ok, reason = check_study_access(user["user_id"], dataset["dataset_id"], conn)
    conn.close()
    if not ok:
        error(f"Access denied: {reason}")
        pause()
        return

    # Decrypt DEK with researcher's RSA private key
    try:
        researcher_priv = load_user_rsa_private(user["user_id"], password)
        with open(dataset["wrapped_dek_path"], "rb") as f:
            wrapped_dek = f.read()
        from crypto_utils import rsa_unwrap_key
        research_dek = rsa_unwrap_key(researcher_priv, wrapped_dek)
    except Exception as e:
        error(f"Failed to decrypt data encryption key: {e}")
        write_audit_event(user["user_id"], "researcher", "Decrypt and Analyse Dataset",
                          "DECRYPT_DEK_FAILED",
                          f"DEK decryption failed: {type(e).__name__}",
                          "dataset", dataset.get("dataset_id"))
        pause()
        return

    # Decrypt research data
    try:
        with open(dataset["encrypted_research_path"], "rb") as f:
            encrypted_data = f.read()
        plaintext = aes_decrypt(research_dek, encrypted_data)
        records = json.loads(plaintext)
    except Exception as e:
        error(f"Failed to decrypt dataset: {e}")
        pause()
        return

    write_audit_event(user["user_id"], "researcher", "Decrypt and Analyse Dataset",
                      "DATASET_DECRYPTED",
                      f"Researcher decrypted dataset '{dataset['dataset_id']}'",
                      "dataset", dataset["dataset_id"],
                      study_id=dataset["study_id"])

    # Display data (pseudonymised)
    print_header(f"DATASET: {dataset['dataset_name']} ({len(records)} records)")
    info("Data shown is pseudonymised research data — no raw PII is present.")
    info("")

    # Display ALL records — no artificial limit
    # Columns are paginated: show first 8 fields in the table to fit terminal width.
    # All records are shown because researchers need the full dataset context
    # for their analysis. The user can scroll the terminal to view all rows.
    if records:
        headers = list(records[0].keys())
        # Show 8 cols max for terminal fit; truncate each value to 22 chars
        display_headers = headers[:8]
        rows = []
        for r in records:
            row = [str(r.get(h, ""))[:22] for h in display_headers]
            rows.append(row)
        print_table(display_headers, rows)
        if len(headers) > 8:
            info(f"({len(headers) - 8} additional columns not shown — all available in analysis)")

    pause("Press [Enter] to continue to analysis options...")

    # Analysis options
    while True:
        print_header("ANALYSIS OPTIONS")
        c = choose([
            "Mean age at which conditions are first recorded",
            "Distribution of conditions by consent year",
            "Top 5 most frequent recorded conditions",
            "Record and sign findings",
            "Back to menu"
        ], "Select analysis")

        if c == 1:
            _analyse_mean_age(records, dataset)
        elif c == 2:
            _analyse_by_year(records, dataset)
        elif c == 3:
            _analyse_top_conditions(records, dataset)
        elif c == 4:
            _sign_findings(user, password, dataset, records)
            break
        elif c == 5:
            break
        else:
            pause()

        if c in (1, 2, 3):
            if not confirm_yn("Run another analysis?"):
                if confirm_yn("Record and sign findings?"):
                    _sign_findings(user, password, dataset, records)
                break


def _analyse_mean_age(records: list, dataset: dict):
    print_header("MEAN AGE AT CONDITION RECORDING")
    ages = []
    for r in records:
        try:
            age = int(r.get("age_at_consent", 0))
            if age > 0:
                ages.append(age)
        except (ValueError, TypeError):
            pass

    if not ages:
        info("No age data available.")
        pause()
        return

    mean_age = sum(ages) / len(ages)
    min_age = min(ages)
    max_age = max(ages)

    info(f"Records with age data : {len(ages)}")
    info(f"Mean age at consent   : {mean_age:.1f} years")
    info(f"Age range             : {min_age} – {max_age} years")

    # Age bucket distribution
    buckets = {"<18": 0, "18-35": 0, "36-55": 0, "56-70": 0, ">70": 0}
    for age in ages:
        if age < 18:
            buckets["<18"] += 1
        elif age <= 35:
            buckets["18-35"] += 1
        elif age <= 55:
            buckets["36-55"] += 1
        elif age <= 70:
            buckets["56-70"] += 1
        else:
            buckets[">70"] += 1

    info("\n  Age Distribution:")
    for bucket, count in buckets.items():
        bar = "█" * (count * 20 // max(len(ages), 1))
        info(f"  {bucket:>8}  {bar} {count}")
    pause()


def _analyse_by_year(records: list, dataset: dict):
    print_header("RECORDS BY CONSENT YEAR")
    year_counts = {}
    for r in records:
        date_str = r.get("consent_date", "")
        if date_str and len(date_str) >= 4:
            year = date_str[:4]
            year_counts[year] = year_counts.get(year, 0) + 1

    if not year_counts:
        info("No consent date data available.")
        pause()
        return

    info("Consent Year  |  Count")
    info("-" * 25)
    for year in sorted(year_counts):
        bar = "█" * year_counts[year]
        info(f"  {year}         |  {year_counts[year]:4d}  {bar[:30]}")
    pause()


def _analyse_top_conditions(records: list, dataset: dict):
    print_header("TOP CONDITIONS IN DATASET")
    # Look for any 'condition', 'diagnosis', 'ailment' type fields
    condition_fields = [k for k in (records[0].keys() if records else [])
                        if any(kw in k.lower() for kw in
                               ["condition", "diagnosis", "ailment", "disease",
                                "icd", "disorder"])]
    if not condition_fields:
        info("No condition/diagnosis fields found in this dataset.")
        pause()
        return

    counts = {}
    for r in records:
        for field in condition_fields:
            val = str(r.get(field, "")).strip()
            if val and val.lower() not in ("", "none", "null", "n/a"):
                counts[val] = counts.get(val, 0) + 1

    if not counts:
        info("No condition data available.")
        pause()
        return

    top5 = sorted(counts.items(), key=lambda x: -x[1])[:5]
    info("Top Conditions:")
    for rank, (cond, cnt) in enumerate(top5, 1):
        bar = "█" * (cnt * 20 // max(counts.values()))
        info(f"  {rank}. {cond[:40]:<40}  {cnt:4d}  {bar}")
    pause()


def _sign_findings(user: dict, password: str, dataset: dict, records: list):
    print_header("RECORD AND SIGN FINDINGS")

    finding_text = prompt("Enter your research findings/observations")
    if not finding_text.strip():
        error("Finding text cannot be empty.")
        pause()
        return

    if not confirm_yn("Sign and record these findings?"):
        info("Signing cancelled.")
        pause()
        return

    # Assign finding_id for audit and reference — format FND-<random>
    finding_id = secure_random_id("FND-")

    # Sign with Ed25519 private key
    now = datetime.now(timezone.utc).isoformat()
    try:
        ed_priv = load_user_ed_private(user["user_id"], password)
        
        message = json.dumps({
            "finding_id": finding_id,
            "study_id": dataset.get("study_id", ""),
            "dataset_id": dataset["dataset_id"],
            "researcher_id": user["user_id"],
            "finding_text": finding_text,
            "signed_at": now,
        }, sort_keys=True).encode()

        signature = ed25519_sign(ed_priv, message)
        sig_b64 = b64e(signature)
    except Exception as e:
        error(f"Signing failed: {e}")
        pause()
        return

    
    
    conn = get_conn()
    conn.execute("""
        INSERT INTO findings (finding_id, study_id, dataset_id, researcher_id,
                              finding_text, signature_b64, signed_at)
        VALUES (?,?,?,?,?,?,?)
    """, (finding_id, dataset.get("study_id"), dataset["dataset_id"],
          user["user_id"], finding_text, sig_b64, now))
    conn.commit()
    conn.close()

    write_audit_event(user["user_id"], "researcher", "Decrypt and Analyse Dataset",
                      "FINDING_SIGNED",
                      f"Research finding signed and recorded for dataset '{dataset['dataset_id']}'",
                      "finding", finding_id,
                      study_id=dataset.get("study_id"))

    success(f"Finding signed and recorded: {finding_id}")
    info(f"Signature (Ed25519): {sig_b64[:40]}...")
    pause()


def view_findings(user: dict):
    print_header("MY SIGNED FINDINGS")
    conn = get_conn()
    findings = conn.execute("""
        SELECT f.finding_id, f.study_id, f.dataset_id, f.finding_text,
               f.signature_b64, f.signed_at,
               s.study_name, d.dataset_name
        FROM findings f
        LEFT JOIN studies s ON f.study_id = s.study_id
        LEFT JOIN datasets d ON f.dataset_id = d.dataset_id
        WHERE f.researcher_id = ?
        ORDER BY f.signed_at DESC
    """, (user["user_id"],)).fetchall()
    conn.close()

    if not findings:
        info("You have no signed findings yet.")
        pause()
        return

    for i, f in enumerate(findings, 1):
        print_header(f"Finding #{i} — {f['finding_id']}")
        info(f"Study   : {f['study_name'] or f['study_id'] or 'N/A'}")
        info(f"Dataset : {f['dataset_name'] or f['dataset_id']}")
        info(f"Signed  : {f['signed_at']}")
        info(f"Finding : {f['finding_text']}")

        # Verify signature
        try:
            ed_pub = load_user_ed_public(user["user_id"])
            # We need to reconstruct the message — just show signature status
            sig_bytes = b64d(f["signature_b64"])
            info(f"Signature (first 40 chars): {f['signature_b64'][:40]}...")
            info("Signature verification: auditor can verify the stored finding record using the researcher's Ed25519 public key.")
        except Exception as e:
            warn(f"Could not load public key for verification: {e}")

    write_audit_event(user["user_id"], "researcher", "View Signed Findings",
                      "VIEW", "Researcher viewed their signed findings")
    pause()
