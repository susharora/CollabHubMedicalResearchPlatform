"""
role_auditor.py — Auditor Role Menu and Actions
================================================
Implements all authorised actions for the Auditor role. Auditors operate
in a strictly read-only capacity. They can view audit events filtered by
scope and verify the cryptographic integrity of both the audit chain and
research findings.

AUDIT CHAIN VERIFICATION:
  The SHA-256 hash chain is verified by replaying the chain from GENESIS:
  for each event, recompute SHA-256(event_fields + prev_hash) and compare
  to the stored event_hash. Any mismatch indicates either:
    a) Tampering with that event's fields
    b) Insertion/deletion of events (breaks all subsequent hashes)
  WHY linear replay (not Merkle tree): Sequential replay is O(n) and
  simple to implement and audit. A Merkle tree would allow O(log n) proof
  of a single event but adds implementation complexity not justified for
  an audit log of thousands (not millions) of events.

RBAC ENFORCEMENT:
  Auditor has no entries in study_researchers or researcher_dataset_keys.
  The auditor menu contains NO write paths — all DB calls are SELECT-only.
  Even if an attacker escalated to auditor role, they could not modify data.
"""
import json
from datetime import datetime, timezone

from database import get_conn, write_audit_event
from ui_utils import (print_header, info, success, error, warn,
                      prompt, pause, choose, print_table)
from crypto_utils import compute_event_hash, ed25519_verify, b64d
from key_manager import load_user_ed_public


def auditor_menu(user: dict):
    while True:
        print_header(f"AUDITOR CONSOLE  ▸  {user['full_name']}")
        choice = choose([
            "View Audit Events",
            "Verify Audit Log Integrity (Hash Chain)",
            "Verify Research Finding Signatures",
            "Logout"
        ], "Select action")

        if choice == 1:
            view_audit_events(user)
        elif choice == 2:
            verify_audit_chain(user)
        elif choice == 3:
            verify_findings(user)
        elif choice == 4:
            write_audit_event(user["user_id"], "auditor", "Auditor Menu",
                              "LOGOUT", "Auditor logged out")
            info("Logged out. Returning to main menu.")
            pause()
            break
        else:
            pause()


def view_audit_events(user: dict):
    print_header("VIEW AUDIT EVENTS")
    c = choose([
        "All events (CollabHub level)",
        "By Study",
        "By Researcher",
        "By Clinician",
        "By Admin",
        "Back"
    ], "View events")

    if c == 6 or c < 0:
        return

    conn = get_conn()

    if c == 1:
        events = conn.execute("""
            SELECT event_id, event_seq, timestamp, actor_user_id, role,
                   menu_item, event_type, description, entity_type, entity_id,
                   study_id, event_hash
            FROM audit_log ORDER BY event_seq DESC LIMIT 200
        """).fetchall()
        scope = "All Events"

    elif c == 2:
        studies = conn.execute("SELECT study_id, study_name FROM studies ORDER BY study_name").fetchall()
        conn.close()
        if not studies:
            info("No studies found.")
            pause()
            return
        print_table(["#", "Study ID", "Name"],
                    [(i + 1, s["study_id"], s["study_name"]) for i, s in enumerate(studies)])
        idx = prompt("Select study #")
        try:
            idx = int(idx)
        except ValueError:
            pause()
            return
        if idx < 1 or idx > len(studies):
            pause()
            return
        study = studies[idx - 1]
        conn = get_conn()
        events = conn.execute("""
            SELECT event_id, event_seq, timestamp, actor_user_id, role,
                   menu_item, event_type, description, entity_type, entity_id,
                   study_id, event_hash
            FROM audit_log WHERE study_id=? ORDER BY event_seq DESC LIMIT 100
        """, (study["study_id"],)).fetchall()
        scope = f"Study: {study['study_name']}"

    elif c == 3:
        researchers = conn.execute(
            "SELECT user_id, full_name FROM users WHERE role='researcher' ORDER BY full_name"
        ).fetchall()
        conn.close()
        if not researchers:
            info("No researchers found.")
            pause()
            return
        print_table(["#", "User ID", "Name"],
                    [(i + 1, r["user_id"], r["full_name"]) for i, r in enumerate(researchers)])
        idx = prompt("Select researcher #")
        try:
            idx = int(idx)
        except ValueError:
            pause()
            return
        if idx < 1 or idx > len(researchers):
            pause()
            return
        researcher = researchers[idx - 1]
        conn = get_conn()
        events = conn.execute("""
            SELECT event_id, event_seq, timestamp, actor_user_id, role,
                   menu_item, event_type, description, entity_type, entity_id,
                   study_id, event_hash
            FROM audit_log WHERE actor_user_id=? AND role='researcher'
            ORDER BY event_seq DESC LIMIT 100
        """, (researcher["user_id"],)).fetchall()
        scope = f"Researcher: {researcher['full_name']}"

    elif c == 4:
        clinicians = conn.execute(
            "SELECT user_id, full_name FROM users WHERE role='clinician' ORDER BY full_name"
        ).fetchall()
        conn.close()
        if not clinicians:
            info("No clinicians found.")
            pause()
            return
        print_table(["#", "User ID", "Name"],
                    [(i + 1, cl["user_id"], cl["full_name"]) for i, cl in enumerate(clinicians)])
        idx = prompt("Select clinician #")
        try:
            idx = int(idx)
        except ValueError:
            pause()
            return
        if idx < 1 or idx > len(clinicians):
            pause()
            return
        clinician = clinicians[idx - 1]
        conn = get_conn()
        events = conn.execute("""
            SELECT event_id, event_seq, timestamp, actor_user_id, role,
                   menu_item, event_type, description, entity_type, entity_id,
                   study_id, event_hash
            FROM audit_log WHERE actor_user_id=? AND role='clinician'
            ORDER BY event_seq DESC LIMIT 100
        """, (clinician["user_id"],)).fetchall()
        scope = f"Clinician: {clinician['full_name']}"

    elif c == 5:
        conn.close()
        conn = get_conn()
        events = conn.execute("""
            SELECT event_id, event_seq, timestamp, actor_user_id, role,
                   menu_item, event_type, description, entity_type, entity_id,
                   study_id, event_hash
            FROM audit_log WHERE role='admin'
            ORDER BY event_seq DESC LIMIT 100
        """).fetchall()
        scope = "Admin Events"

    conn.close()

    print_header(f"AUDIT EVENTS — {scope}")
    if not events:
        info("No audit events found for this scope.")
        pause()
        return

    for ev in events:
        print(f"\n  ┌─ [{ev['event_seq']:04d}] {ev['timestamp']}")
        print(f"  │  Event   : {ev['event_type']}")
        print(f"  │  Actor   : {ev['actor_user_id']} ({ev['role']})")
        print(f"  │  Menu    : {ev['menu_item']}")
        print(f"  │  Details : {ev['description']}")
        if ev['study_id']:
            print(f"  │  Study   : {ev['study_id']}")
        if ev['entity_id']:
            print(f"  │  Entity  : {ev['entity_type']} / {ev['entity_id']}")
        print(f"  └─ Hash    : {ev['event_hash'][:32]}...")

    write_audit_event(user["user_id"], "auditor", "View Audit Events",
                      "AUDIT_VIEW", f"Auditor viewed audit events: {scope}")
    pause()


def verify_audit_chain(user: dict):
    print_header("VERIFY AUDIT LOG INTEGRITY")
    info("Verifying SHA-256 hash chain integrity across all audit events...")

    conn = get_conn()
    events = conn.execute(
        "SELECT * FROM audit_log ORDER BY event_seq ASC"
    ).fetchall()
    conn.close()

    if not events:
        info("No audit events to verify.")
        pause()
        return

    total = len(events)
    broken = []
    prev_hash = "GENESIS"

    for ev in events:
        event_data = {
            "event_id": ev["event_id"],
            "event_seq": ev["event_seq"],
            "timestamp": ev["timestamp"],
            "actor_user_id": ev["actor_user_id"],
            "role": ev["role"],
            "menu_item": ev["menu_item"],
            "event_type": ev["event_type"],
            "description": ev["description"],
            "entity_type": ev["entity_type"],
            "entity_id": ev["entity_id"],
            "study_id": ev["study_id"],
            "prev_hash": prev_hash,
        }
        expected_hash = compute_event_hash(event_data, prev_hash)

        if expected_hash != ev["event_hash"]:
            broken.append({
                "seq": ev["event_seq"],
                "event_id": ev["event_id"],
                "stored_hash": ev["event_hash"],
                "expected_hash": expected_hash
            })

        if ev["prev_hash"] != prev_hash:
            broken.append({
                "seq": ev["event_seq"],
                "event_id": ev["event_id"],
                "issue": "prev_hash mismatch",
                "stored": ev["prev_hash"],
                "expected": prev_hash
            })

        prev_hash = ev["event_hash"]

    if not broken:
        success(f"✔ Audit chain INTACT — all {total} events verified.")
        info("Hash chain is unbroken. No tampering detected.")
    else:
        error(f"✖ INTEGRITY FAILURE — {len(broken)} broken link(s) detected!")
        warn("POSSIBLE TAMPERING OR DATA CORRUPTION DETECTED")
        for b in broken[:5]:
            error(f"  Event #{b.get('seq')} ({b.get('event_id')}): {b}")

    write_audit_event(user["user_id"], "auditor", "Verify Audit Log Integrity",
                      "INTEGRITY_CHECK",
                      f"Auditor verified audit chain: {total} events, "
                      f"{'INTACT' if not broken else f'{len(broken)} failures'}")
    pause()


def verify_findings(user: dict):
    print_header("VERIFY RESEARCH FINDING SIGNATURES")

    conn = get_conn()
    findings = conn.execute("""
        SELECT f.finding_id, f.study_id, f.dataset_id, f.researcher_id,
               f.finding_text, f.signature_b64, f.signed_at,
               u.full_name as researcher_name,
               s.study_name, d.dataset_name
        FROM findings f
        JOIN users u ON f.researcher_id = u.user_id
        LEFT JOIN studies s ON f.study_id = s.study_id
        LEFT JOIN datasets d ON f.dataset_id = d.dataset_id
        ORDER BY f.signed_at DESC
    """).fetchall()
    conn.close()

    if not findings:
        info("No signed findings found.")
        pause()
        return

    print_table(
        ["#", "Finding ID", "Researcher", "Study", "Dataset", "Signed At"],
        [(i + 1, f["finding_id"], f["researcher_name"],
          f["study_name"] or f["study_id"] or "-",
          f["dataset_name"] or f["dataset_id"],
          f["signed_at"][:16]) for i, f in enumerate(findings)]
    )

    idx = prompt("Select finding # to verify (or 0 to verify all)")
    try:
        idx = int(idx)
    except ValueError:
        pause()
        return

    if idx == 0:
        to_verify = list(findings)
    elif 1 <= idx <= len(findings):
        to_verify = [findings[idx - 1]]
    else:
        pause()
        return

    verified_count = 0
    failed_count = 0

    for f in to_verify:
        print(f"\n  ── Finding: {f['finding_id']}")
        print(f"     Researcher : {f['researcher_name']} ({f['researcher_id']})")
        print(f"     Study      : {f['study_name'] or f['study_id'] or 'N/A'}")
        print(f"     Dataset    : {f['dataset_name'] or f['dataset_id']}")
        print(f"     Signed at  : {f['signed_at']}")
        print(f"     Finding    : {f['finding_text'][:80]}...")

        # Load researcher's Ed25519 public key
        try:
            ed_pub = load_user_ed_public(f["researcher_id"])
        except Exception as e:
            warn(f"     Cannot load signing key: {e}")
            failed_count += 1
            continue

        # Reconstruct the same canonical finding payload that the researcher signed.
        # This verifies integrity and authenticity of the stored finding record.
        try:
            sig_bytes = b64d(f["signature_b64"])

            signed_payload = {
                "finding_id": f["finding_id"],
                "study_id": f["study_id"] or "",
                "dataset_id": f["dataset_id"],
                "researcher_id": f["researcher_id"],
                "finding_text": f["finding_text"],
                "signed_at": f["signed_at"] }

            message = json.dumps(signed_payload, sort_keys=True).encode()
            ok = ed25519_verify(ed_pub, sig_bytes, message)
            
            info(f"     Signature  : {f['signature_b64'][:40]}...")
            info(f"     Key type   : Ed25519 (signing key loaded successfully)")
            info(f"     Verification: Ed25519 public key retrieved for {f['researcher_name']}")
            
            if ok:
                success("     Status     : Signature VALID — finding record is authenticated and unchanged.")
                verified_count += 1
            else:
                error("     Status     : Signature INVALID — finding record may have been altered.")
                failed_count += 1

        except Exception as e:
            error(f"     ✖ VERIFICATION FAILED: {e}")
            failed_count += 1

    print()
    if failed_count == 0:
        success(f"All {verified_count} finding(s) verified successfully.")
    else:
        warn(f"{verified_count} verified, {failed_count} failed.")

    write_audit_event(user["user_id"], "auditor", "Verify Research Finding Signatures",
                      "SIGNATURE_VERIFICATION",
                      f"Auditor verified {len(to_verify)} finding(s): "
                      f"{verified_count} OK, {failed_count} failed")
    pause()
