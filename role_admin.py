"""
role_admin.py — Administrator Role Menu and Actions
====================================================
Implements the System Governance role. The admin establishes trust anchors
(organisations, users, studies) and handles crisis management. The admin
does NOT access patient data — enforcing separation of duties.

SEPARATION OF DUTIES:
  Admin can verify users and organisations but cannot:
  - Upload patient data (clinician only)
  - Decrypt research data (researcher only)
  - Sign findings (researcher only)
  - The admin's RSA keypair is for system governance only

KEY GENERATION AT VERIFICATION:
  When admin changes a user status from unverified → verified, RSA and
  Ed25519 keypairs are generated for the user. WHY at verification:
  - Identity has been checked (3rd party verification)
  - Keys should not exist for unverified users (no data access)
  - Admin sets initial password; user changes on first login (future feature)

CRISIS MANAGEMENT:
  DEK revocation sets all study datasets to status='revoked'. This prevents
  new decryption (researcher_dataset_keys entries remain but dataset status
  check in check_study_access blocks access). WHY soft revocation: Hard
  deletion of key files would prevent forensic recovery; status='revoked'
  allows the dataset to be re-keyed after incident remediation.
"""
import os
import json
import secrets
from datetime import datetime, timezone

from database import get_conn, write_audit_event
from main import require_jit_reauth
from ui_utils import (print_header, info, success, error, warn,
                      prompt, prompt_password, pause, choose, confirm_yn, print_table)
from key_manager import (generate_user_keys, generate_org_keypair,
                         generate_system_key, load_system_key_public,
                         load_system_key_private, load_wrapped_dek,load_user_rsa_private,
                         save_wrapped_dek)
from crypto_utils import (rsa_wrap_key, rsa_unwrap_key, secure_random_id,
                           serialize_public_key, load_public_key, b64e, b64d,
                           hash_password)


# ─── Admin Menu ────────────────────────────────────────────────────────────

def admin_menu(user: dict):
    while True:
        print_header(f"ADMIN CONSOLE  ▸  {user['full_name']}")
        choice = choose([
            "Entity Management",
            "Study Management",
            "Crisis Management",
            "Logout"
        ], "Select action")

        if choice == 1:
            entity_management_menu(user)
        elif choice == 2:
            study_management_menu(user)
        elif choice == 3:
            crisis_management_menu(user)
        elif choice == 4:
            write_audit_event(user["user_id"], "admin", "Admin Menu",
                              "LOGOUT", "Admin logged out")
            info("Logged out. Returning to main menu.")
            pause()
            break
        else:
            pause("Press [Enter] to try again...")


# ─── Entity Management ─────────────────────────────────────────────────────

def verify_datasets(user: dict):
    """
    Allow admin to review and verify uploaded datasets.
    Datasets arrive with status='unverified' after clinician upload.
    Admin sets them to 'verified' after confirming the upload is
    legitimate and from an authorised organisation, enforcing the
    principle that data governance requires a human approval step
    before research access is granted (NIST SP 800-53 AC-5).

    Only 'verified' datasets appear in the clinician assignment list,
    so unverified datasets cannot reach researchers.
    """
    if not require_jit_reauth(user, "Verify Uploaded Datasets"):
        return

    print_header("VERIFY UPLOADED DATASETS")

    conn = get_conn()
    datasets = conn.execute("""
        SELECT d.dataset_id, d.dataset_name, d.status,
               d.records_ingested, d.records_discarded, d.created_at,
               u.full_name AS uploaded_by_name,
               o.org_name  AS org_name
        FROM   datasets d
        LEFT JOIN users         u ON d.uploaded_by   = u.user_id
        LEFT JOIN organisations o ON d.source_org_id = o.org_id
        ORDER BY d.created_at DESC
    """).fetchall()
    conn.close()

    if not datasets:
        info("No datasets found in the system.")
        pause()
        return

    # Show all datasets with current status so admin has full picture
    print_table(
        ["#", "Dataset ID", "Name", "Status", "Ingested", "Uploaded By", "Organisation", "Created"],
        [(i + 1,
          d["dataset_id"],
          d["dataset_name"][:28],
          d["status"],
          d["records_ingested"],
          d["uploaded_by_name"] or "—",
          d["org_name"] or "—",
          d["created_at"][:10])
         for i, d in enumerate(datasets)]
    )

    idx = prompt("Enter # to update dataset status (or 0 to cancel)")
    try:
        idx = int(idx)
    except ValueError:
        pause()
        return
    if idx == 0 or idx > len(datasets):
        pause()
        return

    ds = datasets[idx - 1]
    info(f"Dataset : {ds['dataset_name']} ({ds['dataset_id']})")
    info(f"Org     : {ds['org_name']}")
    info(f"Records : {ds['records_ingested']} ingested, {ds['records_discarded']} discarded")
    info(f"Current status: {ds['status']}")
    print()

    sc = choose(
        ["unverified", "verified", "suspended", "revoked"],
        "Set dataset status to"
    )
    if sc < 0:
        pause()
        return
    new_status = ["unverified", "verified", "suspended", "revoked"][sc - 1]

    if not confirm_yn(f"Set '{ds['dataset_name']}' to status '{new_status}'?"):
        info("Cancelled.")
        pause()
        return

    conn = get_conn()
    conn.execute(
        "UPDATE datasets SET status=?, updated_at=? WHERE dataset_id=?",
        (new_status, datetime.now(timezone.utc).isoformat(), ds["dataset_id"])
    )
    conn.commit()
    conn.close()

    write_audit_event(
        user["user_id"], "admin", "Verify Uploaded Datasets",
        "DATASET_STATUS_CHANGED",
        f"Dataset '{ds['dataset_name']}' ({ds['dataset_id']}) "
        f"status changed to '{new_status}' by admin",
        "dataset", ds["dataset_id"]
    )

    success(f"Dataset '{ds['dataset_name']}' is now '{new_status}'.")
    if new_status == "verified":
        info("Clinicians can now assign this dataset to a study.")
    pause()


def entity_management_menu(user: dict):
    while True:
        print_header("ENTITY MANAGEMENT")
        choice = choose([
            "Onboard Organisation (Hospital / Research Org / Auditor Firm)",
            "Update Organisation Status",
            "Invite New User (Create Account with Temporary Password)",
            "Update User Status (Verify / Suspend)",
            "Verify Uploaded Datasets",
            "Manage Collab-Hub-Master-Key (Unassigned Datasets)",
            "Manage Collab-Hub-Incoming-Data-key-pair",
            "Manage User Account Lockouts",
            "Back"
        ], "Select action")

        if choice == 1:
            onboard_organisation(user)
        elif choice == 2:
            update_org_status(user)
        elif choice == 3:
            send_invitation(user)
        elif choice == 4:
            update_user_status(user)
        elif choice == 5:
            verify_datasets(user)
        elif choice == 6:
            manage_master_key(user)
        elif choice == 7:
            manage_incoming_data_key(user)
        elif choice == 8:
            manage_user_lockouts(user)
        elif choice == 9:
            break
        else:
            pause()


def onboard_organisation(user: dict):
    print_header("ONBOARD ORGANISATION")
    org_name = prompt("Organisation name")
    if not org_name:
        error("Organisation name cannot be empty.")
        pause()
        return

    c = choose(["Hospital", "Research Organisation", "Auditor Firm"], "Organisation type")
    if c < 0:
        pause()
        return
    org_types = ["hospital", "research_org", "auditor_firm"]
    org_type = org_types[c - 1]

    country = prompt("Country (ISO 3166-1 alpha-2, e.g. GB, DE, US)")
    if not country or len(country) != 2:
        error("Invalid country code. Must be 2 letters.")
        pause()
        return

    conn = get_conn()
    existing = conn.execute("SELECT 1 FROM organisations WHERE org_name=?", (org_name,)).fetchone()
    if existing:
        conn.close()
        error(f"Organisation '{org_name}' already exists.")
        pause()
        return

    org_id = secure_random_id("ORG-")
    now = datetime.now(timezone.utc).isoformat()

    # Generate RSA keypair for org (used for PII DEK wrapping for hospitals)
    pub_pem = None
    if org_type == "hospital":
        keys = generate_org_keypair(org_id)
        pub_pem = keys["pub_pem"]

    conn.execute("""
        INSERT INTO organisations (org_id, org_name, org_type, country, status, public_key_pem, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?)
    """, (org_id, org_name, org_type, country.upper(), "unverified", pub_pem, now, now))
    conn.commit()
    conn.close()

    write_audit_event(user["user_id"], "admin", "Onboard Organisation",
                      "ORG_CREATED",
                      f"Organisation '{org_name}' ({org_type}) onboarded",
                      "organisation", org_id)

    success(f"Organisation '{org_name}' created with ID: {org_id}")
    info("Status: unverified — update status to 'verified' after 3rd party checks.")
    pause()


def update_org_status(user: dict):
    """
    Update organisation status — individually or all at once.
    Feedback-14: Bulk "verify all" option added for testing convenience.
    Clearly labelled as a testing aid with a confirmation dialog.
    JIT re-auth required before any changes.
    """
    if not require_jit_reauth(user, "Update Organisation Status"):
        return

    print_header("UPDATE ORGANISATION STATUS")
    conn = get_conn()
    orgs = conn.execute(
        "SELECT org_id, org_name, org_type, status, country FROM organisations ORDER BY org_name"
    ).fetchall()
    conn.close()

    if not orgs:
        info("No organisations found.")
        pause()
        return

    print_table(
        ["#", "Org ID", "Name", "Type", "Country", "Status"],
        [(i + 1, o["org_id"], o["org_name"], o["org_type"], o["country"], o["status"])
         for i, o in enumerate(orgs)]
    )

    # Offer bulk option for testing convenience
    print()
    info("Enter a # to update a single organisation, or:")
    info("  Enter 'ALL' to update ALL organisations at once  [TESTING CONVENIENCE — use with care]")
    print()

    raw = prompt("Selection (number or ALL, 0 to cancel)").strip().upper()

    statuses = ["unverified", "verified", "suspended"]

    if raw == "ALL":
        # ── Bulk update — testing convenience ────────────────────────────
        warn("⚠  BULK UPDATE — FOR TESTING CONVENIENCE ONLY")
        warn("   This will update ALL listed organisations to a single status.")
        warn("   In production, each organisation should be verified individually")
        warn("   after proper identity and data processing agreement checks.")
        print()
        info(f"Organisations affected ({len(orgs)}):")
        for o in orgs:
            info(f"  • {o['org_name']} (currently: {o['status']})")
        print()

        sc = choose(["unverified", "verified", "suspended"],
                    "Set ALL organisations to status")
        if sc < 0:
            pause()
            return
        new_status = statuses[sc - 1]

        if not confirm_yn(
            f"CONFIRM: Set ALL {len(orgs)} organisations to '{new_status}'?"
        ):
            info("Bulk update cancelled.")
            pause()
            return

        now = datetime.now(timezone.utc).isoformat()
        conn = get_conn()
        for o in orgs:
            conn.execute(
                "UPDATE organisations SET status=?, updated_at=? WHERE org_id=?",
                (new_status, now, o["org_id"])
            )
        conn.commit()
        conn.close()

        # One audit event per org for full traceability
        for o in orgs:
            write_audit_event(
                user["user_id"], "admin", "Update Organisation Status",
                "ORG_STATUS_CHANGED_BULK",
                f"[BULK UPDATE] Organisation '{o['org_name']}' "
                f"status changed to '{new_status}' (testing convenience)",
                "organisation", o["org_id"]
            )

        success(f"All {len(orgs)} organisations updated to '{new_status}'.")
        pause()
        return

    # ── Single organisation update ─────────────────────────────────────────
    try:
        idx = int(raw)
    except ValueError:
        pause()
        return
    if idx == 0 or idx > len(orgs):
        pause()
        return

    org = orgs[idx - 1]
    sc = choose(["unverified", "verified", "suspended"],
                f"New status for '{org['org_name']}' (current: {org['status']})")
    if sc < 0:
        pause()
        return
    new_status = statuses[sc - 1]

    conn = get_conn()
    conn.execute(
        "UPDATE organisations SET status=?, updated_at=? WHERE org_id=?",
        (new_status, datetime.now(timezone.utc).isoformat(), org["org_id"])
    )
    conn.commit()
    conn.close()

    write_audit_event(user["user_id"], "admin", "Update Organisation Status",
                      "ORG_STATUS_CHANGED",
                      f"Organisation '{org['org_name']}' status changed to '{new_status}'",
                      "organisation", org["org_id"])
    success(f"'{org['org_name']}' status updated to '{new_status}'.")
    pause()


def send_invitation(user: dict):
    """
    Feedback-7 / Feedback-15:
    Create a fully operational user account immediately — username auto-derived,
    temporary password generated, cryptographic keys generated, TOTP secret
    assigned. Credentials displayed on screen for the admin to share securely.

    WHY create the account immediately (not just send a token):
      In simulation mode there is no email delivery. Creating the account here
      gives the admin credentials to share right away and lets the invited user
      log in without any self-registration step. This mirrors enterprise HR
      on-boarding: IT creates the account, prints the credentials sheet, and
      hands it to the new employee.

    WHY status='verified' at creation (not 'invited'):
      'invited' status blocks login (check_user_status returns False).
      The admin creating the account IS the verification step in this prototype.
      must_change_password=1 ensures the user sets their own secret on first use.

    WHY keys generated now (not at first login):
      Clinicians need RSA keys before they can upload datasets; researchers need
      them before they can decrypt. Deferring key generation would leave the user
      unable to do anything until a second admin action. Generating with the temp
      password is safe because _force_password_change() re-encrypts the keys.
    """
    import string as _str
    import re

    print_header("INVITE NEW USER — Create Account with Temporary Password")

    # ── Personal details ────────────────────────────────────────────────────
    first_name = prompt("First name")
    last_name  = prompt("Last name")
    if not first_name or not last_name:
        error("First and last name are required.")
        pause()
        return

    email = prompt("Email address")
    if not email or "@" not in email:
        error("Invalid email address.")
        pause()
        return

    # mobile = prompt("Mobile number for MFA (e.g. +44 7700 900000, or Enter to skip )")
    # mobile = mobile.strip() or None

    mobile = prompt("Mobile number for MFA Format - /""+country code/"" /""space/"" /""Digits/"" (e.g. +44 7700900000): ").strip()

    # Basic UK/international format check    
    if not mobile:
        error("Mobile number is required.")
        pause()
        return        
        
    
    if not re.fullmatch(r"\+\d{1,3}\s?\d{7,15}", mobile):
        error("Invalid mobile number format. Use format like +44 7700900000")
        pause()    
        return 

    # ── Role ────────────────────────────────────────────────────────────────
    rc = choose(["Clinician", "Researcher", "Auditor"], "Role for this user")
    if rc < 0:
        pause()
        return
    role_map   = {1: "clinician",   2: "researcher",   3: "auditor"}
    prefix_map = {1: "cl_",         2: "res_",         3: "au_"}
    org_map   =  {1: "hospital",    2: "research_org", 3: "auditor_firm"}
    role   = role_map[rc]
    prefix = prefix_map[rc]
    org_type = org_map[rc]

    # ── Organisation ────────────────────────────────────────────────────────
    conn = get_conn()
    orgs = conn.execute(
        "SELECT org_id, org_name, org_type FROM organisations WHERE status='verified' and org_type=? ORDER BY org_name", (org_type,) 
    ).fetchall()
    if not orgs:
        conn.close()
        error("No verified organisations found. Verify an organisation first.")
        pause()
        return

    print_table(["#", "Org ID", "Name", "Type"],
                [(i + 1, o["org_id"], o["org_name"], o["org_type"]) for i, o in enumerate(orgs)])
    idx = prompt("Enter # of organisation")
    try:
        idx = int(idx)
    except ValueError:
        conn.close(); pause(); return
    if idx < 1 or idx > len(orgs):
        conn.close(); pause(); return
    org = orgs[idx - 1]

    # ── Auto-generate unique username ───────────────────────────────────────
    # Prefix encodes role for audit readability. Suffix is 6 cryptographically
    # random lowercase alphanumeric chars. Underscore is safe per POSIX and
    # common web standards (regex \w = [a-zA-Z0-9_]).
    _safe_chars = _str.ascii_lowercase + _str.digits
    while True:
        username = prefix + "".join(secrets.choice(_safe_chars) for _ in range(6))
        if not conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            break  # username is unique
    conn.close()

    # ── Generate temp password meeting complexity requirements ───────────────
    _pw_chars = _str.ascii_letters + _str.digits + "!@#$%"
    while True:
        temp_pw = "".join(secrets.choice(_pw_chars) for _ in range(12))
        if (any(ch.isupper() for ch in temp_pw) and
                any(ch.islower() for ch in temp_pw) and
                any(ch.isdigit() for ch in temp_pw) and
                any(ch in "!@#$%" for ch in temp_pw)):
            break

    # ── Generate TOTP secret ─────────────────────────────────────────────────
    from mfa_utils import generate_totp_secret
    totp_secret = generate_totp_secret()

    # ── Generate user ID and cryptographic keys ──────────────────────────────
    user_id   = secure_random_id("USR-")
    full_name = f"{first_name} {last_name}"
    now       = datetime.now(timezone.utc).isoformat()

    info("Generating cryptographic key pairs (this may take a moment)...")
    try:
        keys = generate_user_keys(user_id, role, temp_pw)
    except Exception as e:
        error(f"Key generation failed: {e}")
        pause()
        return

    # ── Create user record in DB ─────────────────────────────────────────────
    conn = get_conn()
    conn.execute("""
        INSERT INTO users
        (user_id, username, password_hash, role, full_name, email,
         org_id, country, status,
         rsa_pub_pem, rsa_priv_enc, ed_pub_pem, ed_priv_enc,
         mobile_number, totp_secret, must_change_password,
         created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        user_id, username, hash_password(temp_pw), role, full_name, email,
        org["org_id"], None, "unverified",                    # unverified = pending 3rd party che
        keys.get("rsa_pub_pem"), keys.get("rsa_priv_path"),
        keys.get("ed_pub_pem"),  keys.get("ed_priv_path"),
        mobile, totp_secret,
        1,                                                   # must_change_password on first login
        now, now
    ))

    # Audit record in invitations table
    token     = secrets.token_urlsafe(32)
    invite_id = secure_random_id("INV-")
    conn.execute("""
        INSERT INTO invitations
        (invite_id, email, role, org_id, token, status, created_by, created_at)
        VALUES (?,?,?,?,?,?,?,?)
    """, (invite_id, email, role, org["org_id"], token, "registered", user["user_id"], now))
    conn.commit()
    conn.close()

    write_audit_event(user["user_id"], "admin", "Invite New User",
                      "USER_CREATED_WITH_CREDENTIALS",
                      f"User account created: {full_name} ({role}) at {org['org_name']}, "
                      f"username={username}, status=verified, must_change_password=True",
                      "user", user_id)

    # ── Display credentials for admin to share ───────────────────────────────
    success(f"Account created for {full_name}.")
    print()
    print(f"  ╔════════════════════════════════════════════════════════════════╗")
    print(f"  ║  SHARE THESE CREDENTIALS SECURELY WITH THE USER               ║")
    print(f"  ╠════════════════════════════════════════════════════════════════╣")
    print(f"  ║  Full name         : {full_name:<42}║")
    print(f"  ║  Username          : {username:<42}║")
    print(f"  ║  Temporary password: {temp_pw:<42}║")
    print(f"  ║  Role              : {role:<42}║")
    print(f"  ║  Organisation      : {org['org_name']:<42}║")
    print(f"  ║  User ID           : {user_id:<42}║")
    print(f"  ╠════════════════════════════════════════════════════════════════╣")
    print(f"  ║  FIRST LOGIN INSTRUCTIONS FOR THE USER:                       ║")
    print(f"  ║  1. Select their role from the main menu                      ║")
    print(f"  ║  2. Enter username and temporary password above               ║")
    print(f"  ║  3. Enter MFA code shown on screen (simulation mode)          ║")
    print(f"  ║  4. They will be forced to set a new password                 ║")
    print(f"  ║  5. They will be automatically logged out                     ║")
    print(f"  ║  6. Log in again with new password + MFA to start working     ║")
    print(f"  ╚════════════════════════════════════════════════════════════════╝")
    print()
    pause()


def update_user_status(user: dict):
    """
    Update the verification status of a non-admin user account.

    This action is taken AFTER a 3rd-party identity check company has verified
    the user's submitted documents and confirmed their identity. The admin should
    only move a user to 'verified' once satisfied by that external check.

    Keys and credentials were already generated when the admin invited the user.
    The user already holds their temporary password and will be forced to change
    it on first login. No new credentials are issued here — this is purely a
    status gate controlling when the account becomes active.

    BULK UPDATE: An 'ALL' option is provided for testing convenience only.
    In production, each user must be verified individually after proper
    identity checks.
    """
    if not require_jit_reauth(user, "Update User Status"):
        return

    print_header("UPDATE USER STATUS")
    conn = get_conn()
    users = conn.execute("""
        SELECT u.user_id, u.full_name, u.role, u.email, u.status, o.org_name
        FROM users u LEFT JOIN organisations o ON u.org_id=o.org_id
        WHERE u.role != 'admin'
        ORDER BY u.role, u.full_name
    """).fetchall()
    conn.close()

    if not users:
        info("No non-admin users found.")
        pause()
        return

    print_table(
        ["#", "Name", "Role", "Org", "Email", "Status"],
        [(i + 1, u["full_name"], u["role"], u["org_name"] or "-",
          u["email"], u["status"]) for i, u in enumerate(users)]
    )

    print()
    info("Enter a # to update a single user, or:")
    info("  Enter 'ALL' to update ALL users at once  [TESTING CONVENIENCE — use with care]")
    print()

    raw = prompt("Selection (number or ALL, 0 to cancel)").strip().upper()
    statuses = ["unverified", "verified", "suspended"]

    if raw == "ALL":
        # ── Bulk update — testing convenience ────────────────────────────
        warn("⚠  BULK UPDATE — FOR TESTING CONVENIENCE ONLY")
        warn("   In production, each user must be verified individually")
        warn("   after proper 3rd-party identity and document checks.")
        print()
        info(f"Users affected ({len(users)}):")
        for u in users:
            info(f"  • {u['full_name']} ({u['role']}, currently: {u['status']})")
        print()

        c = choose(["unverified", "verified", "suspended"],
                   "Set ALL users to status")
        if c < 0:
            pause()
            return
        new_status = statuses[c - 1]

        if not confirm_yn(
            f"CONFIRM: Set ALL {len(users)} users to '{new_status}'?"
        ):
            info("Bulk update cancelled.")
            pause()
            return

        now = datetime.now(timezone.utc).isoformat()
        conn = get_conn()
        for u in users:
            conn.execute(
                "UPDATE users SET status=?, updated_at=? WHERE user_id=?",
                (new_status, now, u["user_id"])
            )
        conn.commit()
        conn.close()

        for u in users:
            write_audit_event(
                user["user_id"], "admin", "Update User Status",
                "USER_STATUS_CHANGED_BULK",
                f"[BULK UPDATE] User '{u['full_name']}' ({u['role']}) "
                f"status changed to '{new_status}' (testing convenience)",
                "user", u["user_id"]
            )

        success(f"All {len(users)} users updated to '{new_status}'.")
        if new_status == "verified":
            info("All users can now log in with their temporary passwords.")
        pause()
        return

    # ── Single user update ────────────────────────────────────────────────
    try:
        idx = int(raw)
    except ValueError:
        pause()
        return
    if idx == 0 or idx > len(users):
        pause()
        return

    target = users[idx - 1]
    c = choose(statuses,
               f"New status for '{target['full_name']}' (current: {target['status']})")
    if c < 0:
        pause()
        return
    new_status = statuses[c - 1]

    if new_status == "verified" and target["status"] != "verified":
        info(f"Verifying '{target['full_name']}' ({target['role']}).")
        info("Confirm that 3rd-party identity checks are complete and documents accepted.")
        info("The user already holds their temporary password from the invitation.")
        info("They will be required to change it on first login.")
        if not confirm_yn(f"Confirm verification of '{target['full_name']}'?"):
            info("Verification cancelled.")
            pause()
            return

    conn = get_conn()
    conn.execute(
        "UPDATE users SET status=?, updated_at=? WHERE user_id=?",
        (new_status, datetime.now(timezone.utc).isoformat(), target["user_id"])
    )
    conn.commit()
    conn.close()

    write_audit_event(user["user_id"], "admin", "Update User Status",
                      "USER_STATUS_CHANGED",
                      f"User '{target['full_name']}' ({target['role']}) "
                      f"status changed to '{new_status}'",
                      "user", target["user_id"])

    success(f"User '{target['full_name']}' status updated to '{new_status}'.")
    if new_status == "verified":
        info("User can now log in with their temporary password and will be prompted")
        info("to set a new password before accessing any system functions.")
    elif new_status == "suspended":
        warn("User login is now blocked. Reinstate by setting status to 'verified'.")
    pause()


def manage_master_key(user: dict):
    print_header("COLLAB-HUB MASTER KEY (Unassigned Datasets)")
    conn = get_conn()
    keys = conn.execute("""
        SELECT key_id, key_name, status, created_at
        FROM system_keys WHERE key_type='MASTER_UNASSIGNED'
        ORDER BY created_at DESC
    """).fetchall()
    conn.close()

    if keys:
        print_table(["#", "Key ID", "Name", "Status", "Created At"],
                    [(i + 1, k["key_id"], k["key_name"], k["status"], k["created_at"])
                     for i, k in enumerate(keys)])

    c = choose(["Generate New Master Key", "View Key Details", "Back"], "Action")
    if c == 1:
        _create_system_key(user, "Collab-Hub-Master-Key-unassigned-datasets", "MASTER_UNASSIGNED")
    elif c == 2:
        if not keys:
            info("No keys found.")
        else:
            info("Key details are stored securely on disk. Public PEM displayed below.")
            conn = get_conn()
            for k in keys:
                row = conn.execute("SELECT pub_pem FROM system_keys WHERE key_id=?",
                                   (k["key_id"],)).fetchone()
                if row and row["pub_pem"]:
                    print(f"\n  Key: {k['key_name']} ({k['status']})")
                    print(f"  {row['pub_pem'][:100]}...")
            conn.close()
    pause()


def manage_incoming_data_key(user: dict):
    print_header("COLLAB-HUB INCOMING DATA KEY PAIR")
    conn = get_conn()
    keys = conn.execute("""
        SELECT key_id, key_name, status, created_at
        FROM system_keys WHERE key_type='INCOMING_DATA'
        ORDER BY created_at DESC
    """).fetchall()
    conn.close()

    if keys:
        print_table(["#", "Key ID", "Name", "Status", "Created At"],
                    [(i + 1, k["key_id"], k["key_name"], k["status"], k["created_at"])
                     for i, k in enumerate(keys)])

    c = choose(["Generate New Incoming Data Key Pair", "View Public Key", "Back"], "Action")
    if c == 1:
        _create_system_key(user, "Collab-Hub-Incoming-Data-key-pair", "INCOMING_DATA")
        success("Public key is available for hospital stub to encrypt session keys.")
    elif c == 2:
        if not keys:
            info("No keys found.")
        else:
            conn = get_conn()
            latest = conn.execute(
                "SELECT pub_pem, key_name FROM system_keys WHERE key_type='INCOMING_DATA' AND status='active' ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            conn.close()
            if latest:
                print(f"\n  Active Key: {latest['key_name']}")
                print(f"\n{latest['pub_pem']}")
            else:
                info("No active incoming data key found.")
    pause()


def _create_system_key(user: dict, key_name: str, key_type: str):
    keys = generate_system_key(key_name)
    key_id = secure_random_id("SKEY-")
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    # Retire existing active keys
    conn.execute("UPDATE system_keys SET status='retired', updated_at=? WHERE key_type=? AND status='active'",
                 (now, key_type))
    # INSERT OR REPLACE handles the case where a key with this name already
    # exists (e.g. was created by the seeder). The previous UPDATE retired the
    # old row's status, but the UNIQUE constraint on key_name means a plain
    # INSERT would fail. OR REPLACE overwrites the existing row cleanly.
    conn.execute("""
        INSERT OR REPLACE INTO system_keys
        (key_id, key_name, key_type, pub_pem, priv_enc, status, created_by, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?)
    """, (key_id, key_name, key_type, keys["pub_pem"], keys["priv_path"], "active",
          user["user_id"], now, now))
    conn.commit()
    conn.close()

    write_audit_event(user["user_id"], "admin", "Manage System Key",
                      "SYSTEM_KEY_CREATED",
                      f"System key '{key_name}' (type: {key_type}) created",
                      "system_key", key_id)
    success(f"Key '{key_name}' generated and activated.")


# ─── Study Management ──────────────────────────────────────────────────────

def study_management_menu(user: dict):
    while True:
        print_header("STUDY MANAGEMENT")
        choice = choose([
            "Create Study",
            "Update Study Status",
            "Manage Study Legal Basis Countries",
            "View All Verified Researchers",
            "Assign Researcher to Study",
            "View Researchers Assigned to Study",
            "Remove Researcher from Study",
            "Back"
        ], "Select action")

        if choice == 1:
            create_study(user)
        elif choice == 2:
            update_study_status(user)
        elif choice == 3:
            manage_study_legal_basis(user)
        elif choice == 4:
            view_all_verified_researchers(user)
        elif choice == 5:
            assign_researcher(user)
        elif choice == 6:
            view_study_researchers(user)
        elif choice == 7:
            remove_researcher(user)
        elif choice == 8:
            break
        else:
            pause()


def create_study(user: dict):
    print_header("CREATE STUDY")
    name = prompt("Study name")
    if not name:
        error("Study name cannot be empty.")
        pause()
        return
    desc = prompt("Study description")

    # Optionally record legal basis countries at creation time.
    # These are countries outside the EU adequacy list for which the admin
    # has confirmed appropriate safeguards (SCCs etc.) exist for this study.
    # Format: comma-separated ISO codes e.g. "US, AU" — leave blank if none.
    info("Legal basis countries allow transfers to non-adequacy countries where")
    info("SCCs or other GDPR Art. 46 safeguards have been established.")
    lbc_raw = prompt("Legal basis countries (comma-separated ISO codes, or leave blank)")
    legal_basis_countries = _parse_legal_basis_input(lbc_raw)

    study_id = secure_random_id("STU-")
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    conn.execute("""
        INSERT INTO studies (study_id, study_name, description, status, created_by,
                             legal_basis_countries, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?)
    """, (study_id, name, desc, "unverified", user["user_id"],
          json.dumps(legal_basis_countries), now, now))
    conn.commit()
    conn.close()

    write_audit_event(user["user_id"], "admin", "Create Study",
                      "STUDY_CREATED",
                      f"Study '{name}' created. Legal basis countries: "
                      f"{legal_basis_countries if legal_basis_countries else 'none'}",
                      "study", study_id)
    success(f"Study created: {study_id}")
    if legal_basis_countries:
        info(f"Legal basis countries recorded: {', '.join(legal_basis_countries)}")
    info("Status: unverified — update to 'verified' to allow dataset assignment.")
    pause()

def _parse_legal_basis_input(raw: str) -> list:
    """
    Parse a comma-separated string of ISO country codes into a clean list.
    Uppercases, strips whitespace, and removes empty entries.
    e.g. "us, AU , sg" → ["US", "AU", "SG"]
    """
    if not raw or not raw.strip():
        return []
    return [c.strip().upper() for c in raw.split(",") if c.strip()]


def manage_study_legal_basis(user: dict):
    """
    View and update the legal basis countries for an existing study.
    These countries are used by the policy engine to permit transfers
    that would otherwise be blocked by the adequacy check (GDPR Art. 46).
    """
    print_header("MANAGE STUDY LEGAL BASIS COUNTRIES")

    conn = get_conn()
    studies = conn.execute(
        "SELECT study_id, study_name, status, legal_basis_countries "
        "FROM studies ORDER BY study_name"
    ).fetchall()
    conn.close()

    if not studies:
        info("No studies found.")
        pause()
        return

    print_table(
        ["#", "Study Name", "Status", "Legal Basis Countries"],
        [(i + 1, s["study_name"], s["status"],
          ", ".join(json.loads(s["legal_basis_countries"] or "[]")) or "none")
         for i, s in enumerate(studies)]
    )

    idx = prompt("Select study # to edit (or 0 to cancel)")
    try:
        idx = int(idx)
    except ValueError:
        pause()
        return
    if idx == 0 or idx < 1 or idx > len(studies):
        pause()
        return

    study = studies[idx - 1]
    current = json.loads(study["legal_basis_countries"] or "[]")

    info(f"Study    : {study['study_name']}")
    info(f"Current  : {', '.join(current) if current else 'none'}")
    info("Enter the full updated list of ISO country codes (replaces existing).")
    info("Example  : US, AU, SG   — or leave blank to clear all.")

    lbc_raw = prompt("Legal basis countries (comma-separated ISO codes)")
    new_list = _parse_legal_basis_input(lbc_raw)

    if not confirm_yn(
        f"Set legal basis countries for '{study['study_name']}' to "
        f"{new_list if new_list else 'NONE (clear all)'}?"
    ):
        info("No changes made.")
        pause()
        return

    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    conn.execute(
        "UPDATE studies SET legal_basis_countries=?, updated_at=? WHERE study_id=?",
        (json.dumps(new_list), now, study["study_id"])
    )
    conn.commit()
    conn.close()

    write_audit_event(user["user_id"], "admin", "Manage Study Legal Basis Countries",
                      "STUDY_LEGAL_BASIS_UPDATED",
                      f"Study '{study['study_name']}' legal basis countries updated "
                      f"from {current} to {new_list}",
                      "study", study["study_id"])

    success(f"Legal basis countries updated.")
    if new_list:
        info(f"Transfers to {', '.join(new_list)} are now permitted for this study "
             f"subject to GDPR Art. 46 safeguards.")
    else:
        info("All legal basis overrides cleared. Only adequacy-listed countries permitted.")
    pause()

def update_study_status(user: dict):
    print_header("UPDATE STUDY STATUS")
    conn = get_conn()
    studies = conn.execute("SELECT study_id, study_name, status FROM studies ORDER BY study_name").fetchall()
    conn.close()

    if not studies:
        info("No studies found.")
        pause()
        return

    print_table(["#", "Study ID", "Name", "Status"],
                [(i + 1, s["study_id"], s["study_name"], s["status"]) for i, s in enumerate(studies)])

    idx = prompt("Enter # of study (or 0 to cancel)")
    try:
        idx = int(idx)
    except ValueError:
        pause()
        return
    if idx == 0 or idx > len(studies):
        pause()
        return

    s = studies[idx - 1]
    c = choose(["unverified", "verified", "completed", "suspended"],
               f"New status for '{s['study_name']}'")
    if c < 0:
        pause()
        return
    statuses = ["unverified", "verified", "completed", "suspended"]
    new_status = statuses[c - 1]

    conn = get_conn()
    conn.execute("UPDATE studies SET status=?, updated_at=? WHERE study_id=?",
                 (new_status, datetime.now(timezone.utc).isoformat(), s["study_id"]))
    conn.commit()
    conn.close()

    write_audit_event(user["user_id"], "admin", "Update Study Status",
                      "STUDY_STATUS_CHANGED",
                      f"Study '{s['study_name']}' status changed to '{new_status}'",
                      "study", s["study_id"])
    success(f"Study status updated to '{new_status}'.")
    pause()


def view_all_verified_researchers(user: dict):
    print_header("ALL VERIFIED RESEARCHERS")
    conn = get_conn()
    researchers = conn.execute("""
        SELECT u.user_id, u.full_name, u.email, o.org_name, u.country, u.status
        FROM users u LEFT JOIN organisations o ON u.org_id=o.org_id
        WHERE u.role='researcher' AND u.status='verified'
        ORDER BY o.org_name, u.full_name
    """).fetchall()
    conn.close()

    if not researchers:
        info("No verified researchers found.")
        pause()
        return

    print_table(
        ["#", "User ID", "Name", "Email", "Organisation", "Country"],
        [(i + 1, r["user_id"], r["full_name"], r["email"],
          r["org_name"] or "-", r["country"] or "-")
         for i, r in enumerate(researchers)]
    )
    write_audit_event(user["user_id"], "admin", "View All Verified Researchers",
                      "VIEW", "Admin viewed all verified researchers")
    pause()


def assign_researcher(user: dict):
    print_header("ASSIGN RESEARCHER TO STUDY")
    conn = get_conn()

    studies = conn.execute(
        "SELECT study_id, study_name FROM studies WHERE status='verified' ORDER BY study_name"
    ).fetchall()
    if not studies:
        conn.close()
        info("No verified studies available.")
        pause()
        return

    print_table(["#", "Study ID", "Name"],
                [(i + 1, s["study_id"], s["study_name"]) for i, s in enumerate(studies)])
    idx = prompt("Select study #")
    try:
        idx = int(idx)
    except ValueError:
        conn.close()
        pause()
        return
    if idx < 1 or idx > len(studies):
        conn.close()
        pause()
        return
    study = studies[idx - 1]

    researchers = conn.execute("""
        SELECT u.user_id, u.full_name, u.email, o.org_name
        FROM users u LEFT JOIN organisations o ON u.org_id=o.org_id
        WHERE u.role='researcher' AND u.status='verified'
        AND u.user_id NOT IN (
            SELECT user_id FROM study_researchers WHERE study_id=?
        )
        ORDER BY u.full_name
    """, (study["study_id"],)).fetchall()

    if not researchers:
        conn.close()
        info("No unassigned verified researchers available.")
        pause()
        return

    print_table(["#", "Name", "Email", "Organisation"],
                [(i + 1, r["full_name"], r["email"], r["org_name"] or "-")
                 for i, r in enumerate(researchers)])
    ridx = prompt("Select researcher #")
    try:
        ridx = int(ridx)
    except ValueError:
        conn.close()
        pause()
        return
    if ridx < 1 or ridx > len(researchers):
        conn.close()
        pause()
        return
    researcher = researchers[ridx - 1]

    now = datetime.now(timezone.utc).isoformat()
    conn.execute("""
        INSERT OR IGNORE INTO study_researchers (study_id, user_id, assigned_at, assigned_by)
        VALUES (?,?,?,?)
    """, (study["study_id"], researcher["user_id"], now, user["user_id"]))
    conn.commit()
    conn.close()

    write_audit_event(user["user_id"], "admin", "Assign Researcher to Study",
                      "RESEARCHER_ASSIGNED",
                      f"Researcher '{researcher['full_name']}' assigned to study '{study['study_name']}'",
                      "study", study["study_id"], study_id=study["study_id"])
    success(f"Researcher '{researcher['full_name']}' assigned to study '{study['study_name']}'.")
    pause()


def view_study_researchers(user: dict):
    print_header("VIEW STUDY RESEARCHERS")
    conn = get_conn()
    studies = conn.execute("SELECT study_id, study_name, status FROM studies ORDER BY study_name").fetchall()
    conn.close()

    if not studies:
        info("No studies found.")
        pause()
        return

    print_table(["#", "Study ID", "Name", "Status"],
                [(i + 1, s["study_id"], s["study_name"], s["status"]) for i, s in enumerate(studies)])
    idx = prompt("Select study # to view researchers")
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
    researchers = conn.execute("""
        SELECT u.full_name, u.email, o.org_name, sr.assigned_at
        FROM study_researchers sr
        JOIN users u ON sr.user_id=u.user_id
        LEFT JOIN organisations o ON u.org_id=o.org_id
        WHERE sr.study_id=?
        ORDER BY u.full_name
    """, (study["study_id"],)).fetchall()
    conn.close()

    if not researchers:
        info(f"No researchers assigned to study '{study['study_name']}'.")
    else:
        print_table(
            ["Name", "Email", "Organisation", "Assigned At"],
            [(r["full_name"], r["email"], r["org_name"] or "-", r["assigned_at"])
             for r in researchers]
        )

    write_audit_event(user["user_id"], "admin", "View Study Researchers",
                      "VIEW", f"Admin viewed researchers for study '{study['study_name']}'",
                      "study", study["study_id"])
    pause()


def remove_researcher(user: dict):
    print_header("REMOVE RESEARCHER FROM STUDY")
    conn = get_conn()
    studies = conn.execute("SELECT study_id, study_name FROM studies WHERE status='verified'").fetchall()
    if not studies:
        conn.close()
        info("No verified studies.")
        pause()
        return

    print_table(["#", "Study ID", "Name"],
                [(i + 1, s["study_id"], s["study_name"]) for i, s in enumerate(studies)])
    idx = prompt("Select study #")
    try:
        idx = int(idx)
    except ValueError:
        conn.close()
        pause()
        return
    if idx < 1 or idx > len(studies):
        conn.close()
        pause()
        return
    study = studies[idx - 1]

    researchers = conn.execute("""
        SELECT u.user_id, u.full_name FROM study_researchers sr
        JOIN users u ON sr.user_id=u.user_id
        WHERE sr.study_id=?
    """, (study["study_id"],)).fetchall()

    if not researchers:
        conn.close()
        info("No researchers assigned to this study.")
        pause()
        return

    print_table(["#", "User ID", "Name"],
                [(i + 1, r["user_id"], r["full_name"]) for i, r in enumerate(researchers)])
    ridx = prompt("Select researcher # to remove")
    try:
        ridx = int(ridx)
    except ValueError:
        conn.close()
        pause()
        return
    if ridx < 1 or ridx > len(researchers):
        conn.close()
        pause()
        return
    researcher = researchers[ridx - 1]

    conn.execute("DELETE FROM study_researchers WHERE study_id=? AND user_id=?",
                 (study["study_id"], researcher["user_id"]))
    conn.commit()
    conn.close()

    write_audit_event(user["user_id"], "admin", "Remove Researcher from Study",
                      "RESEARCHER_REMOVED",
                      f"Researcher '{researcher['full_name']}' removed from study '{study['study_name']}'",
                      "study", study["study_id"])
    success(f"Researcher '{researcher['full_name']}' removed from study.")
    pause()

# ─── Account Lockout Management ────────────────────────────────────────────
 
def manage_user_lockouts(user: dict):
    """
    Display all user accounts that are currently locked or approaching the
    lockout threshold, and allow the admin to reset individual lockouts.
 
    SECURITY DESIGN:
      Account lockout (3 failed attempts within 5 minutes) is a brute-force
      defence. Admin unlock is the only recovery path — self-service unlock
      would defeat the control. JIT re-auth is required before any reset
      to ensure a compromised admin session cannot silently unlock accounts,
      which would let an attacker continue credential-stuffing.
 
    WHY show near-threshold accounts (not just locked):
      A user with 4 failed attempts is one guess away from lockout. Surfacing
      this lets the admin proactively contact the user before they are fully
      locked out, and flag possible credential-stuffing in progress.
 
    WHAT the reset does:
      Sets account_locked=0, failed_attempts=0, failed_attempt_window_start=NULL.
      This is a clean slate — the failure counter window restarts.
      It does NOT change the user's password; admin should advise the user to
      change their password if the lockout was caused by a suspected compromise
      rather than genuine forgotten-password.
    """
    if not require_jit_reauth(user, "Manage User Account Lockouts"):
        return
 
    print_header("MANAGE USER ACCOUNT LOCKOUTS")
 
    conn = get_conn()
    # Fetch all non-admin users with either a lockout or at least one failed attempt
    # so the admin has the full picture, not just fully locked accounts.
    all_users = conn.execute("""
        SELECT u.user_id, u.username, u.full_name, u.role,
               o.org_name,
               u.status,
               u.account_locked,
               u.failed_attempts,
               u.failed_attempt_window_start
        FROM users u
        LEFT JOIN organisations o ON u.org_id = o.org_id
        WHERE u.role != 'admin'
        ORDER BY u.account_locked DESC, u.failed_attempts DESC, u.full_name ASC
    """).fetchall()
    conn.close()
 
    if not all_users:
        info("No non-admin user accounts found in the system.")
        pause()
        return
 
    # Separate into locked, at-risk (>0 attempts, not locked), and clean
    locked     = [u for u in all_users if u["account_locked"]]
    at_risk    = [u for u in all_users if not u["account_locked"] and (u["failed_attempts"] or 0) > 0]
    clean      = [u for u in all_users if not u["account_locked"] and (u["failed_attempts"] or 0) == 0]
 
    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    if locked:
        warn(f"  {len(locked)} account(s) LOCKED — cannot log in until reset.")
    else:
        success("  No accounts are currently locked.")
 
    if at_risk:
        warn(f"  {len(at_risk)} account(s) have recorded failed attempts (not yet locked).")
 
    info(f"  {len(clean)} account(s) have no failed attempts.")
 
    # ── Locked accounts table ─────────────────────────────────────────────────
    if locked:
        print()
        print("  ── LOCKED ACCOUNTS ──────────────────────────────────────────────")
        print_table(
            ["#", "Username", "Full Name", "Role", "Organisation", "Attempts", "Window Start"],
            [(i + 1,
              u["username"],
              u["full_name"],
              u["role"],
              u["org_name"] or "—",
              u["failed_attempts"] or 0,
              (u["failed_attempt_window_start"] or "—")[:19])
             for i, u in enumerate(locked)]
        )
 
    # ── At-risk accounts table ────────────────────────────────────────────────
    if at_risk:
        print()
        print("  ── AT-RISK ACCOUNTS (failed attempts, not yet locked) ───────────")
        print_table(
            ["#", "Username", "Full Name", "Role", "Organisation", "Attempts", "Window Start"],
            [(len(locked) + i + 1,
              u["username"],
              u["full_name"],
              u["role"],
              u["org_name"] or "—",
              u["failed_attempts"] or 0,
              (u["failed_attempt_window_start"] or "—")[:19])
             for i, u in enumerate(at_risk)]
        )
 
    # ── Action menu ───────────────────────────────────────────────────────────
    actionable = locked + at_risk   # combined list, numbered from 1
 
    if not actionable:
        info("No accounts require attention. All users have clean login records.")
        write_audit_event(user["user_id"], "admin", "Manage User Account Lockouts",
                          "LOCKOUT_VIEW",
                          "Admin viewed lockout status — no locked or at-risk accounts")
        pause()
        return
 
    print()
    info("Enter the account # to unlock/reset it, or 0 to exit without changes.")
    raw = prompt("Account # to reset (or 0 to cancel)")
 
    try:
        idx = int(raw)
    except ValueError:
        pause()
        return
 
    if idx == 0:
        write_audit_event(user["user_id"], "admin", "Manage User Account Lockouts",
                          "LOCKOUT_VIEW",
                          f"Admin viewed lockout status — {len(locked)} locked, "
                          f"{len(at_risk)} at-risk. No changes made.")
        pause()
        return
 
    if idx < 1 or idx > len(actionable):
        error(f"Invalid selection. Enter a number between 1 and {len(actionable)}.")
        pause()
        return
 
    target = actionable[idx - 1]
    is_locked = bool(target["account_locked"])
 
    print()
    info(f"Account   : {target['full_name']} ({target['username']})")
    info(f"Role      : {target['role']}")
    info(f"Org       : {target['org_name'] or '—'}")
    attempts     = target["failed_attempts"] or 0
    status_label = "🔒 LOCKED" if is_locked else f"⚠ At-risk ({attempts} failed attempt(s))"
    info(f"Status    : {status_label}")
 
    action_label = "unlock and reset failed-attempt counter" if is_locked \
        else "reset failed-attempt counter (account not locked)"
 
    if not confirm_yn(f"Confirm: {action_label} for '{target['full_name']}'?"):
        info("Reset cancelled. No changes made.")
        write_audit_event(user["user_id"], "admin", "Manage User Account Lockouts",
                          "LOCKOUT_RESET_CANCELLED",
                          f"Admin cancelled lockout reset for user "
                          f"'{target['username']}' ({target['user_id']})",
                          "user", target["user_id"])
        pause()
        return
 
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    conn.execute("""
        UPDATE users
        SET account_locked              = 0,
            failed_attempts             = 0,
            failed_attempt_window_start = NULL,
            must_change_password        = 1,
            updated_at                  = ?
        WHERE user_id = ?
    """, (now, target["user_id"]))
    conn.commit()
    conn.close()
 
    event_type = "ACCOUNT_UNLOCKED" if is_locked else "FAILED_ATTEMPTS_RESET"
    description = (
        f"Admin {'unlocked' if is_locked else 'reset failed-attempt counter for'} "
        f"user '{target['full_name']}' ({target['username']}, role: {target['role']}). "
        f"Previous failed attempts: {target['failed_attempts'] or 0}."
    )
 
    write_audit_event(user["user_id"], "admin", "Manage User Account Lockouts",
                      event_type, description, "user", target["user_id"])
 
    if is_locked:
        success(f"Account '{target['username']}' has been unlocked.")
        info("The user will be required to change their password on next login.")
        info("Their existing TOTP device will be used to authenticate the reset.")
    else:
        success(f"Failed-attempt counter reset for '{target['username']}'.")
        info("The user's 10-minute lockout window has been cleared.")
 
    pause()

# ─── Crisis Management ─────────────────────────────────────────────────────

def crisis_rotate_master_key(user: dict):
    """
    Rotate the master key AND re-wrap all existing dataset DEKs.
    SAFE DESIGN: generates new keypair in memory, completes ALL re-wraps,
    then and only then writes that exact keypair to disk and retires the old one.
    If any re-wrap fails the entire operation is aborted — old key unchanged.
    """
    if not require_jit_reauth(user, "Crisis: Rotate Master Key"):
        return

    print_header("CRISIS — ROTATE MASTER KEY WITH DEK RE-WRAP")

    conn = get_conn()
    old_key = conn.execute(
        "SELECT key_id, key_name FROM system_keys "
        "WHERE key_type='MASTER_UNASSIGNED' AND status='active' "
        "ORDER BY created_at DESC LIMIT 1"
    ).fetchone()
    datasets = conn.execute(
        "SELECT dataset_id, dataset_name, wrapped_master_dek_path "
        "FROM datasets WHERE wrapped_master_dek_path IS NOT NULL"
    ).fetchall()
    conn.close()

    if not old_key:
        error("No active master key found. Generate one via Entity Management first.")
        pause()
        return

    info(f"Current master key : {old_key['key_name']}")
    info(f"Datasets to re-wrap: {len(datasets)}")
    warn("This will generate a new master key and re-wrap all dataset DEKs.")
    warn("The new key is only committed to disk if ALL re-wraps succeed.")
    warn("If any re-wrap fails the operation is aborted — old key remains active.")

    if not confirm_yn("Proceed with master key rotation?"):
        info("Rotation cancelled.")
        pause()
        return

    # Step 1: Load old private key into memory
    try:
        old_master_priv = load_system_key_private(
            "Collab-Hub-Master-Key-unassigned-datasets")
    except Exception as e:
        error(f"Cannot load current master private key: {e}")
        pause()
        return

    # Step 2: Generate new keypair IN MEMORY only — do not write to disk yet.
    # This exact keypair will be committed in Step 5 — we do NOT generate another
    # one later. Using the same keypair ensures DEKs wrapped here can be unwrapped
    # by the private key that ends up on disk.
    try:
        from crypto_utils import generate_rsa_keypair, serialize_public_key, serialize_private_key
        new_priv, new_pub_obj = generate_rsa_keypair()
        new_master_pub = new_pub_obj
        new_pub_pem = serialize_public_key(new_master_pub).decode()
        new_priv_pem = serialize_private_key(new_priv)
    except Exception as e:
        error(f"Failed to generate new keypair: {e}")
        pause()
        return

    # Step 3: Attempt all re-wraps using new public key (nothing written yet)
    rewrapped_results = []
    failed = 0

    for ds in datasets:
        try:
            old_wrapped = load_wrapped_dek(ds["wrapped_master_dek_path"])
            dek = rsa_unwrap_key(old_master_priv, old_wrapped)
            new_wrapped = rsa_wrap_key(new_master_pub, dek)
            fname = os.path.basename(ds["wrapped_master_dek_path"])
            rewrapped_results.append((ds["dataset_id"], fname, new_wrapped,
                                      ds["dataset_name"]))
        except Exception as e:
            warn(f"Cannot re-wrap DEK for '{ds['dataset_name']}': {e}")
            failed += 1

    if failed > 0:
        error(f"{failed} dataset(s) could not be re-wrapped. Operation ABORTED.")
        warn("Old master key is unchanged. No files have been modified.")
        warn("Investigate the failed datasets before retrying.")
        write_audit_event(user["user_id"], "admin", "Crisis Management",
                          "MASTER_KEY_ROTATION_ABORTED",
                          f"Master key rotation aborted — {failed} DEK re-wrap "
                          f"failure(s). Old key unchanged.",
                          "system_key", old_key["key_id"])
        pause()
        return

    # Step 4: All re-wraps succeeded — write DEK files to disk
    for dataset_id, fname, new_wrapped, ds_name in rewrapped_results:
        save_wrapped_dek(dataset_id, fname, new_wrapped)

    # Step 5: Write the SAME keypair from Step 2 to disk — not a new one.
    # Encrypt private key with KEK and save; update DB to retire old key.
    try:
        from system_startup import get_system_kek
        from crypto_utils import aes_encrypt
        key_dir = os.path.join(os.path.dirname(__file__), "keys", "system")
        safe_name = "Collab_Hub_Master_Key_unassigned_datasets"
        kek = get_system_kek()
        enc_priv = aes_encrypt(kek, new_priv_pem)
        priv_path = os.path.join(key_dir, f"{safe_name}_private_enc.bin")
        pub_path  = os.path.join(key_dir, f"{safe_name}_public.pem")
        with open(priv_path, "wb") as f:
            f.write(enc_priv)
        with open(pub_path, "wb") as f:
            f.write(new_pub_pem.encode())
    except Exception as e:
        error(f"Failed to write new key to disk: {e}")
        warn("DEK files have been updated but new key was not saved.")
        warn("System is in inconsistent state — contact administrator.")
        pause()
        return

    # Update DB: retire old key, insert new key record
    key_id = secure_random_id("SKEY-")
    now = datetime.now(timezone.utc).isoformat()
    key_name = "Collab-Hub-Master-Key-unassigned-datasets"
    conn = get_conn()
    conn.execute(
        "UPDATE system_keys SET status='retired', updated_at=? "
        "WHERE key_type='MASTER_UNASSIGNED' AND status='active'",
        (now,)
    )
    conn.execute("""
        INSERT OR REPLACE INTO system_keys
        (key_id, key_name, key_type, pub_pem, priv_enc, status,
         created_by, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?)
    """, (key_id, key_name, "MASTER_UNASSIGNED", new_pub_pem, priv_path,
          "active", user["user_id"], now, now))
    conn.commit()
    conn.close()

    write_audit_event(user["user_id"], "admin", "Crisis Management",
                      "MASTER_KEY_ROTATED",
                      f"Master key rotated successfully. "
                      f"{len(rewrapped_results)} DEKs re-wrapped. "
                      f"Same keypair used for wrapping and disk commit.",
                      "system_key", old_key["key_id"])

    success(f"Master key rotated. All {len(rewrapped_results)} dataset DEKs re-wrapped.")
    info("New master key is active. Old key retired.")
    pause()

def crisis_repair_master_dek_from_clinician(user: dict):
    """
    Recovery tool: rebuilds the master-key-wrapped DEK copy for datasets
    where the master fallback path is broken. Uses the clinician-wrapped
    copy as the source. Run after a failed/partial master key rotation.
    """
    if not require_jit_reauth(user, "Crisis: Repair Master DEK"):
        return

    print_header("CRISIS — REPAIR MASTER DEK FROM CLINICIAN KEY")
    warn("Use this after a failed master key rotation to restore the")
    warn("master key fallback path using the clinician-wrapped DEK copy.")

    conn = get_conn()
    datasets = conn.execute("""
        SELECT d.dataset_id, d.dataset_name,
               d.wrapped_research_dek_path,
               d.wrapped_master_dek_path,
               u.full_name as clinician_name,
               u.user_id as clinician_id
        FROM datasets d
        JOIN users u ON d.uploaded_by = u.user_id
        WHERE d.wrapped_research_dek_path IS NOT NULL
        AND d.wrapped_master_dek_path IS NOT NULL
        ORDER BY d.dataset_name
    """).fetchall()
    conn.close()

    if not datasets:
        info("No datasets found.")
        pause()
        return

    print_table(
        ["#", "Dataset", "Uploaded By"],
        [(i + 1, d["dataset_name"], d["clinician_name"])
         for i, d in enumerate(datasets)]
    )

    idx = prompt("Select dataset # to repair (or 0 to cancel)")
    try:
        idx = int(idx)
    except ValueError:
        pause()
        return
    if idx == 0 or idx > len(datasets):
        pause()
        return

    ds = datasets[idx - 1]
    info(f"Dataset  : {ds['dataset_name']}")
    info(f"Clinician: {ds['clinician_name']}")
    warn("The clinician's password is required to unwrap the DEK.")

    from ui_utils import prompt_password
    clin_password = prompt_password("Clinician's current password")

    try:
        clinician_priv = load_user_rsa_private(ds["clinician_id"], clin_password)
        clinician_wrapped = load_wrapped_dek(ds["wrapped_research_dek_path"])
        dek = rsa_unwrap_key(clinician_priv, clinician_wrapped)
    except Exception as e:
        error(f"Cannot recover DEK from clinician key: {e}")
        pause()
        return

    try:
        new_master_pub = load_system_key_public(
            "Collab-Hub-Master-Key-unassigned-datasets")
        new_master_wrapped = rsa_wrap_key(new_master_pub, dek)
        fname = os.path.basename(ds["wrapped_master_dek_path"])
        save_wrapped_dek(ds["dataset_id"], fname, new_master_wrapped)
    except Exception as e:
        error(f"Cannot re-wrap under new master key: {e}")
        pause()
        return

    write_audit_event(user["user_id"], "admin", "Crisis Management",
                      "MASTER_DEK_REPAIRED",
                      f"Master-key DEK copy rebuilt for '{ds['dataset_name']}' "
                      f"using clinician key. Master fallback path restored.",
                      "dataset", ds["dataset_id"])

    success(f"Master DEK copy repaired for '{ds['dataset_name']}'.")
    info("Master key fallback path is restored for this dataset.")
    pause()

def crisis_revoke_researcher_access(user: dict):
    """
    Cryptographically revoke a specific researcher's access to a dataset
    by deleting their wrapped DEK file and DB entry.
    App-layer status block alone leaves the DEK file on disk — this removes it.

    CLEANUP DESIGN:
      researcher_dataset_keys : deleted — cryptographic revocation + allows
                                clean re-grant via INSERT OR REPLACE later.
      DEK file on disk        : securely zeroed then deleted.
      datasets.status         : reset to 'verified' if this was the last
                                researcher — re-enables clinician assign flow
                                for fresh DEK issuance.
      study_researchers       : intentionally kept — researcher must remain
                                linked to study so re-assignment includes them
                                automatically without admin re-adding them.
      findings                : intentionally kept — signed cryptographic
                                evidence, treated as immutable like audit_log.
    """
    if not require_jit_reauth(user, "Crisis: Revoke Researcher Dataset Access"):
        return

    print_header("CRISIS — REVOKE RESEARCHER DATASET ACCESS")

    conn = get_conn()
    entries = conn.execute("""
        SELECT rdk.rdkey_id, rdk.wrapped_dek_path,
               u.full_name, u.user_id,
               d.dataset_name, d.dataset_id
        FROM researcher_dataset_keys rdk
        JOIN users u ON rdk.user_id = u.user_id
        JOIN datasets d ON rdk.dataset_id = d.dataset_id
        ORDER BY u.full_name, d.dataset_name
    """).fetchall()
    conn.close()

    if not entries:
        info("No researcher dataset keys found.")
        pause()
        return

    print_table(
        ["#", "Researcher", "Dataset", "DEK File Exists"],
        [(i + 1, e["full_name"], e["dataset_name"],
          "YES" if os.path.exists(e["wrapped_dek_path"]) else "ALREADY DELETED")
         for i, e in enumerate(entries)]
    )

    idx = prompt("Select # to revoke (cryptographically removes DEK file)")
    try:
        idx = int(idx)
    except ValueError:
        pause()
        return
    if idx < 1 or idx > len(entries):
        pause()
        return

    target = entries[idx - 1]

    warn(f"This will permanently delete the DEK file for '{target['full_name']}'")
    warn(f"on dataset '{target['dataset_name']}'. This cannot be undone.")
    if not confirm_yn("Confirm cryptographic revocation?"):
        info("Revocation cancelled.")
        pause()
        return

    # ── Securely delete the wrapped DEK file ─────────────────────────────
    if os.path.exists(target["wrapped_dek_path"]):
        fsize = os.path.getsize(target["wrapped_dek_path"])
        with open(target["wrapped_dek_path"], "r+b") as f:
            f.write(b'\x00' * fsize)
        os.remove(target["wrapped_dek_path"])
        file_status = "DEK file securely zeroed and deleted."
    else:
        file_status = "DEK file was already absent from disk."

    # ── Remove researcher_dataset_keys row ────────────────────────────────
    # Deleting this row also allows INSERT OR REPLACE to cleanly re-grant
    # access later without hitting the UNIQUE(dataset_id, user_id) constraint.
    conn = get_conn()
    conn.execute("DELETE FROM researcher_dataset_keys WHERE rdkey_id=?",
                 (target["rdkey_id"],))

    # ── Reset dataset status to allow re-assignment if needed ─────────────
    # Only reset if this was the LAST researcher key for this dataset.
    # If other researchers still have access, leave status as 'assigned'.
    remaining = conn.execute(
        "SELECT COUNT(*) as cnt FROM researcher_dataset_keys WHERE dataset_id=?",
        (target["dataset_id"],)
    ).fetchone()["cnt"]

    if remaining == 0:
        conn.execute(
            "UPDATE datasets SET status='verified', updated_at=? WHERE dataset_id=?",
            (datetime.now(timezone.utc).isoformat(), target["dataset_id"])
        )
        dataset_status_note = (
            "Dataset status reset to 'verified' (no remaining researcher access). "
            "Clinician can now re-assign to restore access."
        )
    else:
        dataset_status_note = (
            f"Dataset status unchanged — {remaining} other researcher(s) "
            f"still have access."
        )

    conn.commit()
    conn.close()

    write_audit_event(user["user_id"], "admin", "Crisis Management",
                      "RESEARCHER_ACCESS_CRYPTOGRAPHICALLY_REVOKED",
                      f"DEK revoked for '{target['full_name']}' on dataset "
                      f"'{target['dataset_name']}'. {file_status} "
                      f"{dataset_status_note}",
                      "dataset", target["dataset_id"])

    success("Cryptographic revocation complete.")
    info(f"DEK          : {file_status}")
    info(f"DB key entry : Removed from researcher_dataset_keys.")
    info(f"Dataset      : {dataset_status_note}")
    info("Study link   : Researcher remains in study_researchers — enables re-grant.")
    info("Findings     : Retained as signed evidence (treated as audit records).")
    pause()

def crisis_management_menu(user: dict):
    while True:
        print_header("CRISIS MANAGEMENT")
        warn("All actions in this menu are irreversible and fully audit-logged.")
        print()
        print("  Available crisis actions:")
        print()
        print("  1. Revoke All Datasets for a Study")
        print("     └─ Marks all datasets in a study as REVOKED. Blocks all researcher")
        print("        access immediately via application policy. Dataset files remain")
        print("        on disk for forensic recovery but are inaccessible to all users.")
        print()
        print("  2. Revoke Researcher Access to a Dataset (Cryptographic)")
        print("     └─ Deletes a specific researcher's wrapped DEK file from disk.")
        print("        Unlike a status block, this is cryptographically permanent —")
        print("        the researcher cannot decrypt that dataset even with their")
        print("        private key. Access can only be restored by re-running dataset")
        print("        assignment for that researcher.")
        print()
        print("  3. Rotate Master Key with Full DEK Re-wrap")
        print("     └─ Generates a new Master Key and re-wraps every existing dataset")
        print("        DEK under the new key before retiring the old one. Safe design:")
        print("        new key is only written to disk if ALL re-wraps succeed first.")
        print("        Aborts cleanly if any dataset cannot be re-wrapped.")
        print()
        print("  4. Repair Master DEK from Clinician Key")
        print("     └─ Recovery tool. Rebuilds the master-key-wrapped DEK copy for a")
        print("        specific dataset using the clinician-wrapped copy as source.")
        print("        Use this after a failed or partial master key rotation to restore")
        print("        the master key fallback path. Requires the clinician's password.")
        print()
        print("  5. Back")
        print()

        choice = prompt("Select action (1-5)")
        try:
            choice = int(choice)
        except ValueError:
            error("Please enter a number between 1 and 5.")
            pause()
            continue

        if choice == 1:
            # ── Revoke all datasets for a study ───────────────────────────
            print_header("CRISIS — REVOKE ALL DATASETS FOR A STUDY")
            warn("This blocks ALL researcher access to ALL datasets in the selected study.")
            warn("Dataset files remain on disk but status is set to REVOKED.")
            warn("This action is irreversible via this menu.")
            print()
            conn = get_conn()
            studies = conn.execute(
                "SELECT study_id, study_name FROM studies WHERE status='verified'"
            ).fetchall()
            conn.close()

            if not studies:
                info("No verified studies found.")
                pause()
                continue

            print_table(["#", "Study ID", "Name"],
                        [(i + 1, s["study_id"], s["study_name"])
                         for i, s in enumerate(studies)])

            idx = prompt("Select study # to revoke (or 0 to cancel)")
            try:
                idx = int(idx)
            except ValueError:
                pause()
                continue
            if idx == 0 or idx > len(studies):
                pause()
                continue

            study = studies[idx - 1]
            if not confirm_yn(
                f"CONFIRM: Revoke ALL datasets for study '{study['study_name']}'?"
            ):
                info("Revocation cancelled.")
                pause()
                continue

            conn = get_conn()
            conn.execute("""
                UPDATE datasets SET status='revoked', updated_at=?
                WHERE study_id=? AND status != 'revoked'
            """, (datetime.now(timezone.utc).isoformat(), study["study_id"]))
            conn.commit()
            conn.close()

            write_audit_event(user["user_id"], "admin",
                              "Crisis Management",
                              "STUDY_DATASETS_REVOKED",
                              f"All datasets for study '{study['study_name']}' "
                              f"revoked — application-layer access blocked.",
                              "study", study["study_id"])

            success(f"All datasets for study '{study['study_name']}' marked REVOKED.")
            warn("Researchers can no longer access these datasets via the application.")
            warn("DEK files remain on disk. Use option 2 for cryptographic revocation")
            warn("of individual researcher DEK files if also required.")
            pause()

        elif choice == 2:
            crisis_revoke_researcher_access(user)

        elif choice == 3:
            crisis_rotate_master_key(user)

        elif choice == 4:
            crisis_repair_master_dek_from_clinician(user)

        elif choice == 5:
            break

        else:
            error("Please enter a number between 1 and 5.")
            pause()