"""
main.py — CollabHub Entry Point, Startup Sequence, and Authentication
======================================================================
Orchestrates the full system lifecycle:

  FIRST-EVER STARTUP (no admin in DB):
    1. Bootstrap: creates admin with temp credentials (displayed on screen)
    2. Admin logs in with temp creds (no MFA — none configured yet)
    3. Force password change (must_change_password=1 flag)
    4. Force MFA enrollment: mobile number + TOTP setup + verification
    5. Force re-login with new password + TOTP
    6. Admin sets system KEK passphrase (encrypts system private keys)
    7. "System fully configured." — main menu available to all users

  SUBSEQUENT STARTUPS:
    1. Startup banner explains why admin must go first
    2. Admin logs in (password + TOTP)
    3. Admin enters KEK passphrase → system private keys decrypted into RAM
    4. "System unlocked." — main menu available to all users

  NORMAL OPERATION:
    - Main menu loops indefinitely until option 5 (Shutdown)
    - sys.exit(0) is ONLY called from this module, never from role modules
    - All errors/bad inputs loop back gracefully

   — JIT RE-AUTH:
    Sensitive admin actions (status changes, key revocation, lockout reset)
    call require_jit_reauth() which re-verifies admin password + TOTP before
    proceeding. Simulates Just-In-Time privilege escalation.

   — BOOTSTRAP ADMIN:
    First startup creates admin with no MFA. First login forces password
    change then MFA enrollment (mobile + TOTP) before the admin can proceed.
"""

import sys
import os
import hashlib
import secrets
import string
import json
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(__file__))

from database   import init_db, get_conn, write_audit_event, get_config, set_config
from ui_utils   import (print_banner, print_header, print_sep, info, success,
                        error, warn, prompt, prompt_password, pause, choose,
                        confirm_yn)
from crypto_utils  import verify_password, hash_password
from policy_engine import check_user_status
from mfa_utils     import verify_totp, display_and_prompt_totp, generate_totp_secret
from system_startup import (is_system_unlocked, set_system_kek, derive_kek,
                             generate_kek_salt, clear_system_kek)

# ── Constants ────────────────────────────────────────────────────────────────
_ADMIN_UNLOCK_HASH    = "$argon2id$v=19$m=65536,t=3,p=2$Fbefd+C6co1181CMv7FA1g$KbF038/g9pJBefVbgSz4l/V/TzeMnnSXwsvZZm71WBk"
_MAX_FAILED_ATTEMPTS  = 3
_FAILURE_WINDOW_MINS  = 5


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _is_within_window(ts):
    if not ts:
        return False
    try:
        t = datetime.fromisoformat(ts)
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - t) < timedelta(minutes=_FAILURE_WINDOW_MINS)
    except Exception:
        return False


# ── Failure tracking ─────────────────────────────────────────────────────────

def _record_failed_attempt(user_id, role, menu_item, reason):
    conn = get_conn()
    row  = conn.execute(
        "SELECT failed_attempts, failed_attempt_window_start FROM users WHERE user_id=?",
        (user_id,)
    ).fetchone()
    if not row:
        conn.close()
        return
    now   = _now_iso()
    count = row["failed_attempts"] or 0
    win   = row["failed_attempt_window_start"]
    if not _is_within_window(win):
        count = 0
        win   = now
    new_count = count + 1
    conn.execute("""
        UPDATE users SET failed_attempts=?, failed_attempt_window_start=?,
        account_locked = CASE WHEN ? >= ? THEN 1 ELSE account_locked END,
        updated_at=? WHERE user_id=?
    """, (new_count, win, new_count, _MAX_FAILED_ATTEMPTS, now, user_id))
    conn.commit()
    conn.close()
    desc = f"Failed login ({new_count}/{_MAX_FAILED_ATTEMPTS}): {reason}"
    if new_count >= _MAX_FAILED_ATTEMPTS:
        desc += " — ACCOUNT LOCKED"
    write_audit_event(user_id, role, menu_item, "LOGIN_FAILED", desc, "user", user_id)
    if new_count >= _MAX_FAILED_ATTEMPTS:
        error("Account locked — too many failed attempts. Contact administrator.")


def _reset_failed_attempts(user_id):
    conn = get_conn()
    conn.execute("""
        UPDATE users SET failed_attempts=0, failed_attempt_window_start=NULL, updated_at=?
        WHERE user_id=?
    """, (_now_iso(), user_id))
    conn.commit()
    conn.close()


# ── Admin self-unlock passphrase ─────────────────────────────────────────────

def _admin_self_unlock(username):
    print_header("ADMIN ACCOUNT SELF-UNLOCK")
    warn("Enter the system unlock passphrase to reset your admin lockout.")
    pp = prompt_password("System unlock passphrase")
    if not verify_password(_ADMIN_UNLOCK_HASH, pp):
        error("Incorrect passphrase.")
        write_audit_event(None, "admin", "Admin Self-Unlock",
                          "ADMIN_UNLOCK_FAILED",
                          f"Wrong passphrase for admin self-unlock (user: {username})")
        pause()
        return False
    conn = get_conn()
    u = conn.execute("SELECT user_id FROM users WHERE username=? AND role='admin'",
                     (username,)).fetchone()
    if not u:
        conn.close(); error("Admin not found."); pause(); return False
    conn.execute("""
        UPDATE users SET account_locked=0, failed_attempts=0, must_change_password=1,
        failed_attempt_window_start=NULL, updated_at=? WHERE user_id=?
    """, (_now_iso(), u["user_id"]))
    conn.commit()
    conn.close()
    write_audit_event(u["user_id"], "admin", "Admin Self-Unlock",
                      "ADMIN_UNLOCKED", "Admin lockout reset via system passphrase")
    success("Lockout reset. Log in and change your password.")
    pause()
    return True


# ── Password + MFA re-auth gate (JIT) ───────────────────────────

def require_jit_reauth(admin_user: dict, action_label: str) -> bool:
    """
    Re-verify admin identity before a sensitive action (JIT escalation).
    Re-checks password + TOTP — a stolen session token alone is insufficient.
    All outcomes written to audit trail.

    WHY re-auth for status changes: Account and organisation status changes
    are high-impact, irreversible actions. A compromised admin session (e.g.,
    admin walks away from unlocked terminal) should not allow silent escalation.
    This simulates JIT (Just-In-Time) privilege models used in PAM/CyberArk.
    WHY both password AND TOTP: Re-entering password alone could be defeated
    by shoulder-surfing the original login. Both factors together confirm the
    admin's physical presence and possession of their MFA device.
    """
    print_sep()
    print(f"  🔐  JIT RE-AUTHORISATION — {action_label.upper()}")
    print_sep()
    warn("Sensitive action. Re-enter your credentials to confirm your identity.")

    # Re-fetch latest password hash from DB (may have changed since login)
    conn = get_conn()
    fresh = conn.execute(
        "SELECT password_hash, totp_secret, mobile_number FROM users WHERE user_id=?",
        (admin_user["user_id"],)
    ).fetchone()
    conn.close()
    if not fresh:
        error("Could not re-load admin credentials.")
        return False

    pw = prompt_password("Admin password")
    if not verify_password(fresh["password_hash"], pw):
        error("Incorrect password. Action denied.")
        write_audit_event(admin_user["user_id"], "admin",
                          f"JIT Re-auth ({action_label})",
                          "JIT_REAUTH_FAILED",
                          f"JIT re-auth failed (wrong password) for: {action_label}",
                          "user", admin_user["user_id"])
        pause()
        return False

    if fresh["totp_secret"]:
        entered = display_and_prompt_totp(fresh["totp_secret"], fresh["mobile_number"])
        if not verify_totp(fresh["totp_secret"], entered):
            error("Incorrect MFA code. Action denied.")
            write_audit_event(admin_user["user_id"], "admin",
                              f"JIT Re-auth ({action_label})",
                              "JIT_REAUTH_FAILED",
                              f"JIT re-auth failed (wrong TOTP) for: {action_label}",
                              "user", admin_user["user_id"])
            pause()
            return False

    write_audit_event(admin_user["user_id"], "admin",
                      f"JIT Re-auth ({action_label})",
                      "JIT_REAUTH_GRANTED",
                      f"Admin JIT re-auth granted for sensitive action: {action_label}",
                      "user", admin_user["user_id"])
    success("Identity confirmed.")
    return True


# ── First-login flows ─────────────────────────────────────────────────────────

def _force_password_change(user: dict, old_password: str) -> bool:
    """
    Force user to set a new password on first login. Re-encrypts private keys.
    Returns True (caller should log out and loop back to main menu).
    """
    print_header("MANDATORY PASSWORD CHANGE")
    warn("You are using a temporary password. Set a new password to continue.")
    info("Requirements: ≥12 chars, uppercase, lowercase, digit, special character.")

    while True:
        new_pw = prompt_password("New password")
        if len(new_pw) < 12:
            error("Minimum 12 characters required."); continue
        if not any(c.isupper() for c in new_pw):
            error("Must contain an uppercase letter."); continue
        if not any(c.islower() for c in new_pw):
            error("Must contain a lowercase letter."); continue
        if not any(c.isdigit() for c in new_pw):
            error("Must contain a digit."); continue
        if not any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in new_pw):
            error("Must contain a special character."); continue
        if prompt_password("Confirm new password") != new_pw:
            error("Passwords do not match."); continue
        break

    conn = get_conn()
    conn.execute(
        "UPDATE users SET password_hash=?, must_change_password=0, updated_at=? WHERE user_id=?",
        (hash_password(new_pw), _now_iso(), user["user_id"])
    )
    conn.commit()
    conn.close()

    # Re-encrypt private keys with new password
    if user["role"] != "admin":
        try:
            from key_manager import _user_key_dir, _derive_key_from_password, load_user_rsa_private
            from crypto_utils import aes_encrypt, serialize_private_key
            rsa_priv = load_user_rsa_private(user["user_id"], old_password)
            new_k    = _derive_key_from_password(new_pw, user["user_id"] + "_rsa")
            key_dir  = _user_key_dir(user["user_id"])
            with open(os.path.join(key_dir, "rsa_private_enc.bin"), "wb") as f:
                f.write(aes_encrypt(new_k, serialize_private_key(rsa_priv)))
            if user["role"] == "researcher":
                from key_manager import load_user_ed_private
                from crypto_utils import serialize_ed25519_private
                ed_priv = load_user_ed_private(user["user_id"], old_password)
                new_ek  = _derive_key_from_password(new_pw, user["user_id"] + "_ed")
                with open(os.path.join(key_dir, "ed_private_enc.bin"), "wb") as f:
                    f.write(aes_encrypt(new_ek, serialize_ed25519_private(ed_priv)))
            info("Private keys re-protected with new password.")
        except Exception as e:
            warn(f"Key re-encryption issue: {e}. Contact admin if login problems occur.")

    write_audit_event(user["user_id"], user["role"], "Mandatory Password Change",
                      "PASSWORD_CHANGED",
                      "Temporary password changed on first login", "user", user["user_id"])
    success("Password updated successfully.")
    return True


def _force_mfa_setup(user: dict) -> bool:
    """
    Force MFA enrollment in SIMULATION MODE — code shown on screen at every attempt.

    PROTOTYPE / SIMULATION BEHAVIOUR (Feedback-1):
      The system is in prototype mode. No authenticator app is required.
      The current TOTP code is displayed on screen before each attempt so
      the user can simply read and enter it. This is consistent with how
      all other MFA prompts in the system work (display_and_prompt_totp).

      In production: remove the on-screen code display and instead send an
      SMS to mobile_number. The verification logic is identical in both modes.

    FAILURE BEHAVIOUR (Feedback-2):
      After 3 failed code entries the function returns False WITHOUT saving
      the TOTP secret. The caller is responsible for cleaning up any
      credentials created during this session and restarting the appropriate
      journey (re-bootstrap for admin, re-login for other users).

    WHY code refreshed each attempt:
      TOTP codes are valid for 30 seconds. Displaying a single code at the
      start and then asking for it several minutes later (after user reads
      instructions) would cause valid codes to expire mid-attempt. Refreshing
      the displayed code inside the loop prevents this.
    """
    from mfa_utils import get_current_code

    print_header("MFA ENROLLMENT — REQUIRED")
    warn("Your account does not have MFA configured. Enrollment is mandatory.")
    print()
    info("[SIMULATION MODE] Your verification code will be displayed on screen.")
    info("In production this code would be sent to your registered mobile number.")
    print()

    mobile = prompt("Mobile number (for production SMS, e.g. +44 7700 900000,"
                    " or press Enter to skip in simulation)")
    mobile = mobile.strip() or None
    if not mobile:
        info("No mobile number recorded — codes displayed on screen (simulation only).")

    # Generate TOTP secret — NOT saved to DB yet (saved only on successful verification)
    totp_secret = generate_totp_secret()

    # Show the secret so the user may optionally add it to an authenticator app
    print(f"\n  TOTP secret (optional — add to authenticator app for production use):")
    print(f"  {totp_secret}\n")

    _MAX_MFA_ATTEMPTS = 3
    for attempt in range(1, _MAX_MFA_ATTEMPTS + 1):

        # Refresh code display inside the loop — code valid for current 30-second window
        current_code = get_current_code(totp_secret)
        print(f"  ┌──────────────────────────────────────────────────────────────┐")
        print(f"  │  [SIMULATION MODE]  Current verification code: {current_code}        │")
        print(f"  │  Enter the code shown above. (Attempt {attempt}/{_MAX_MFA_ATTEMPTS})              │")
        print(f"  │  In production this code is sent to your mobile — not shown. │")
        print(f"  └──────────────────────────────────────────────────────────────┘")

        entered = prompt("Enter the 6-digit code").strip()

        if verify_totp(totp_secret, entered):
            # ── Success: save TOTP secret and mobile ─────────────────────
            conn = get_conn()
            conn.execute("""
                UPDATE users SET totp_secret=?, mobile_number=?, updated_at=?
                WHERE user_id=?
            """, (totp_secret, mobile, _now_iso(), user["user_id"]))
            conn.commit()
            conn.close()

            write_audit_event(user["user_id"], user["role"], "MFA Enrollment",
                              "MFA_ENROLLED",
                              f"TOTP MFA enrolled for {user['full_name']} "
                              f"(mobile: {mobile or 'not set — simulation mode'})",
                              "user", user["user_id"])
            success("MFA enrollment complete!")
            info("From now on, every login will require a 6-digit verification code.")
            return True

        remaining = _MAX_MFA_ATTEMPTS - attempt
        if remaining > 0:
            error(f"Incorrect code. {remaining} attempt(s) remaining.")
        else:
            # ── Failure: log and return False — do NOT save the secret ───
            error("MFA enrollment failed after maximum attempts.")
            error("For security, credentials created during this session will be cleared.")
            error("The system will restart the appropriate setup process.")
            write_audit_event(user["user_id"], user["role"], "MFA Enrollment",
                              "MFA_ENROLLMENT_FAILED",
                              f"MFA enrollment failed after {_MAX_MFA_ATTEMPTS} attempts "
                              f"for user '{user['full_name']}' — credentials will be cleared",
                              "user", user["user_id"])
            pause()
            return False

    return False  # unreachable but satisfies type checker


# ── Core authentication ───────────────────────────────────────────────────────

def authenticate(role_label: str, db_role: str) -> tuple:
    """
    Three-layer authentication: username+password → account checks → TOTP MFA.
    All failures written to audit log before returning (None, None).
    """
    print_header(f"LOGIN — {role_label.upper()}")
    username = prompt("Username")
    password = prompt_password("Password")

    if not username or not password:
        error("Username and password are required.")
        write_audit_event(None, db_role, f"Login ({role_label})",
                          "LOGIN_FAILED", "Login attempt with empty credentials")
        return None, None

    conn = get_conn()
    user = conn.execute("""
        SELECT u.*, o.org_name, o.org_type, o.status as org_status
        FROM users u
        LEFT JOIN organisations o ON u.org_id = o.org_id
        WHERE u.username = ? AND u.role = ?
    """, (username, db_role)).fetchone()
    conn.close()

    if not user:
        error("Invalid username or password.")
        write_audit_event(None, db_role, f"Login ({role_label})",
                          "LOGIN_FAILED",
                          f"Unknown username '{username}' for role '{db_role}'")
        return None, None

    user = dict(user)

    # Lockout check
    if user.get("account_locked"):
        if db_role == "admin":
            warn("Admin account is locked.")
            if confirm_yn("Attempt admin self-unlock with system passphrase?"):
                _admin_self_unlock(username)
        else:
            error("Account locked. Contact system administrator.")
            write_audit_event(user["user_id"], db_role, f"Login ({role_label})",
                              "LOGIN_FAILED_LOCKED",
                              f"Login attempt on locked account '{username}'")
        return None, None

    # Password verification
    if not verify_password(user["password_hash"], password):
        error("Invalid username or password.")
        _record_failed_attempt(user["user_id"], db_role,
                               f"Login ({role_label})", "Wrong password")
        return None, None

    # Account/org status
    ok, reason = check_user_status(user)
    if not ok:
        error(reason)
        write_audit_event(user["user_id"], db_role, f"Login ({role_label})",
                          "LOGIN_FAILED", f"Status: {reason}", "user", user["user_id"])
        return None, None

    if db_role != "admin" and user.get("org_status") and user["org_status"] != "verified":
        msg = f"Organisation not verified (status: {user['org_status']}). Contact admin."
        error(msg)
        write_audit_event(user["user_id"], db_role, f"Login ({role_label})",
                          "LOGIN_FAILED", msg, "user", user["user_id"])
        return None, None

    # TOTP MFA (skipped if no secret configured — handled separately in startup)
    if user.get("totp_secret"):
        entered = display_and_prompt_totp(user["totp_secret"], user.get("mobile_number"))
        if not verify_totp(user["totp_secret"], entered):
            error("Invalid verification code.")
            _record_failed_attempt(user["user_id"], db_role,
                                   f"Login ({role_label})", "Wrong TOTP code")
            return None, None
    else:
        write_audit_event(user["user_id"], db_role, f"Login ({role_label})",
                          "LOGIN_NO_MFA",
                          f"Login without MFA (no TOTP secret for '{username}')")

    _reset_failed_attempts(user["user_id"])
    success(f"Welcome, {user['full_name']}!")
    write_audit_event(user["user_id"], db_role, f"Login ({role_label})",
                      "LOGIN_SUCCESS", f"{role_label} authenticated successfully",
                      "user", user["user_id"])
    return user, password


# ── System startup sequence ───────────────────────────────────────────────────

def _admin_exists() -> bool:
    conn = get_conn()
    row  = conn.execute("SELECT 1 FROM users WHERE role='admin' LIMIT 1").fetchone()
    conn.close()
    return row is not None


def _bootstrap_admin():
    """
    Create the first admin on a fresh system (no DB users).
    Generates a temp password, creates admin account with must_change_password=1
    and NO TOTP secret (MFA is enrolled at first login, not bootstrap time).

    WHY no MFA at bootstrap: The system has no phone/authenticator configured
    yet. Bootstrap is a physical/console operation; MFA enrollment follows
    immediately at first login, before any cryptographic keys are accessible.
    WHY temp password + force change: Bootstrap is a low-security moment
    (credentials displayed on screen). Forcing change at first login ensures
    only the admin who types the new password knows the final credentials.
    """
    _chars = string.ascii_letters + string.digits + "!@#$%"
    while True:
        temp_pw = "".join(secrets.choice(_chars) for _ in range(14))
        if (any(c.isupper() for c in temp_pw) and
                any(c.islower() for c in temp_pw) and
                any(c.isdigit() for c in temp_pw) and
                any(c in "!@#$%" for c in temp_pw)):
            break

    now     = _now_iso()
    user_id = "USR-ADMIN-001"
    conn    = get_conn()
    conn.execute("""
        INSERT OR IGNORE INTO users
        (user_id, username, password_hash, role, full_name, email,
         status, must_change_password, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (user_id, "admin", hash_password(temp_pw), "admin",
          "System Administrator", "admin@collabhub.int",
          "verified", 1, now, now))
    conn.commit()
    conn.close()

    write_audit_event(user_id, "admin", "System Bootstrap",
                      "ADMIN_BOOTSTRAPPED",
                      "First-startup admin account created via bootstrap procedure")

    print(f"\n  ┌──────────────────────────────────────────────────────────────┐")
    print(f"  │   ⚠  FIRST-TIME SYSTEM BOOTSTRAP — ADMIN ACCOUNT CREATED    │")
    print(f"  │                                                               │")
    print(f"  │   Username         : admin                                   │")
    print(f"  │   Temporary password: {temp_pw:<39}│")
    print(f"  │                                                               │")
    print(f"  │   You MUST change this password on first login.              │")
    print(f"  │   You MUST enrol MFA before system services are unlocked.    │")
    print(f"  │   These credentials are shown ONCE. Store them securely.     │")
    print(f"  └──────────────────────────────────────────────────────────────┘")
    pause("Press [Enter] when you have recorded the credentials...")


def _setup_system_kek_first_time(admin_user: dict):
    """
    First-time KEK setup: admin chooses a passphrase, system keys are
    generated and encrypted with the derived KEK.

    WHY passphrase chosen by admin (not pre-set):
      The admin who runs the system owns the KEK. Pre-setting a passphrase
      (e.g., in a config file) would mean the developer knows the KEK — a
      fundamental violation of separation of duties. The admin must choose
      a passphrase only they know.
    """
    print_header("SYSTEM KEY ENCRYPTION KEY (KEK) — FIRST-TIME SETUP")
    info("System private keys will be encrypted with a passphrase you choose.")
    info("This passphrase is required at every system restart to unlock")
    info("cryptographic services. Choose something long and memorable.")
    info("Store it securely — loss of this passphrase means the system")
    info("private keys cannot be recovered without re-keying all datasets.")
    warn("⚠  This passphrase is separate from your login password.")
    print()

    while True:
        pp  = prompt_password("System KEK passphrase (min 16 chars)")
        if len(pp) < 16:
            error("KEK passphrase must be at least 16 characters."); continue
        pp2 = prompt_password("Confirm KEK passphrase")
        if pp != pp2:
            error("Passphrases do not match."); continue
        break

    # Generate salt, derive KEK, store verification hash
    from argon2 import PasswordHasher
    salt_hex = generate_kek_salt()
    kek      = derive_kek(pp, salt_hex)
    ph       = PasswordHasher()
    kek_hash = ph.hash(pp)

    set_config("kek_salt",    salt_hex)
    set_config("kek_hash",    kek_hash)
    set_config("system_initialized", "1")

    # Generate and encrypt system keypairs
    from key_manager import (generate_rsa_keypair, serialize_public_key,
                              save_system_key_encrypted)
    from key_manager import _system_key_dir
    import os as _os

    key_dir = _system_key_dir()
    _os.makedirs(key_dir, exist_ok=True)

    info("Generating and encrypting system key pairs...")
    # key_type must match what role_admin.py and hospital_stub.py query by.
    # manage_master_key()         → WHERE key_type='MASTER_UNASSIGNED'
    # manage_incoming_data_key()  → WHERE key_type='INCOMING_DATA'
    # hospital_stub.py            → WHERE key_type='INCOMING_DATA'
    key_configs = [
        ("Collab-Hub-Master-Key-unassigned-datasets", "MASTER_UNASSIGNED"),
        ("Collab-Hub-Incoming-Data-key-pair",         "INCOMING_DATA"),
    ]
    for key_name, key_type in key_configs:
        priv, pub = generate_rsa_keypair(4096)
        enc_path = save_system_key_encrypted(key_name, priv, kek)
        pub_path = _os.path.join(key_dir, f"{key_name}_public.pem")
        with open(pub_path, "wb") as f:
            f.write(serialize_public_key(pub))
        conn = get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO system_keys
            (key_id, key_name, key_type, pub_pem, priv_enc, status, created_by, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (secrets.token_hex(8), key_name, key_type,
              serialize_public_key(pub).decode(), enc_path,
              "active", admin_user["user_id"], _now_iso(), _now_iso()))
        conn.commit()
        conn.close()
        info(f"  ✔ {key_name} (type: {key_type})")

    set_system_kek(kek)

    write_audit_event(admin_user["user_id"], "admin", "System KEK Setup",
                      "KEK_CONFIGURED",
                      "System KEK passphrase set; system private keys encrypted at rest")

    success("System keys generated and encrypted. KEK loaded into memory.")
    info("The system is now fully operational.")
    pause()


def _unlock_system_at_startup(admin_user: dict):
    """
    Subsequent startups: verify KEK passphrase and load system keys into RAM.
    Called after admin successfully authenticates at startup.
    """
    print_header("SYSTEM KEY UNLOCK — KEK PASSPHRASE REQUIRED")
    info("Enter the system KEK passphrase to decrypt system private keys.")
    info("This passphrase is required at every system restart.")

    kek_hash_stored = get_config("kek_hash")
    salt_hex        = get_config("kek_salt")

    if not kek_hash_stored or not salt_hex:
        error("KEK configuration not found. System may not be fully initialised.")
        return False

    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    ph = PasswordHasher()

    for attempt in range(3):
        pp = prompt_password("System KEK passphrase")
        try:
            ph.verify(kek_hash_stored, pp)
            break
        except VerifyMismatchError:
            error(f"Incorrect passphrase. {2 - attempt} attempt(s) remaining.")
            if attempt == 2:
                write_audit_event(admin_user["user_id"], "admin",
                                  "System Unlock", "KEK_UNLOCK_FAILED",
                                  "KEK passphrase failed 3 times at startup — system locked")
                error("System startup aborted — KEK passphrase incorrect.")
                return False

    kek = derive_kek(pp, salt_hex)
    set_system_kek(kek)

    write_audit_event(admin_user["user_id"], "admin", "System Unlock",
                      "SYSTEM_UNLOCKED",
                      "System KEK passphrase verified; system private keys decrypted into RAM")
    success("System keys unlocked. Cryptographic services are now available.")
    info("All users may now log in.")
    pause()
    return True


def _print_startup_banner():
    """
    Display the startup banner explaining why admin login is required.
    Shown before the admin authentication prompt on every startup.
    """
    print("\n")
    print("  ╔════════════════════════════════════════════════════════════════════╗")
    print("  ║        CollabHub — Secure Clinical Research Platform              ║")
    print("  ║        GDPR-Compliant Cross-Border Data Collaboration             ║")
    print("  ╠════════════════════════════════════════════════════════════════════╣")
    print("  ║  ⚠  SYSTEM STARTUP — ADMINISTRATOR AUTHENTICATION REQUIRED        ║")
    print("  ║                                                                    ║")
    print("  ║  System private keys are protected by a Key Encryption Key (KEK)  ║")
    print("  ║  held ONLY in RAM — never stored as plaintext on disk.            ║")
    print("  ║  An administrator must log in to supply the KEK passphrase and    ║")
    print("  ║  decrypt system services before any other users can proceed.      ║")
    print("  ║                                                                    ║")
    print("  ║  ► This prompt appears only after a server restart.               ║")
    print("  ║    In production, servers run continuously for months.            ║")
    print("  ║    Non-cloud / bare-metal hospital environments may involve        ║")
    print("  ║    a physical key ceremony for the KEK passphrase on first        ║")
    print("  ║    startup or hardware replacement — consistent with GDPR Art.32  ║")
    print("  ║    and ISO 27001 Annex A.10 key management requirements.         ║")
    print("  ╚════════════════════════════════════════════════════════════════════╝")
    print()


def startup_sequence():
    """
    Orchestrate the full startup sequence. Returns only when system is unlocked.

    FIRST STARTUP:
      bootstrap → admin login (no MFA) → force pw change → force MFA setup
      → force re-login (with MFA) → KEK setup → system open

    SUBSEQUENT STARTUPS:
      admin login (with MFA) → KEK passphrase → system open
    """
    init_db()
    _print_startup_banner()

    # ── First ever startup: bootstrap admin ───────────────────────────────
    if not _admin_exists():
        info("No administrator account found. Initiating first-startup bootstrap...")
        _bootstrap_admin()

    system_init = get_config("system_initialized")

    # ── Admin must authenticate to proceed ────────────────────────────────
    info("Administrator login required to unlock system services.")
    print()

    while True:
        print_header("ADMINISTRATOR LOGIN — SYSTEM STARTUP")
        username = prompt("Admin username")
        password = prompt_password("Admin password")

        conn = get_conn()
        user = conn.execute("""
            SELECT * FROM users WHERE username=? AND role='admin'
        """, (username,)).fetchone()
        conn.close()

        if not user:
            error("Invalid credentials.")
            pause()
            continue

        user = dict(user)

        if user.get("account_locked"):
            warn("Admin account is locked.")
            if confirm_yn("Attempt self-unlock with system passphrase?"):
                _admin_self_unlock(username)
            pause()
            continue

        if not verify_password(user["password_hash"], password):
            error("Invalid credentials.")
            _record_failed_attempt(user["user_id"], "admin",
                                   "System Startup Login", "Wrong password")
            pause()
            continue

        # First login: force password change + MFA enrollment
        if user.get("must_change_password"):
            # Tailor the message to what will actually happen:
            # MFA enrollment only triggers if totp_secret is not yet set.
            # After a lockout reset the admin already has TOTP configured,
            # so saying "MFA enrollment required" would be misleading.
            if user.get("totp_secret"):
                info("Password change required. Please set a new password to continue.")
            else:
                info("Mandatory password change and MFA enrollment required.")
            pause()
            _force_password_change(user, password)

            # Reload user after password change
            conn = get_conn()
            user = dict(conn.execute("SELECT * FROM users WHERE user_id=?",
                                     (user["user_id"],)).fetchone())
            conn.close()

            # Force MFA enrollment (Feedback-13)
            if not user.get("totp_secret"):
                if not _force_mfa_setup(user):
                    # FB-2: MFA enrollment failed during bootstrap.
                    # Delete the admin account so the outer loop detects
                    # _admin_exists()==False and calls _bootstrap_admin()
                    # again with fresh credentials. No partial state remains.
                    warn("Deleting admin account. System will re-bootstrap with new credentials.")
                    try:
                        import shutil as _sh
                        _kd = os.path.join(os.path.dirname(__file__),
                                           "keys", "users", user["user_id"])
                        if os.path.exists(_kd):
                            _sh.rmtree(_kd)
                    except Exception:
                        pass  # best-effort key cleanup
                    conn2 = get_conn()
                    conn2.execute("DELETE FROM users WHERE user_id=?", (user["user_id"],))
                    conn2.commit()
                    conn2.close()
                    write_audit_event(
                        None, "system", "System Bootstrap",
                        "BOOTSTRAP_RESTART",
                        f"Admin account deleted after MFA enrollment failure. "
                        f"Bootstrap will restart with new credentials."
                    )
                    info("A new administrator account will now be created.")
                    info("Please record the new credentials carefully.")
                    pause()
                    continue  # outer while: _admin_exists()==False -> _bootstrap_admin()

            write_audit_event(user["user_id"], "admin", "System Startup",
                              "ADMIN_FIRST_LOGIN_COMPLETE",
                              "Admin completed first-login: password changed + MFA enrolled. "
                              "Must re-login.")
            info("Account fully configured. Please log in again with your new credentials + MFA.")
            pause()
            continue   # loop back to login prompt

        # TOTP MFA for normal subsequent logins
        if user.get("totp_secret"):
            entered = display_and_prompt_totp(user["totp_secret"], user.get("mobile_number"))
            if not verify_totp(user["totp_secret"], entered):
                error("Invalid verification code.")
                _record_failed_attempt(user["user_id"], "admin",
                                       "System Startup Login", "Wrong TOTP")
                pause()
                continue
        else:
            # No TOTP configured (edge case: non-first-login without MFA)
            warn("No MFA configured for admin. Proceeding without MFA (not recommended).")

        _reset_failed_attempts(user["user_id"])
        success(f"Welcome, {user['full_name']}!")
        write_audit_event(user["user_id"], "admin", "System Startup",
                          "STARTUP_ADMIN_AUTH",
                          "Administrator authenticated at system startup")

        # ── KEK setup or unlock ───────────────────────────────────────────
        if not system_init:
            # First time: set up KEK passphrase and generate system keys
            _setup_system_kek_first_time(user)
        else:
            # Subsequent start: unlock with existing passphrase
            if not _unlock_system_at_startup(user):
                error("System startup aborted. Restart the application.")
                sys.exit(1)

        return user   # system is now unlocked; return admin user for main loop


# ── Main application loop ─────────────────────────────────────────────────────

def main():
    # Run startup sequence (blocks until system is unlocked)
    startup_admin = startup_sequence()

    # Welcome the unlocked system
    print_sep()
    success("System is UNLOCKED and operational.")
    info("Cryptographic services available. All users may now log in.")
    print_sep()
    pause()

    while True:
        print_banner()
        choice = choose([
            "Administrator Login",
            "Clinician Login",
            "Researcher Login",
            "Auditor Login",
            "Shutdown"
        ], "Select role to login or shutdown")

        if choice < 0:
            pause("Invalid selection. Press [Enter] to try again...")
            continue

        if choice == 5:
            print_sep()
            info("CollabHub shutting down. Sessions terminated. Audit trail preserved.")
            clear_system_kek()
            info("System KEK cleared from memory.")
            print_sep()
            sys.exit(0)

        user, password = None, None

        if choice == 1:
            user, password = authenticate("Administrator", "admin")
            if user:
                if user.get("must_change_password"):
                    _force_password_change(user, password)
                    continue
                if not user.get("totp_secret"):
                    warn("Admin has no MFA configured. Enrolling now...")
                    if not _force_mfa_setup(user):
                        # FB-2: MFA enrollment failed for established admin account.
                        # Reset TOTP secret and force re-enrollment on next login.
                        # The admin account is NOT deleted (it was pre-existing),
                        # but it is reset to an unresolvable state without MFA.
                        conn_r = get_conn()
                        conn_r.execute("""
                            UPDATE users SET totp_secret=NULL, must_change_password=0,
                            updated_at=? WHERE user_id=?
                        """, (_now_iso(), user["user_id"]))
                        conn_r.commit()
                        conn_r.close()
                        error("MFA enrollment failed. Account reset.")
                        error("You must complete MFA enrollment to access the system.")
                        error("Log in again to restart the enrollment process.")
                    continue
                from role_admin import admin_menu
                admin_menu(user)

        elif choice == 2:
            user, password = authenticate("Clinician", "clinician")
            if user:
                if user.get("must_change_password"):
                    _force_password_change(user, password); continue
                from role_clinician import clinician_menu
                clinician_menu(user, password)

        elif choice == 3:
            user, password = authenticate("Researcher", "researcher")
            if user:
                if user.get("must_change_password"):
                    _force_password_change(user, password); continue
                from role_researcher import researcher_menu
                researcher_menu(user, password)

        elif choice == 4:
            user, password = authenticate("Auditor", "auditor")
            if user:
                if user.get("must_change_password"):
                    _force_password_change(user, password); continue
                from role_auditor import auditor_menu
                auditor_menu(user)

        if not user and choice != 5:
            pause("Press [Enter] to return to main menu...")


if __name__ == "__main__":
    main()
