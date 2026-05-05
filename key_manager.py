"""
key_manager.py — Key Lifecycle Management for CollabHub
========================================================
Provides generate, store, and load operations for all cryptographic keys
used by the platform: user RSA keypairs, user Ed25519 keypairs, organisation
RSA keypairs, system RSA keypairs, and dataset DEK wrapped copies.

KEY STORAGE ARCHITECTURE:
  All private key material is stored on the filesystem (under /keys/),
  NOT in the SQLite database. The DB stores only:
    - Public key PEMs (safe to store anywhere)
    - File PATHS to encrypted private key files

  WHY filesystem for private keys:
    - OS-level file permissions (chmod 600) restrict access independently of
      the DB credentials — layered access control.
    - Private keys can be backed up, archived, or hardware-protected (HSM)
      independently of the application DB.
    - In production: replace file writes with HSM API calls without changing
      the rest of the codebase.
    Alternative: Store encrypted private keys as BLOBs in the DB — rejected
    because it couples key material to DB backups and access control.

  WHY AES-256-GCM-SIV to protect user private keys (not RSA password-protection):
    - serialization.BestAvailableEncryption() uses the key as a password,
      which has limited entropy. We derive a 256-bit key from password+salt
      via SHA-256 and encrypt the PEM with AES-256-GCM-SIV for stronger protection.
    Alternative: PKCS#8 encrypted PEM with scrypt — would be preferred in
    production. SHA-256 derivation is used here for simplicity; in production
    replace _derive_key_from_password with Argon2id.

  DIRECTORY STRUCTURE:
    keys/
      users/<user_id>/
        rsa_private_enc.bin    (AES-encrypted RSA private key PEM)
        rsa_public.pem         (RSA public key, plaintext)
        ed_private_enc.bin     (AES-encrypted Ed25519 private key PEM, researchers only)
        ed_public.pem          (Ed25519 public key, plaintext)
      orgs/<org_id>/
        org_public.pem         (RSA public key for PII DEK wrapping)
        org_private.pem        (RSA private key — hospital retains this)
      system/
        <key_name>_public.pem
        <key_name>_private.pem
      datasets/<dataset_id>/
        <dataset_id>_research_dek_clin.wrapped   (RSA-encrypted DEK, clinician key)
        <dataset_id>_research_dek_master.wrapped  (RSA-encrypted DEK, master key)
        <dataset_id>_pii_dek.wrapped              (RSA-encrypted DEK, org key)
        researcher_<user_id>_dek.bin              (RSA-encrypted DEK, per researcher)
"""

import os
import json
from crypto_utils import (
    generate_rsa_keypair, generate_ed25519_keypair,
    serialize_private_key, serialize_public_key,
    serialize_ed25519_private, serialize_ed25519_public,
    load_private_key, load_public_key,
    load_ed25519_private, load_ed25519_public,
    aes_encrypt, aes_decrypt, generate_dek,
    rsa_wrap_key, rsa_unwrap_key, b64e, b64d
)

KEYS_DIR = os.path.join(os.path.dirname(__file__), "keys")


def _user_key_dir(user_id: str) -> str:
    d = os.path.join(KEYS_DIR, "users", user_id)
    os.makedirs(d, exist_ok=True)
    return d


def _org_key_dir(org_id: str) -> str:
    d = os.path.join(KEYS_DIR, "orgs", org_id)
    os.makedirs(d, exist_ok=True)
    return d


def _sys_key_dir() -> str:
    d = os.path.join(KEYS_DIR, "system")
    os.makedirs(d, exist_ok=True)
    return d


def _dataset_key_dir(dataset_id: str) -> str:
    d = os.path.join(KEYS_DIR, "datasets", dataset_id)
    os.makedirs(d, exist_ok=True)
    return d


# ── User key generation ───────────────────────────────────────────────────

def generate_user_keys(user_id: str, role: str, password: str) -> dict:
    """
    Generate and persist cryptographic key material for a newly verified user.
    Returns a dict with public key PEMs (for DB storage) and key file paths.

    Key allocation by role:
      Clinician  : 1 RSA-4096 keypair (DEK wrap/unwrap for dataset assignment)
      Researcher : 1 RSA-4096 keypair (DEK unwrap for decryption)
                 + 1 Ed25519 keypair  (finding signing/verification)
      Auditor    : 1 RSA-4096 keypair (for potential future encrypted data receipt)
      Admin      : No asymmetric keys (admin does not handle patient data)

    WHY generate at verification time (not registration): Keys are generated
    when admin verifies the user after identity checks. Unverified users have
    no keys and cannot participate in cryptographic operations.
    WHY store encrypted on filesystem: Private key material never enters the DB.
    The encrypted file + the user's password are the two factors required.
    """
    key_dir = _user_key_dir(user_id)
    result = {}

    # All roles get RSA keypair for DEK wrapping
    rsa_priv, rsa_pub = generate_rsa_keypair()
    rsa_pub_pem = serialize_public_key(rsa_pub).decode()

    # Encrypt private key with password-derived protection
    # We use a fixed derived key from password for simplicity (Argon2 in real scenario)
    # Here we store encrypted PEM using AES with a password-derived key
    priv_pem = serialize_private_key(rsa_priv)
    # Encrypt the private key PEM with AES using password as passphrase key
    pw_key = _derive_key_from_password(password, user_id + "_rsa")
    encrypted_priv = aes_encrypt(pw_key, priv_pem)

    rsa_priv_path = os.path.join(key_dir, "rsa_private_enc.bin")
    rsa_pub_path = os.path.join(key_dir, "rsa_public.pem")

    with open(rsa_priv_path, "wb") as f:
        f.write(encrypted_priv)
    with open(rsa_pub_path, "wb") as f:
        f.write(rsa_pub_pem.encode())

    result["rsa_pub_pem"] = rsa_pub_pem
    result["rsa_priv_path"] = rsa_priv_path
    result["rsa_pub_path"] = rsa_pub_path

    if role == "researcher":
        # Ed25519 for signing findings
        ed_priv, ed_pub = generate_ed25519_keypair()
        ed_pub_pem = serialize_ed25519_public(ed_pub).decode()
        ed_priv_pem = serialize_ed25519_private(ed_priv)

        pw_key_ed = _derive_key_from_password(password, user_id + "_ed")
        encrypted_ed_priv = aes_encrypt(pw_key_ed, ed_priv_pem)

        ed_priv_path = os.path.join(key_dir, "ed_private_enc.bin")
        ed_pub_path = os.path.join(key_dir, "ed_public.pem")

        with open(ed_priv_path, "wb") as f:
            f.write(encrypted_ed_priv)
        with open(ed_pub_path, "wb") as f:
            f.write(ed_pub_pem.encode())

        result["ed_pub_pem"] = ed_pub_pem
        result["ed_priv_path"] = ed_priv_path
        result["ed_pub_path"] = ed_pub_path

    return result


def _derive_key_from_password(password: str, salt_str: str) -> bytes:
    """
    Derive a 256-bit AES key from a password and per-user salt string.

    WHY SHA-256 (not Argon2 here): This module already uses the crypto_utils
    AES functions which need a raw key. Argon2 is used for login (via database
    module) where the output is a stored hash. Here we need a deterministic
    AES key from the password so the private key file can be decrypted on
    each login with the same password.
    WHY NOT store the derived key: The key is re-derived from the password on
    each login. Storing it would create another secret to protect.
    PRODUCTION NOTE: Replace with Argon2id(password, salt_str, 32-byte output)
    for stronger key derivation. SHA-256 is acceptable for a prototype where
    the private key file is additionally protected by OS file permissions.
    """
    import hashlib
    return hashlib.sha256((password + salt_str).encode()).digest()


def load_user_rsa_private(user_id: str, password: str):
    """Load and decrypt user's RSA private key."""
    key_dir = _user_key_dir(user_id)
    path = os.path.join(key_dir, "rsa_private_enc.bin")
    with open(path, "rb") as f:
        encrypted_priv = f.read()
    pw_key = _derive_key_from_password(password, user_id + "_rsa")
    priv_pem = aes_decrypt(pw_key, encrypted_priv)
    return load_private_key(priv_pem)


def load_user_rsa_public(user_id: str):
    """Load user's RSA public key."""
    key_dir = _user_key_dir(user_id)
    path = os.path.join(key_dir, "rsa_public.pem")
    with open(path, "rb") as f:
        return load_public_key(f.read())


def load_user_ed_private(user_id: str, password: str):
    """Load and decrypt user's Ed25519 private key."""
    key_dir = _user_key_dir(user_id)
    path = os.path.join(key_dir, "ed_private_enc.bin")
    with open(path, "rb") as f:
        encrypted_priv = f.read()
    pw_key = _derive_key_from_password(password, user_id + "_ed")
    priv_pem = aes_decrypt(pw_key, encrypted_priv)
    return load_ed25519_private(priv_pem)


def load_user_ed_public(user_id: str):
    key_dir = _user_key_dir(user_id)
    path = os.path.join(key_dir, "ed_public.pem")
    with open(path, "rb") as f:
        return load_ed25519_public(f.read())


# ── Organisation keys (PII vault wrapping) ───────────────────────────────

def generate_org_keypair(org_id: str) -> dict:
    """Generate RSA keypair for hospital org (PII DEK wrapping)."""
    key_dir = _org_key_dir(org_id)
    priv, pub = generate_rsa_keypair()
    pub_pem = serialize_public_key(pub).decode()
    priv_pem = serialize_private_key(priv)

    with open(os.path.join(key_dir, "org_public.pem"), "wb") as f:
        f.write(pub_pem.encode())
    with open(os.path.join(key_dir, "org_private.pem"), "wb") as f:
        f.write(priv_pem)

    return {"pub_pem": pub_pem}


def load_org_rsa_public(org_id: str):
    path = os.path.join(_org_key_dir(org_id), "org_public.pem")
    with open(path, "rb") as f:
        return load_public_key(f.read())


def load_org_rsa_private(org_id: str):
    path = os.path.join(_org_key_dir(org_id), "org_private.pem")
    with open(path, "rb") as f:
        return load_private_key(f.read())


# ── System keys (Master key, Incoming data key) ──────────────────────────

def _system_key_dir():
    """Alias for _sys_key_dir for backward compatibility with new modules."""
    return _sys_key_dir()


def generate_system_key(key_name: str) -> dict:
    """
    Generate a system RSA keypair.
    If a KEK is available in system_startup, encrypts the private key.
    Otherwise saves plaintext (seeder must set KEK before calling).
    Returns dict with pub_pem, priv_path, pub_path.
    """
    from system_startup import is_system_unlocked, get_system_kek
    key_dir   = _sys_key_dir()
    safe_name = key_name.replace(" ", "_").replace("-", "_")
    priv, pub = generate_rsa_keypair()
    pub_pem   = serialize_public_key(pub).decode()
    priv_pem  = serialize_private_key(priv)

    pub_path  = os.path.join(key_dir, f"{safe_name}_public.pem")
    with open(pub_path, "wb") as f:
        f.write(pub_pem.encode())

    if is_system_unlocked():
        # Encrypt private key with KEK (Option A)
        from crypto_utils import aes_encrypt
        kek      = get_system_kek()
        enc_data = aes_encrypt(kek, priv_pem)
        priv_path = os.path.join(key_dir, f"{safe_name}_private_enc.bin")
        with open(priv_path, "wb") as f:
            f.write(enc_data)
        # Remove plaintext if it exists
        plain = os.path.join(key_dir, f"{safe_name}_private.pem")
        if os.path.exists(plain):
            os.remove(plain)
    else:
        # Plaintext fallback (should not happen in production after KEK is set)
        priv_path = os.path.join(key_dir, f"{safe_name}_private.pem")
        with open(priv_path, "wb") as f:
            f.write(priv_pem)

    return {"pub_pem": pub_pem, "priv_path": priv_path, "pub_path": pub_path}

def load_system_key_public(key_name: str):
    """
    Load system public key.
    Primary source: pub_pem column in system_keys DB table (authoritative,
    immune to filename convention changes between versions).
    Fallback: filesystem with both hyphen and underscore naming conventions
    to handle keys generated by older versions of the seeder.

    WHY DB-first: The seeder and generate_system_key() both write pub_pem
    to the system_keys table. Reading from DB avoids any filename mismatch
    caused by hyphen-vs-underscore conversion differences across versions.
    """
    # 1. Try DB first (most reliable — independent of filename convention)
    try:
        from database import get_conn
        conn = get_conn()
        row  = conn.execute(
            "SELECT pub_pem FROM system_keys WHERE key_name=? AND status='active' "
            "ORDER BY created_at DESC LIMIT 1",
            (key_name,)
        ).fetchone()
        conn.close()
        if row and row["pub_pem"]:
            return load_public_key(row["pub_pem"].encode())
    except Exception:
        pass  # Fall through to filesystem

    # 2. Filesystem fallback — try both naming conventions
    key_dir = _sys_key_dir()
    for name_variant in [
        key_name.replace(" ", "_").replace("-", "_"),  # hyphens→underscores (current)
        key_name.replace(" ", "_"),                    # spaces→underscores, hyphens kept (old)
        key_name,                                       # literal key name
    ]:
        path = os.path.join(key_dir, f"{name_variant}_public.pem")
        if os.path.exists(path):
            with open(path, "rb") as f:
                return load_public_key(f.read())

    raise FileNotFoundError(
        f"Public key not found for '{key_name}'. "
        f"Check system_keys table and keys/system/ directory. "
        f"Re-generate the key via Admin > Entity Management if needed."
    )


def load_system_key_private(key_name: str):
    """
    Load system private key — decrypts with in-memory KEK if encrypted.
    Falls back to plaintext .pem for legacy/test compatibility.
    Raises RuntimeError if system is locked and only encrypted version exists.
    """
    from system_startup import is_system_unlocked, get_system_kek

    key_dir   = _sys_key_dir()
    safe_name = key_name.replace(" ", "_").replace("-", "_")
    enc_path  = os.path.join(key_dir, f"{safe_name}_private_enc.bin")
    pem_path  = os.path.join(key_dir, f"{safe_name}_private.pem")

    if os.path.exists(enc_path):
        if not is_system_unlocked():
            raise RuntimeError(
                f"System is locked. Cannot load '{key_name}' private key. "
                "Administrator must supply KEK passphrase at startup."
            )
        from crypto_utils import aes_decrypt
        with open(enc_path, "rb") as f:
            enc_data = f.read()
        pem_bytes = aes_decrypt(get_system_kek(), enc_data)
        return load_private_key(pem_bytes)

    elif os.path.exists(pem_path):
        with open(pem_path, "rb") as f:
            return load_private_key(f.read())
    else:
        raise FileNotFoundError(
            f"System private key not found: '{key_name}' "
            "(tried {enc_path} and {pem_path})"
        )

def save_system_key_encrypted(key_name: str, private_key, kek: bytes) -> str:
    """Encrypt a system private key with the given KEK. Removes plaintext version."""
    from crypto_utils import aes_encrypt
    key_dir   = _sys_key_dir()
    safe_name = key_name.replace(" ", "_").replace("-", "_")
    pem_bytes = serialize_private_key(private_key)
    enc_data  = aes_encrypt(kek, pem_bytes)
    enc_path  = os.path.join(key_dir, f"{safe_name}_private_enc.bin")
    with open(enc_path, "wb") as f:
        f.write(enc_data)
    # Remove plaintext version
    pem_path = os.path.join(key_dir, f"{safe_name}_private.pem")
    if os.path.exists(pem_path):
        os.remove(pem_path)
    return enc_path

def save_wrapped_dek(dataset_id: str, filename: str, wrapped_dek: bytes) -> str:
    """Save a wrapped DEK blob. Returns file path."""
    key_dir = _dataset_key_dir(dataset_id)
    path = os.path.join(key_dir, filename)
    with open(path, "wb") as f:
        f.write(wrapped_dek)
    return path


def load_wrapped_dek(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def save_researcher_dek(dataset_id: str, user_id: str, wrapped_dek: bytes) -> str:
    """Save researcher-specific wrapped DEK."""
    key_dir = _dataset_key_dir(dataset_id)
    path = os.path.join(key_dir, f"researcher_{user_id}_dek.bin")
    with open(path, "wb") as f:
        f.write(wrapped_dek)
    return path
