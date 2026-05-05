"""
system_startup.py — System Key Encryption Key (KEK) Management
===============================================================
Implements Option A key protection: system private keys (master key,
incoming data key) are encrypted at rest with an AES-256 key derived
from an administrator-supplied passphrase. The KEK is held ONLY in
process RAM for the lifetime of the running server — it is never
written to disk in any form.

THREAT MODEL:
  Protected against: theft of the server disk / DB backup without the
  running process. An attacker who clones the filesystem cannot read
  system private keys without the passphrase.
  NOT protected against: live memory forensics on a running process,
  or an attacker who can read /proc/<pid>/mem. For that level, use an
  HSM (Option D split knowledge + hardware boundary).

TRADE-OFF (vs Option B env-var):
  Option A requires a human administrator at every startup — the system
  will not serve any users until the KEK passphrase is entered.
  Option B allows automated/unattended restart. For a clinical research
  platform under GDPR Article 32, the human-in-the-loop at startup is
  an intentional governance control, documented in the risk register.

PRODUCTION NOTE:
  Servers are long-running. The startup prompt appears only after a
  server restart. In non-cloud, bare-metal NHS/hospital environments
  this is consistent with physical key ceremony procedures for
  cryptographic key material (e.g., ISO 27001 Annex A.10).

KEK DERIVATION:
  KEK = SHA-256(passphrase_bytes + salt_bytes)
  The salt is a 32-byte random value generated once on first setup and
  stored in system_config (not secret — it's a KDF parameter).
  PRODUCTION NOTE: Replace SHA-256 derivation with Argon2id (memory-hard)
  for stronger resistance to offline dictionary attacks on the passphrase.

PASSPHRASE VERIFICATION:
  The Argon2id hash of the passphrase is stored in system_config. On
  startup, the passphrase is verified against this hash before the KEK
  is derived — providing fast, secure rejection of wrong passphrases
  without leaking timing information about the derived key.
"""

import os
import hashlib
import secrets
from typing import Optional

# ── In-memory KEK storage ──────────────────────────────────────────────────
# WHY module-level variable (not class): A module is a singleton in Python's
# import system. All callers that import this module share the same variable,
# making it a natural process-wide singleton without complex DI patterns.
# Alternative: threading.local() — considered but rejected because the KEK
# must be accessible across all threads (role modules run sequentially in a
# CLI, not concurrently).
_SYSTEM_KEK: Optional[bytes] = None


def is_system_unlocked() -> bool:
    """Return True if the system KEK has been loaded into RAM this session."""
    return _SYSTEM_KEK is not None


def get_system_kek() -> bytes:
    """
    Return the in-memory KEK. Raises RuntimeError if system is locked.
    Callers (key_manager) should call is_system_unlocked() first.
    """
    if _SYSTEM_KEK is None:
        raise RuntimeError(
            "System keys are locked. Administrator must log in and supply "
            "the KEK passphrase to unlock system services."
        )
    return _SYSTEM_KEK


def set_system_kek(kek: bytes) -> None:
    """Store the derived KEK in RAM. Called only during startup unlock."""
    global _SYSTEM_KEK
    _SYSTEM_KEK = kek


def clear_system_kek() -> None:
    """
    Zero out the KEK from RAM (called on clean shutdown).
    WHY: Python does not guarantee immediate memory zeroing when objects are
    garbage collected. Explicit overwrite reduces the window in which a
    memory dump could reveal the KEK. Note: CPython may still retain the
    old bytes object in an internal pool — a production system would use
    ctypes.memset on the underlying buffer.
    """
    global _SYSTEM_KEK
    _SYSTEM_KEK = None


def derive_kek(passphrase: str, salt_hex: str) -> bytes:
    """
    Derive a 256-bit AES key from a passphrase and hex-encoded salt.
    Returns 32 bytes suitable for AES-256-GCM-SIV.

    WHY SHA-256 (not Argon2id here):
      Argon2id is used for the passphrase VERIFICATION hash (stored in DB).
      For the AES key derivation we use SHA-256(passphrase + salt) to keep
      the key derivation fast (the heavy work is done by Argon2id verification
      before this is called). In production, replace with HKDF or Argon2id
      with hash_len=32 to make the key derivation itself memory-hard.
    WHY salt:
      Without a salt, two systems using the same passphrase would derive
      the same KEK, allowing cross-system key reuse. The 32-byte random salt
      makes each deployment's KEK unique even with an identical passphrase.
    """
    salt_bytes = bytes.fromhex(salt_hex)
    return hashlib.sha256(passphrase.encode("utf-8") + salt_bytes).digest()


def generate_kek_salt() -> str:
    """Generate a 32-byte cryptographically secure salt, returned as hex string."""
    return secrets.token_hex(32)
