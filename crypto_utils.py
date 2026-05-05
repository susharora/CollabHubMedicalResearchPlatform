"""
crypto_utils.py — Cryptographic Primitives for CollabHub
=========================================================
Central module providing all cryptographic operations used by the platform.
Keeping all crypto in one module ensures a single place for security review
and makes algorithm substitution straightforward.

ALGORITHM CHOICES (summary):
  AES-256-GCM-SIV    : Symmetric authenticated encryption for data at rest
  RSA-4096-OAEP      : Asymmetric key encapsulation (DEK wrapping)
  Ed25519            : Digital signatures for research findings
  SHA-256            : Deterministic audit hash chain
  Argon2id           : Password hashing (memory-hard, phishing-resistant)
  secrets/os.urandom : CSPRNG for nonce and key generation
"""

import os
import secrets
import hashlib
import base64
import json
from datetime import datetime

# cryptography library: provides AES-GCM-SIV, RSA-OAEP, Ed25519 via OpenSSL bindings.
# Alternative considered: PyCryptodome — rejected because cryptography has better
# maintained Rust/OpenSSL bindings and is the de-facto standard for Python crypto.
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ed25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.backends import default_backend

# argon2-cffi: Python bindings for the Argon2 reference implementation.
# Argon2id is chosen (vs bcrypt/scrypt) because it is the PHC winner and
# simultaneously resists GPU and side-channel attacks. time_cost=3,
# memory_cost=64MB is OWASP recommended minimum for interactive login.
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


# ── Argon2 Password Hashing ────────────────────────────────────────────────
# Single shared PasswordHasher instance; instantiating per-call would reload
# parameters each time and is wasteful. Parameters are intentionally slow to
# resist offline brute-force after a hypothetical DB breach.
# Alternative: bcrypt — rejected because Argon2id is memory-hard (defeats GPUs)
# and is the current NIST SP 800-63B recommendation.
_ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)

def hash_password(password: str) -> str:
    """
    Hash a plaintext password with Argon2id.
    WHY: Argon2id stores salt internally and is resistant to rainbow tables.
    Produced hash includes algorithm parameters so future cost increases are
    backward-compatible (old hashes re-verify fine with new params on login).
    """
    return _ph.hash(password)

def verify_password(stored_hash: str, password: str) -> bool:
    """
    Verify a plaintext password against an Argon2id hash.
    Returns False (not raises) on mismatch so callers need not catch exceptions.
    WHY: Normalising the return type to bool keeps authentication logic simple
    and avoids accidentally-uncaught VerifyMismatchError crashing the menu loop.
    """
    try:
        return _ph.verify(stored_hash, password)
    except VerifyMismatchError:
        return False


# ── AES-256-GCM-SIV Symmetric Encryption ─────────────────────────────────────
# AES-GCM-SIV is a misuse-resistant AEAD mode. It provides confidentiality
# and integrity while avoiding catastrophic failure if a nonce is accidentally
# reused. Unlike AES-GCM, it derives a synthetic IV from the key, nonce,
# plaintext and AAD before encryption.
# This means ciphertext tampering is detected on decrypt.
# Alternative: AES-CBC + HMAC-SHA256 was rejected because AEAD modes integrate
# encryption and authentication in one API, reducing implementation mistakes.

def generate_dek() -> bytes:
    """
    Generate a 256-bit Data Encryption Key using the OS CSPRNG.
    WHY AES-256: Provides 128-bit post-quantum security margin (Grover's algorithm
    halves effective key length). 128-bit AES would give only 64-bit PQ margin.
    WHY AESGCMSIV.generate_key: Delegates to os.urandom under the hood, ensuring
    the key comes from the OS entropy pool (dev/urandom on Linux), not Python PRNG.
    """
    return AESGCMSIV.generate_key(bit_length=256)

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext with AES-256-GCM-SIV.
    Output format: [12-byte nonce][ciphertext+16-byte auth tag]
    WHY prepend nonce: The nonce must be transmitted alongside the ciphertext
    for decryption. Prepending is simpler than a separate field and self-contained.
    WHY 12-byte nonce: AES-GCM-SIV uses a 96-bit nonce in this library API.
    A random 12-byte nonce gives a large nonce space and matches the standard
    AEAD nonce size used by GCM-family modes. GCM-SIV is also more misuse-resistant
    than standard GCM if accidental nonce reuse occurs.
    Alternative: Store nonce separately in DB — rejected because it couples
    the encryption output to a specific storage schema; a self-contained blob
    is portable and simpler to audit.
    """
    # secrets.token_bytes uses os.urandom — cryptographically unpredictable.
    # Python's random module must NEVER be used for nonce generation.
    nonce = secrets.token_bytes(12)
    aesgcmsiv = AESGCMSIV(key)
    ct = aesgcmsiv.encrypt(nonce, plaintext, None)   # None = no additional associated data
    return nonce + ct                              # nonce prepended for self-contained blobs

def aes_decrypt(key: bytes, data: bytes) -> bytes:
    """
    Decrypt AES-256-GCM-SIV ciphertext.
    Raises cryptography.exceptions.InvalidTag if auth tag fails (tampered data).
    WHY let exception propagate: Callers must handle tamper detection explicitly;
    silently returning wrong data would be a catastrophic security failure.
    """
    nonce = data[:12]    # first 12 bytes are the nonce prepended at encrypt time
    ct    = data[12:]    # remainder is ciphertext + 16-byte auth tag
    aesgcmsiv = AESGCMSIV(key)
    return aesgcmsiv.decrypt(nonce, ct, None)


# ── RSA-OAEP Key Encapsulation ─────────────────────────────────────────────
# RSA wraps AES key; AES encrypts data
# This hybrid approach (RSA wraps AES key; AES encrypts data) is the standard
# pattern because RSA is orders of magnitude slower than AES for large payloads.
# WHY RSA-4096: 4096-bit RSA is commonly treated as providing roughly 128- to 150-bit 
# classical security, depending on the estimation model.
# With RSA-OAEP SHA-256, the maximum plaintext for 4096-bit key is 446 bytes — sufficient for
# a 32-byte DEK. 
# Alternative: ECDH/ECIES-style wrapping could also support this use case, 
# but RSA-OAEP was chosen for the prototype because recipient public-key wrapping is 
# simple to implement and explain in an asynchronous assignment workflow.
# It allows a single public key usage to wrap for any recipient without a
# key-agreement ceremony.
# WHY OAEP vs PKCS#1 v1.5: PKCS#1 v1.5 is vulnerable to Bleichenbacher padding
# oracle attacks. OAEP with SHA-256 provides CCA-secure padding in the random-oracle model 
# and avoids the historical padding-oracle weaknesses of PKCS#1 v1.5.

def generate_rsa_keypair(key_size: int = 4096):
    """
    Generate an RSA keypair.
    key_size=4096 is the default; 2048 used only in tests for speed.
    WHY e=65537: Standard Fermat prime; provides good security and fast encryption.
    Alternative: ECDSA P-256 — rejected for key wrapping because RSA OAEP gives
    cleaner semantics (direct encryption of DEK) vs ECDH (requires KDF + AES wrap).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    return private_key, private_key.public_key()

def rsa_wrap_key(public_key, dek: bytes) -> bytes:
    """
    Encrypt (wrap) a DEK using RSA-OAEP with SHA-256 mask generation.
    WHY MGF1+SHA256: MGF1 (Mask Generation Function) is the standard OAEP
    component. SHA-256 for both the hash and MGF provides consistent 256-bit
    hash strength throughout the padding scheme.
    """
    return public_key.encrypt(
        dek,
        OAEP(mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def rsa_unwrap_key(private_key, wrapped_key: bytes) -> bytes:
    """
    Decrypt (unwrap) a DEK using RSA-OAEP.
    Raises ValueError on decryption failure (wrong key or corrupted ciphertext).
    WHY let exception propagate: The caller must handle key mismatch explicitly;
    swallowing the exception would allow silent failures in access control.
    """
    return private_key.decrypt(
        wrapped_key,
        OAEP(mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def serialize_private_key(private_key, password: bytes = None) -> bytes:
    """
    Serialise RSA private key to PKCS#8 PEM format.
    PKCS#8 is the modern container format; older PKCS#1 (traditional) format
    is not used as it is algorithm-specific and less interoperable.
    """
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc
    )

def serialize_public_key(public_key) -> bytes:
    """
    Serialise RSA public key to SubjectPublicKeyInfo PEM.
    SPKI is the standard format used in X.509 certificates and TLS; choosing
    this format ensures interoperability if keys are ever shared externally.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_private_key(pem_data: bytes, password: bytes = None):
    """Load an RSA or Ed25519 private key from PEM bytes."""
    return serialization.load_pem_private_key(pem_data, password=password, backend=default_backend())

def load_public_key(pem_data: bytes):
    """Load an RSA or Ed25519 public key from PEM bytes."""
    return serialization.load_pem_public_key(pem_data, backend=default_backend())


# ── Ed25519 Digital Signatures ─────────────────────────────────────────────
# Ed25519 is used exclusively for signing research findings (non-repudiation).
# WHY Ed25519 vs RSA-PSS or ECDSA P-256:
#   - Ed25519 has no per-signature random requirement (ECDSA requires good
#     randomness per sign; weak RNG famously broke PS3 security)
#   - Constant-time implementation in OpenSSL — immune to timing side-channels
#   - Much shorter signatures (64 bytes) vs RSA-2048 (256 bytes)
#   - Batch verification possible for auditor workloads
# Alternative: RSA-PSS with SHA-256 — rejected because Ed25519 is faster,
# produces shorter outputs, and is immune to the "nonce reuse" class of attacks.

def generate_ed25519_keypair():
    """
    Generate an Ed25519 signing keypair.
    Ed25519 uses Curve25519 (Bernstein et al.); the private key is a 32-byte
    scalar and the public key is a compressed point on the curve.
    """
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()

def ed25519_sign(private_key, message: bytes) -> bytes:
    """
    Sign an arbitrary message with Ed25519. Returns a 64-byte signature.
    WHY sign the full message bytes: Signing a hash of the message (sign-then-hash)
    would require trusting the hash function; Ed25519 hashes internally (SHA-512
    over the key + message) so passing raw bytes is the correct API.
    """
    return private_key.sign(message)

def ed25519_verify(public_key, signature: bytes, message: bytes) -> bool:
    """
    Verify an Ed25519 signature. Returns bool rather than raising.
    WHY bool return: Callers (auditor module) need a simple True/False result
    to display to the auditor; exception-based API would require try/except
    everywhere and risks uncaught exceptions silencing the verification failure.
    """
    try:
        public_key.verify(signature, message)
        return True
    except Exception:
        return False

def serialize_ed25519_private(private_key) -> bytes:
    """Serialise Ed25519 private key to PKCS#8 PEM (unencrypted; caller encrypts)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def serialize_ed25519_public(public_key) -> bytes:
    """Serialise Ed25519 public key to SubjectPublicKeyInfo PEM."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_ed25519_private(pem_data: bytes):
    """Load Ed25519 private key from PEM bytes."""
    return serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())

def load_ed25519_public(pem_data: bytes):
    """Load Ed25519 public key from PEM bytes."""
    return serialization.load_pem_public_key(pem_data, backend=default_backend())


# ── SHA-256 Audit Hash Chain ───────────────────────────────────────────────
# The audit log uses a hash chain where each event's hash includes the
# previous event's hash. This creates a tamper-evident structure: modifying
# any event invalidates all subsequent hashes, detectable by any verifier.
# WHY SHA-256 not SHA-3: SHA-256 is hardware-accelerated (SHA-NI instructions)
# and provides 128-bit collision resistance, more than sufficient for audit
# chains. SHA-3 is equally secure but slower in software and hardware support
# is less universal. This is integrity, not collision-resistance, so SHA-256 is fine.
# Alternative: HMAC-SHA256 — would require a shared secret key; SHA-256 chaining
# is sufficient because the chain is verifiable by anyone with the log.
# Alternative: Merkle tree — overkill for a sequential event log; a linear chain
# is simpler, auditable sequentially, and entirely sufficient.

def compute_event_hash(event_data: dict, prev_hash: str) -> str:
    """
    Compute SHA-256 hash for an audit event, chaining it to the previous hash.
    WHY JSON serialise with sort_keys: JSON field order is non-deterministic;
    sort_keys ensures identical serialisation regardless of dict insertion order,
    making the hash reproducible across any Python version or machine.
    WHY concatenate prev_hash into the payload: This binds the event to its
    position in the chain. Reordering events breaks all subsequent hashes.
    """
    payload = json.dumps(event_data, sort_keys=True, default=str) + prev_hash
    return hashlib.sha256(payload.encode()).hexdigest()

def compute_sha256(data: bytes) -> str:
    """Compute a bare SHA-256 hex digest. Used for dataset content hashing."""
    return hashlib.sha256(data).hexdigest()


# ── Cryptographically Secure Random ID Generation ─────────────────────────
# WHY secrets module not random: Python's random module uses Mersenne Twister
# (PRNG not CSPRNG) — predictable if seeded state is known. secrets uses
# os.urandom (kernel entropy pool) and is unpredictable even to root.
# WHY hex encoding: hex is URL-safe, database-safe, and visually distinct.
# Alternative: UUID4 — uses os.urandom but has fixed structure (4 variant bits
# set), reducing entropy slightly. secrets.token_hex gives full 128-bit entropy.

def secure_random_id(prefix: str = "", length: int = 16) -> str:
    """
    Generate a cryptographically secure random ID string.
    prefix:  Human-readable namespace (e.g., 'ORG-', 'EVT-')
    length:  Number of random BYTES (hex string will be 2× longer)
    """
    return prefix + secrets.token_hex(length)

def generate_ch_uid() -> str:
    """
    Generate a CollabHub unique patient UID (CH-XXXXXXXXXXXXXXXX).
    8 random bytes = 64-bit entropy = 1.8×10¹⁹ values; collision probability
    < 1 in a billion even with 1 million records (birthday bound).
    WHY uppercase hex: More readable in audit logs and UI displays.
    Alternative: Sequential integer — rejected because sequential IDs leak
    dataset size and allow enumeration attacks on the API/UI.
    """
    return "CH-" + secrets.token_hex(8).upper()

def generate_dataset_id() -> str:
    """
    Generate a dataset ID (DS-XXXXXXXXXXXX).
    6 random bytes gives ~10¹⁴ possible IDs; collision-safe for any
    foreseeable number of datasets in a clinical research platform.
    """
    return "DS-" + secrets.token_hex(6).upper()


# ── Encoding Helpers ───────────────────────────────────────────────────────
# WHY base64 for binary-in-text storage: Database columns (SQLite TEXT) and
# JSON fields cannot store raw bytes. Base64url or standard base64 encoding
# is the conventional choice. We use standard (non-URL-safe) base64 here
# because the encoded values are stored in files/DB, not in HTTP URLs.

def b64e(data: bytes) -> str:
    """Encode bytes to base64 string for storage in text fields or JSON."""
    return base64.b64encode(data).decode()

def b64d(s: str) -> bytes:
    """Decode base64 string back to bytes."""
    return base64.b64decode(s)
