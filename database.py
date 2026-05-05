"""
database.py — SQLite Schema, Connection Management, and Audit Chain
====================================================================
Provides the relational data store for all platform metadata. Raw encrypted
data (patient records) is stored on the filesystem; only metadata, keys, and
audit events live in SQLite.

WHY SQLite (not PostgreSQL/MySQL):
  - No separate server process; simpler deployment for a prototype/reference system
  - WAL journal mode enables concurrent reads alongside writes
  - ACID transactions protect audit integrity
  - Sufficient for clinical research collaboration scale (thousands of records)
  Alternative: PostgreSQL — would be chosen for production at scale (row-level
  locking, native JSON, partitioning). SQLite is appropriate here because the
  requirement is a demonstrable Python cryptosystem, not a production DBMS.

WHY relational DB for metadata but files for encrypted data:
  - Encrypted blobs (research records, PII) can be gigabytes; SQLite BLOB
    storage is inefficient for large binary data and lacks streaming support.
  - File paths in the DB are pointers; the actual data lives on a filesystem
    that can be swapped to block storage, object storage, etc. independently.
  - Files can be independently replicated, backed up, and access-controlled
    at the OS level without DB involvement.
  - Keys (wrapped DEKs) are small (<1 KB); storing them as files keeps the
    key lifecycle independent of the data lifecycle (you can delete a key
    without touching the encrypted file).
"""

import sqlite3
import os
import json
from datetime import datetime, timezone
from crypto_utils import compute_event_hash, secure_random_id

# Database file location: relative to this module's directory so the path
# works regardless of the working directory when the script is invoked.
DB_PATH = os.path.join(os.path.dirname(__file__), "data", "collab_hub.db")


def get_conn():
    """
    Open and return a SQLite connection with Row factory and foreign keys ON.
    WHY row_factory = sqlite3.Row: Allows column access by name (row["col"])
    rather than index (row[0]), which is clearer and refactoring-safe.
    WHY PRAGMA foreign_keys = ON: SQLite disables FK enforcement by default;
    enabling it catches referential integrity violations at the DB layer.
    WHY PRAGMA journal_mode = WAL: Write-Ahead Logging allows concurrent readers
    during a write transaction, important for an interactive multi-role system.
    Alternative: Returning a connection pool — overkill for a single-process
    CLI application; fresh connections are cheap and avoid shared-state bugs.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db():
    """
    Create all tables if they do not exist. Idempotent — safe to call on startup.
    WHY CREATE TABLE IF NOT EXISTS: Allows the application to call init_db()
    on every startup without failing when tables already exist.
    WHY TEXT PRIMARY KEY (not INTEGER): String IDs (e.g. "ORG-HOSP-001") are
    human-readable in logs and portable across DB instances. INTEGER autoincrement
    would expose record count and create coupling between DB instances.
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_conn()
    c = conn.cursor()

    # ── Organisations Table ─────────────────────────────────────────────
    # Stores hospitals, research orgs, and auditor firms as a single polymorphic
    # table differentiated by org_type. WHY not separate tables per type: the
    # overlapping attributes (name, country, status, public key) are identical;
    # a single table with a type discriminator avoids schema duplication.
    c.execute("""
    CREATE TABLE IF NOT EXISTS organisations (
        org_id          TEXT PRIMARY KEY,
        org_name        TEXT NOT NULL UNIQUE,
        org_type        TEXT NOT NULL CHECK(org_type IN ('hospital','research_org','auditor_firm')),
        country         TEXT NOT NULL,
        status          TEXT NOT NULL DEFAULT 'unverified'
                        CHECK(status IN ('unverified','verified','suspended')),
        public_key_pem  TEXT,
        created_at      TEXT NOT NULL,
        updated_at      TEXT NOT NULL
    )""")

    # ── Users Table ─────────────────────────────────────────────────────
    # All user roles in one table (admin, clinician, researcher, auditor).
    # WHY single table: The role field drives RBAC; splitting by role would
    # require JOINs for any cross-role query and complicate FK references.
    # WHY store public key PEM in DB: Public keys are not secret and need to
    # be efficiently retrievable for DEK wrapping (clinician assigns dataset).
    # WHY store private key path (not the key itself): Private keys are
    # encrypted and stored on the filesystem; the DB holds the path. This
    # ensures the encrypted key blob is not in the same data store as the
    # hashed password — layered security.
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        user_id         TEXT PRIMARY KEY,
        username        TEXT NOT NULL UNIQUE,
        password_hash   TEXT NOT NULL,
        role            TEXT NOT NULL CHECK(role IN ('admin','clinician','researcher','auditor')),
        full_name       TEXT NOT NULL,
        email           TEXT NOT NULL UNIQUE,
        org_id          TEXT REFERENCES organisations(org_id),
        country         TEXT,
        status          TEXT NOT NULL DEFAULT 'unverified'
                        CHECK(status IN ('unverified','verified','suspended','invited')),
        rsa_pub_pem         TEXT,
        rsa_priv_enc        TEXT,
        ed_pub_pem          TEXT,
        ed_priv_enc         TEXT,
        created_at          TEXT NOT NULL,
        updated_at          TEXT NOT NULL
    )""")

    # ── Studies Table ────────────────────────────────────────────────────
    # A study is the unit of access control for researchers. Datasets are
    # linked to studies; researchers are assigned to studies; this intersection
    # determines who can decrypt what.
    c.execute("""
    CREATE TABLE IF NOT EXISTS studies (
        study_id        TEXT PRIMARY KEY,
        study_name      TEXT NOT NULL,
        description     TEXT,
        status          TEXT NOT NULL DEFAULT 'unverified'
                        CHECK(status IN ('unverified','verified','completed','suspended')),
        created_by      TEXT REFERENCES users(user_id),
        created_at      TEXT NOT NULL,
        updated_at      TEXT NOT NULL
    )""")

    # ── Study-Researcher Junction Table ──────────────────────────────────
    # Many-to-many: a researcher can be on many studies; a study has many
    # researchers. WHY explicit junction table not a JSON array in studies:
    # Relational integrity, efficient lookup, and easy addition/removal of
    # individual assignments without parsing/rewriting JSON blobs.
    c.execute("""
    CREATE TABLE IF NOT EXISTS study_researchers (
        study_id        TEXT REFERENCES studies(study_id),
        user_id         TEXT REFERENCES users(user_id),
        assigned_at     TEXT NOT NULL,
        assigned_by     TEXT REFERENCES users(user_id),
        PRIMARY KEY (study_id, user_id)
    )""")

    # ── Datasets Table ───────────────────────────────────────────────────
    # Metadata for each ingested dataset. The actual encrypted files are
    # referenced by path. Two dataset IDs (dataset_id for research data,
    # pii_dataset_id for PII vault) allow independent lifecycle management:
    # the PII vault can be sent to the hospital without touching the research dataset.
    # WHY file paths in DB not BLOBs: Encrypted datasets may be megabytes;
    # storing file paths keeps the DB lightweight and queryable. Files can
    # be on NFS, S3, or local disk without DB schema changes.
    c.execute("""
    CREATE TABLE IF NOT EXISTS datasets (
        dataset_id          TEXT PRIMARY KEY,
        pii_dataset_id      TEXT NOT NULL UNIQUE,
        dataset_name        TEXT NOT NULL,
        source_org_id       TEXT REFERENCES organisations(org_id),
        study_id            TEXT REFERENCES studies(study_id),
        uploaded_by         TEXT REFERENCES users(user_id),
        status              TEXT NOT NULL DEFAULT 'unverified'
                            CHECK(status IN ('unverified','verified','assigned','suspended','revoked')),
        encrypted_research_path   TEXT,
        encrypted_pii_path        TEXT,
        wrapped_research_dek_path TEXT,
        wrapped_master_dek_path   TEXT,
        wrapped_pii_dek_path      TEXT,
        records_processed   INTEGER DEFAULT 0,
        records_ingested    INTEGER DEFAULT 0,
        records_discarded   INTEGER DEFAULT 0,
        created_at          TEXT NOT NULL,
        updated_at          TEXT NOT NULL
    )""")

    # ── Researcher-Dataset Keys Table ─────────────────────────────────────
    # Per-researcher wrapped DEK storage. When a clinician assigns a dataset
    # to a study, this table is populated with one row per researcher — each
    # containing that researcher's personal wrapped copy of the research DEK.
    # WHY a separate table not a column in datasets: One dataset can be
    # accessible to many researchers simultaneously; a single column cannot
    # hold multiple researcher-specific wrapped keys.
    c.execute("""
    CREATE TABLE IF NOT EXISTS researcher_dataset_keys (
        rdkey_id        TEXT PRIMARY KEY,
        dataset_id      TEXT REFERENCES datasets(dataset_id),
        user_id         TEXT REFERENCES users(user_id),
        wrapped_dek_path TEXT NOT NULL,
        created_at      TEXT NOT NULL,
        UNIQUE(dataset_id, user_id)
    )""")

    # ── Findings Table ────────────────────────────────────────────────────
    # Stores signed research findings. The signature_b64 is an Ed25519 signature
    # over a canonical JSON of the finding context (study, dataset, researcher,
    # text, timestamp, data hash). Findings are immutable once signed.
    c.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        finding_id      TEXT PRIMARY KEY,
        study_id        TEXT REFERENCES studies(study_id),
        dataset_id      TEXT REFERENCES datasets(dataset_id),
        researcher_id   TEXT REFERENCES users(user_id),
        finding_text    TEXT NOT NULL,
        signature_b64   TEXT NOT NULL,
        signed_at       TEXT NOT NULL
    )""")

    # ── Audit Log Table ───────────────────────────────────────────────────
    # Tamper-evident event log using a SHA-256 hash chain. Each row stores:
    #   prev_hash   : hash of the preceding row (or "GENESIS" for the first)
    #   event_hash  : SHA-256(this row's fields + prev_hash)
    # WHY relational not append-only file: DB allows structured queries by
    # actor, study, time range; auditors can filter without parsing flat files.
    # WHY not a blockchain: A blockchain adds unnecessary complexity (consensus,
    # blocks, Merkle trees). A simple linked-hash chain is sufficient and
    # auditable by any verifier with a SHA-256 implementation.
    # WHY event_seq INTEGER: Provides a monotonically increasing sequence for
    # ordered replay verification, immune to timestamp manipulation.
    c.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        event_id        TEXT PRIMARY KEY,
        event_seq       INTEGER NOT NULL,
        timestamp       TEXT NOT NULL,
        actor_user_id   TEXT,
        role            TEXT,
        menu_item       TEXT,
        event_type      TEXT NOT NULL,
        description     TEXT NOT NULL,
        entity_type     TEXT,
        entity_id       TEXT,
        study_id        TEXT,
        prev_hash       TEXT NOT NULL,
        event_hash      TEXT NOT NULL
    )""")

    # ── System Keys Table ─────────────────────────────────────────────────
    # Stores metadata for platform-level RSA keypairs (master key, incoming
    # data key). The private key is stored as a FILE PATH (priv_enc column),
    # not the key material itself. WHY: Keeps private key material on the
    # filesystem with OS-level permissions, separate from DB-level access.
    c.execute("""
    CREATE TABLE IF NOT EXISTS system_keys (
        key_id          TEXT PRIMARY KEY,
        key_name        TEXT NOT NULL UNIQUE,
        key_type        TEXT NOT NULL,
        pub_pem         TEXT,
        priv_enc        TEXT,
        status          TEXT NOT NULL DEFAULT 'active'
                        CHECK(status IN ('active','retired','revoked')),
        created_by      TEXT,
        created_at      TEXT NOT NULL,
        updated_at      TEXT NOT NULL
    )""")

    # ── Invitations Table ─────────────────────────────────────────────────
    # Tracks admin-issued email invitations for new users. The token is a
    # URL-safe random 32-byte secret that the invitee uses to self-register.
    # WHY store token in DB not send only by email: Allows admin to list
    # pending invitations and revoke them if needed.
    c.execute("""
    CREATE TABLE IF NOT EXISTS invitations (
        invite_id       TEXT PRIMARY KEY,
        email           TEXT NOT NULL,
        role            TEXT NOT NULL,
        org_id          TEXT REFERENCES organisations(org_id),
        token           TEXT NOT NULL UNIQUE,
        status          TEXT NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending','registered','expired')),
        created_by      TEXT REFERENCES users(user_id),
        created_at      TEXT NOT NULL
    )""")

    # ── System Configuration Table ─────────────────────────────────────────
    # Key-value store for system-level configuration that persists across
    # restarts: KEK salt, passphrase hash, initialisation state.
    # WHY relational table not a JSON file: Transactional writes prevent
    # partial updates; SQL prevents concurrent write corruption.
    c.execute("""
    CREATE TABLE IF NOT EXISTS system_config (
        config_key   TEXT PRIMARY KEY,
        config_value TEXT NOT NULL,
        updated_at   TEXT NOT NULL
    )""")

    # ── Schema migrations (backward-compatible column additions) ──────────────
    # WHY try/except: SQLite has no "ADD COLUMN IF NOT EXISTS" syntax.
    # Silently ignoring OperationalError (column exists) is the standard
    # SQLite migration pattern. Data in existing rows is unaffected.
    _migrations = [
        "ALTER TABLE users ADD COLUMN mobile_number TEXT",
        "ALTER TABLE users ADD COLUMN totp_secret TEXT",
        "ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN failed_attempt_window_start TEXT",
        "ALTER TABLE users ADD COLUMN account_locked INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 0",
        "ALTER TABLE studies ADD COLUMN legal_basis_countries TEXT DEFAULT '[]'",
    ]
    for stmt in _migrations:
        try:
            c.execute(stmt)
        except Exception:
            pass  # Column already exists in this database — safe to skip

    conn.commit()
    conn.close()


def write_audit_event(actor_user_id: str, role: str, menu_item: str,
                      event_type: str, description: str,
                      entity_type: str = None, entity_id: str = None,
                      study_id: str = None):
    """
    Append a tamper-evident event to the audit log using SHA-256 hash chaining.

    WHY single-function audit writing: Centralising all audit writes ensures
    every event goes through the same hash chain linkage logic. If callers
    wrote directly to the table, they could inadvertently break the chain.

    Chain linkage algorithm:
      1. Fetch the latest event's sequence number and hash.
      2. Build the new event's payload dict (all fields that are hashed).
      3. Compute SHA-256(JSON(payload) + prev_hash).
      4. Insert the new row with computed hash.
    This means any retroactive edit to a row's fields invalidates its hash
    AND every subsequent hash — detectable by a linear replay.

    WHY not use a DB trigger for hashing: Triggers run in SQL context and
    cannot call Python hash functions; the chain must be computed in application
    code where SHA-256 is available.

    Returns the generated event_id for callers that need to reference it.
    """
    conn = get_conn()
    c    = conn.cursor()

    # Fetch last event to build chain link
    row = c.execute(
        "SELECT event_seq, event_hash FROM audit_log ORDER BY event_seq DESC LIMIT 1"
    ).fetchone()
    prev_seq  = row["event_seq"]  if row else 0
    prev_hash = row["event_hash"] if row else "GENESIS"  # sentinel for first event

    event_id = secure_random_id("EVT-")
    ts  = datetime.now(timezone.utc).isoformat()
    seq = prev_seq + 1

    # Build the payload dict that is hashed. All fields that could be tampered
    # with are included. Omitting prev_hash from this dict would allow hash-chain
    # attacks; it MUST be included.
    event_data = {
        "event_id":      event_id,
        "event_seq":     seq,
        "timestamp":     ts,
        "actor_user_id": actor_user_id,
        "role":          role,
        "menu_item":     menu_item,
        "event_type":    event_type,
        "description":   description,
        "entity_type":   entity_type,
        "entity_id":     entity_id,
        "study_id":      study_id,
        "prev_hash":     prev_hash,
    }
    event_hash = compute_event_hash(event_data, prev_hash)

    c.execute("""
        INSERT INTO audit_log
        (event_id, event_seq, timestamp, actor_user_id, role, menu_item,
         event_type, description, entity_type, entity_id, study_id, prev_hash, event_hash)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (event_id, seq, ts, actor_user_id, role, menu_item,
          event_type, description, entity_type, entity_id, study_id,
          prev_hash, event_hash))
    conn.commit()
    conn.close()
    return event_id


def get_last_audit_hash():
    """Return the most recent audit event hash, or 'GENESIS' if log is empty."""
    conn = get_conn()
    row  = conn.execute(
        "SELECT event_hash FROM audit_log ORDER BY event_seq DESC LIMIT 1"
    ).fetchone()
    conn.close()
    return row["event_hash"] if row else "GENESIS"


def get_config(key: str) -> str:
    """
    Retrieve a system configuration value by key.
    Returns None if key not found.
    WHY NOT raise on missing: Many callers check if system is initialised by
    checking for None; raising would require try/except everywhere.
    """
    conn = get_conn()
    row  = conn.execute(
        "SELECT config_value FROM system_config WHERE config_key=?", (key,)
    ).fetchone()
    conn.close()
    return row["config_value"] if row else None


def set_config(key: str, value: str) -> None:
    """
    Upsert a system configuration value.
    WHY INSERT OR REPLACE: Idempotent — safe to call multiple times with
    same key. Does not require checking existence first.
    """
    conn = get_conn()
    now  = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT OR REPLACE INTO system_config (config_key, config_value, updated_at) "
        "VALUES (?,?,?)",
        (key, value, now)
    )
    conn.commit()
    conn.close()
