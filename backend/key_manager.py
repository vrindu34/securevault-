"""
key_manager.py
==============
Handles RSA key-pair lifecycle:
  • Generating and storing key pairs
  • Persisting public keys in a local SQLite PKI database
  • Saving / loading private keys from protected local files
  • Resolving a username → public key for encryption
"""

import os
import stat
import sqlite3
from pathlib import Path
from crypto_engine import CryptoEngine


# ---------------------------------------------------------------------------
# Paths  (relative to wherever the script is launched from)
# ---------------------------------------------------------------------------
DB_PATH      = Path("vault/pki.db")          # SQLite PKI store
PRIVKEY_DIR  = Path("vault/private_keys")    # Directory for private key files


# ---------------------------------------------------------------------------
# DatabaseManager  –  thin wrapper around SQLite
# ---------------------------------------------------------------------------
class DatabaseManager:
    """
    Manages the local Public Key Infrastructure (PKI) database.

    Schema
    ------
    users(id INTEGER PK, username TEXT UNIQUE, public_key_pem TEXT, created_at TIMESTAMP)

    This is intentionally minimal.  In a real system you would add:
      • Certificate expiry / revocation
      • Key fingerprints for out-of-band verification
      • Audit log of key registrations
    """

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row   # allows dict-style column access
        return conn

    def _init_schema(self):
        """Create tables if they don't already exist (idempotent)."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    username        TEXT    NOT NULL UNIQUE,
                    public_key_pem  TEXT    NOT NULL,
                    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    # ------------------------------------------------------------------ #
    #  Public-key CRUD                                                     #
    # ------------------------------------------------------------------ #

    def store_public_key(self, username: str, public_key_pem: bytes) -> None:
        """
        Insert or replace a user's public key.
        Using INSERT OR REPLACE allows key rotation without changing the API.
        """
        with self._get_connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO users (username, public_key_pem) VALUES (?, ?)",
                (username, public_key_pem.decode("utf-8"))
            )
            conn.commit()

    def get_public_key(self, username: str) -> bytes | None:
        """
        Retrieve a user's public key PEM.
        Returns None if the user is not registered.
        """
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT public_key_pem FROM users WHERE username = ?",
                (username,)
            ).fetchone()
        return row["public_key_pem"].encode("utf-8") if row else None

    def list_users(self) -> list[str]:
        """Return all registered usernames (for recipient selection UI)."""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT username FROM users ORDER BY username").fetchall()
        return [r["username"] for r in rows]


# ---------------------------------------------------------------------------
# KeyManager  –  key lifecycle orchestrator
# ---------------------------------------------------------------------------
class KeyManager:
    """
    High-level interface for RSA key management.

    Responsibilities
    ----------------
    1. generate_and_register() : create a new key pair, persist both halves.
    2. load_private_key()      : read a protected private key from disk.
    3. get_public_key()        : look up a recipient's public key from the DB.

    Private Key Protection
    ----------------------
    Private keys are stored as plain PEM files in PRIVKEY_DIR.
    After writing, the file permissions are set to 0o600 (owner read/write only)
    so no other OS user can read the key without explicit permission escalation.

    For a production system you would additionally:
      • Encrypt the PEM with a user-supplied passphrase (AES-256-GCM + scrypt KDF)
      • Consider hardware key storage (TPM, HSM, or OS keychain)
    """

    def __init__(self):
        self.db      = DatabaseManager()
        self.key_dir = PRIVKEY_DIR
        self.key_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    #  Key Generation                                                      #
    # ------------------------------------------------------------------ #

    def generate_and_register(self, username: str) -> Path:
        """
        Generate a fresh RSA-2048 key pair for `username`.

        Steps
        -----
        1. Call CryptoEngine to generate (private_pem, public_pem).
        2. Store public_pem in the SQLite PKI database.
        3. Write private_pem to <PRIVKEY_DIR>/<username>_private.pem
           with permissions 0o600.

        Returns the Path of the saved private key file.

        Raises FileExistsError if a private key already exists for this user
        (prevents accidental overwrite — the caller should explicitly delete
        the old key first if rotation is intended).
        """
        priv_path = self._private_key_path(username)
        if priv_path.exists():
            raise FileExistsError(
                f"Private key already exists for '{username}': {priv_path}\n"
                "Delete the file manually to rotate keys."
            )

        private_pem, public_pem = CryptoEngine.generate_rsa_keypair()

        # Persist public key to PKI database
        self.db.store_public_key(username, public_pem)

        # Write private key to disk with restricted permissions
        priv_path.write_bytes(private_pem)
        os.chmod(priv_path, stat.S_IRUSR | stat.S_IWUSR)   # 0o600

        print(f"[KeyManager] Keys generated for '{username}'.")
        print(f"  Public key  → SQLite DB ({self.db.db_path})")
        print(f"  Private key → {priv_path}  (permissions: 600)")
        return priv_path

    # ------------------------------------------------------------------ #
    #  Key Retrieval                                                       #
    # ------------------------------------------------------------------ #

    def load_private_key(self, username: str) -> bytes:
        """
        Load a user's private key PEM from disk.

        Raises FileNotFoundError if the key file does not exist.
        """
        priv_path = self._private_key_path(username)
        if not priv_path.exists():
            raise FileNotFoundError(
                f"No private key found for '{username}'. "
                "Generate keys first with generate_and_register()."
            )
        return priv_path.read_bytes()

    def get_public_key(self, username: str) -> bytes:
        """
        Fetch a user's public key from the PKI database.

        Raises LookupError if the user is not registered.
        """
        pub_pem = self.db.get_public_key(username)
        if pub_pem is None:
            raise LookupError(
                f"No public key registered for '{username}'. "
                "They must generate and register their keys first."
            )
        return pub_pem

    def list_registered_users(self) -> list[str]:
        """Return all users with registered public keys."""
        return self.db.list_users()

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _private_key_path(self, username: str) -> Path:
        # Sanitise username to prevent path-traversal attacks
        safe = "".join(c for c in username if c.isalnum() or c in ("_", "-"))
        return self.key_dir / f"{safe}_private.pem"
