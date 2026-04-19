"""
main.py — SecureVault Web API v3.1
Added: password authentication (bcrypt), session tokens, protected endpoints.
"""

import os
import sys
import json
import shutil
import secrets
import logging
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional

import bcrypt
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn
import sqlite3

# ── Paths ──────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent.parent
VAULT_DIR   = BASE_DIR / "vault"
FILES_DIR   = VAULT_DIR / "files"
INBOX_DIR   = VAULT_DIR / "inbox"
DECRYPT_DIR = VAULT_DIR / "decrypted"
PRIVKEY_DIR = VAULT_DIR / "private_keys"
DB_PATH     = VAULT_DIR / "pki.db"
AUTH_DB     = VAULT_DIR / "auth.db"

for d in [FILES_DIR, INBOX_DIR, DECRYPT_DIR, PRIVKEY_DIR]:
    d.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(Path(__file__).parent))

import key_manager as km_module
km_module.DB_PATH     = DB_PATH
km_module.PRIVKEY_DIR = PRIVKEY_DIR

import vault_io as vi_module
vi_module.VAULT_DIR = FILES_DIR

from key_manager import KeyManager, DatabaseManager
from vault_io    import VaultManager
from crypto_engine import CryptoEngine

# ── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("securevault")

# ── Auth DB ────────────────────────────────────────────────────────────────
def get_auth_conn():
    conn = sqlite3.connect(AUTH_DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_auth_db():
    with get_auth_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                username      TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                created_at    TEXT DEFAULT (datetime('now'))
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token      TEXT PRIMARY KEY,
                username   TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
        """)
        conn.commit()

init_auth_db()

# ── Session helpers ────────────────────────────────────────────────────────
SESSION_TTL_HOURS = 24

def create_session(username: str) -> str:
    token   = secrets.token_urlsafe(32)
    expires = (datetime.utcnow() + timedelta(hours=SESSION_TTL_HOURS)).isoformat()
    with get_auth_conn() as conn:
        conn.execute(
            "INSERT INTO sessions (token, username, expires_at) VALUES (?, ?, ?)",
            (token, username, expires)
        )
        conn.commit()
    return token

def validate_session(token: str) -> Optional[str]:
    with get_auth_conn() as conn:
        row = conn.execute(
            "SELECT username, expires_at FROM sessions WHERE token = ?", (token,)
        ).fetchone()
    if not row:
        return None
    if datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
        with get_auth_conn() as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
        return None
    return row["username"]

def delete_session(token: str):
    with get_auth_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()

# ── Auth dependency ────────────────────────────────────────────────────────
bearer = HTTPBearer(auto_error=False)

def require_auth(credentials: HTTPAuthorizationCredentials = Depends(bearer)) -> str:
    if not credentials:
        raise HTTPException(401, "Not authenticated — please log in")
    username = validate_session(credentials.credentials)
    if not username:
        raise HTTPException(401, "Session expired or invalid — please log in again")
    return username

# ── App ────────────────────────────────────────────────────────────────────
app = FastAPI(title="SecureVault API", version="3.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── WebSocket manager ──────────────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: dict[str, list[WebSocket]] = {}

    async def connect(self, username: str, ws: WebSocket):
        await ws.accept()
        self.active.setdefault(username, []).append(ws)

    def disconnect(self, username: str, ws: WebSocket):
        if username in self.active:
            try: self.active[username].remove(ws)
            except ValueError: pass

    async def notify(self, username: str, payload: dict):
        for ws in list(self.active.get(username, [])):
            try: await ws.send_json(payload)
            except Exception: pass

ws_manager = ConnectionManager()

# ── Key manager helpers ────────────────────────────────────────────────────
def get_key_manager() -> KeyManager:
    km = KeyManager.__new__(KeyManager)
    km.db      = DatabaseManager(DB_PATH)
    km.key_dir = PRIVKEY_DIR
    km.key_dir.mkdir(parents=True, exist_ok=True)
    return km

def get_vault_manager() -> VaultManager:
    vm = VaultManager.__new__(VaultManager)
    vm.vault_dir   = FILES_DIR
    vm.key_manager = get_key_manager()
    return vm

# ═══════════════════════════════════════════════════════════════════════════
# AUTH ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════

@app.post("/api/auth/register")
def auth_register(username: str = Form(...), password: str = Form(...)):
    safe = "".join(c for c in username if c.isalnum() or c in ("_", "-"))
    if len(safe) < 3:
        raise HTTPException(400, "Username must be at least 3 characters (letters, numbers, _ or -)")
    if len(password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")

    with get_auth_conn() as conn:
        existing = conn.execute(
            "SELECT username FROM accounts WHERE username = ?", (safe,)
        ).fetchone()
    if existing:
        raise HTTPException(409, f"Username '{safe}' is already taken — choose another")

    # Hash password with bcrypt (cost factor 12)
    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(12)).decode()

    with get_auth_conn() as conn:
        conn.execute(
            "INSERT INTO accounts (username, password_hash) VALUES (?, ?)",
            (safe, pw_hash)
        )
        conn.commit()

    # Generate RSA-2048 key pair for this user
    km = get_key_manager()
    try:
        km.generate_and_register(safe)
    except FileExistsError:
        pass  # Keys already exist from a previous attempt

    token = create_session(safe)
    log.info(f"Registered new user: {safe}")
    return {"username": safe, "token": token, "status": "registered"}


@app.post("/api/auth/login")
def auth_login(username: str = Form(...), password: str = Form(...)):
    safe = "".join(c for c in username if c.isalnum() or c in ("_", "-"))

    with get_auth_conn() as conn:
        row = conn.execute(
            "SELECT password_hash FROM accounts WHERE username = ?", (safe,)
        ).fetchone()

    # Deliberately vague error — don't reveal whether username exists
    if not row or not bcrypt.checkpw(password.encode("utf-8"), row["password_hash"].encode()):
        raise HTTPException(401, "Invalid username or password")

    token = create_session(safe)
    log.info(f"Login: {safe}")
    return {"username": safe, "token": token}


@app.post("/api/auth/logout")
def auth_logout(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    if credentials:
        delete_session(credentials.credentials)
    return {"status": "logged out"}


@app.get("/api/auth/me")
def auth_me(username: str = Depends(require_auth)):
    return {"username": username}


# ═══════════════════════════════════════════════════════════════════════════
# PROTECTED ENDPOINTS  (all require valid session token)
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/api/users")
def list_users(username: str = Depends(require_auth)):
    km = get_key_manager()
    return {"users": km.list_registered_users()}


@app.post("/api/send")
async def send_file(
    file:      UploadFile = File(...),
    recipient: str = Form(...),
    username:  str = Depends(require_auth),
):
    sender = username
    km = get_key_manager()

    if not (PRIVKEY_DIR / f"{sender}_private.pem").exists():
        raise HTTPException(400, "No private key found for your account — try re-registering")
    if not km.db.get_public_key(recipient):
        raise HTTPException(400, f"Recipient '{recipient}' is not registered")
    if recipient == sender:
        raise HTTPException(400, "Cannot send a file to yourself")

    with tempfile.NamedTemporaryFile(delete=False, suffix=Path(file.filename).suffix) as tmp:
        tmp.write(await file.read())
        tmp_path = Path(tmp.name)

    try:
        vm = get_vault_manager()
        vault_path = vm.encrypt_file(tmp_path, sender, recipient, output_name=file.filename)
    finally:
        tmp_path.unlink(missing_ok=True)

    ts         = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    inbox_name = f"{ts}_{sender}__{file.filename}.vault"
    inbox_path = INBOX_DIR / recipient / inbox_name
    inbox_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(vault_path, inbox_path)

    await ws_manager.notify(recipient, {
        "event":     "new_file",
        "sender":    sender,
        "filename":  file.filename,
        "vault_id":  inbox_name,
        "timestamp": ts,
    })

    log.info(f"Sent '{file.filename}': {sender} → {recipient}")
    return {
        "status":    "delivered",
        "vault_id":  inbox_name,
        "sender":    sender,
        "recipient": recipient,
        "filename":  file.filename,
    }

@app.get("/api/vault-info/{vault_id:path}")
def get_vault_info(vault_id: str, username: str = Depends(require_auth)):
    import hashlib
    vault_path = INBOX_DIR / username / vault_id
    if not vault_path.exists():
        raise HTTPException(404, "Vault file not found")
    from vault_io import FileIO
    bundle = FileIO.read_vault(vault_path)
    return {
        "vault_id":         vault_id,
        "file_size":        vault_path.stat().st_size,
        "ciphertext_size":  len(bundle.ciphertext),
        "wrapped_key_size": len(bundle.wrapped_key),
        "signature_size":   len(bundle.signature),
        "iv_hex":           bundle.iv.hex(),
        "ciphertext_preview": bundle.ciphertext[:64].hex(),
        "wrapped_key_preview": bundle.wrapped_key[:32].hex(),
    }
@app.get("/api/inbox")
def get_inbox(username: str = Depends(require_auth)):
    inbox = INBOX_DIR / username
    if not inbox.exists():
        return {"files": []}

    files = []
    for vault_path in sorted(inbox.glob("*.vault"), reverse=True):
        stem  = vault_path.stem
        parts = stem.split("__", 1)
        if len(parts) == 2:
            prefix, original = parts
            ts_sender = prefix.rsplit("_", 2)
            sender = ts_sender[-1] if len(ts_sender) >= 2 else "unknown"
            ts     = "_".join(ts_sender[:-1]) if len(ts_sender) >= 2 else prefix
        else:
            sender, original, ts = "unknown", stem, ""

        files.append({
            "vault_id":  vault_path.name,
            "filename":  original,
            "sender":    sender,
            "timestamp": ts,
            "size":      vault_path.stat().st_size,
        })
    return {"files": files}


@app.post("/api/decrypt")
async def decrypt_file(
    vault_id: str = Form(...),
    sender:   str = Form(...),
    username: str = Depends(require_auth),
):
    vault_path = INBOX_DIR / username / vault_id
    if not vault_path.exists():
        raise HTTPException(404, "Vault file not found in your inbox")

    if not (PRIVKEY_DIR / f"{username}_private.pem").exists():
        raise HTTPException(400, "No private key found for your account")

    km = get_key_manager()
    if not km.db.get_public_key(sender):
        raise HTTPException(400, f"Sender '{sender}' is not registered — cannot verify signature")

    out_name = vault_path.stem.split("__", 1)[-1] if "__" in vault_path.stem else vault_path.stem
    out_path = DECRYPT_DIR / username / out_name
    out_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        vm = get_vault_manager()
        vm.decrypt_file(vault_path, username, sender, output_path=out_path)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        log.error(f"Decrypt error: {e}", exc_info=True)
        raise HTTPException(500, str(e))

    log.info(f"Decrypted '{out_name}' for '{username}'")
    return {"status": "decrypted", "filename": out_name, "download_id": out_name}


@app.get("/api/download/{filename:path}")
def download_file(filename: str, username: str = Depends(require_auth)):
    # Users can only download their own decrypted files
    file_path = DECRYPT_DIR / username / filename
    if not file_path.exists():
        raise HTTPException(404, "File not found")
    return FileResponse(file_path, filename=Path(filename).name)


# ── WebSocket — token passed as path param ─────────────────────────────────

@app.websocket("/ws/{token}")
async def websocket_endpoint(ws: WebSocket, token: str):
    username = validate_session(token)
    if not username:
        await ws.close(code=4001)
        return
    await ws_manager.connect(username, ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(username, ws)


# ── Serve frontend ─────────────────────────────────────────────────────────

frontend_dir = BASE_DIR / "frontend"
if frontend_dir.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
