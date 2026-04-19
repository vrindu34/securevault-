# SecureVault v3 — Web Deployment Guide

A fully deployed, browser-based encrypted file transfer system built on your
original v2 crypto engine.

## Architecture

```
securevault/
├── backend/
│   ├── main.py           # FastAPI server — REST + WebSocket
│   ├── crypto_engine.py  # AES-256-CBC, RSA-PSS, RSA-OAEP (unchanged from v2)
│   ├── key_manager.py    # RSA key lifecycle + SQLite PKI (unchanged from v2)
│   └── vault_io.py       # .vault format + encrypt/decrypt (unchanged from v2)
├── frontend/
│   └── index.html        # Single-page app — seamless UI
├── vault/                # Runtime data (created automatically)
│   ├── files/            # Encrypted vault bundles
│   ├── inbox/            # Per-user received files
│   ├── decrypted/        # Decrypted downloads
│   └── private_keys/     # RSA private key PEM files (chmod 600)
├── requirements.txt
├── Dockerfile
└── Procfile
```

## What Changed from v2 (Local TCP → Web)

| Component        | v2 Local                    | v3 Web                            |
|------------------|-----------------------------|-----------------------------------|
| Transport        | Raw TCP sockets             | HTTP/WebSocket (FastAPI)          |
| GUI              | Tkinter desktop app         | Browser SPA (no install needed)   |
| Key exchange     | Manual copy folder to B     | Automatic via PKI API             |
| Real-time notify | Not available               | WebSocket push to recipient       |
| File delivery    | LAN only                    | Any network, any device           |
| crypto_engine    | Unchanged ✅                 | Unchanged ✅                       |
| vault_io         | Unchanged ✅                 | Unchanged ✅                       |
| key_manager      | Unchanged ✅                 | Unchanged ✅                       |

---

## Local Development

```bash
pip install -r requirements.txt
cd backend
uvicorn main:app --reload --port 8000
```
Open: http://localhost:8000

---

## Deploy on Railway (recommended — free tier)

1. Push this folder to a GitHub repo
2. Go to https://railway.app → New Project → Deploy from GitHub
3. Railway auto-detects the Procfile
4. Set environment variable: `PORT=8000` (Railway sets this automatically)
5. Done — you get a public HTTPS URL

---

## Deploy on Render

1. Push to GitHub
2. New Web Service → connect repo
3. Build command: `pip install -r requirements.txt`
4. Start command: `cd backend && uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Free tier gives you a public URL

---

## Deploy with Docker

```bash
docker build -t securevault .
docker run -p 8000:8000 -v $(pwd)/vault:/app/vault securevault
```

Mount the vault directory as a volume so data persists across container restarts.

---

## Important: Persistent Storage

The `vault/` directory stores keys, encrypted files, and the PKI SQLite DB.

**For production deployment:**
- Use a persistent volume/disk (Railway Volumes, Render Disks, Docker volumes)
- Without persistence, user keys are lost on restart and users must re-register

**For Railway:** Add a volume mounted at `/app/vault`  
**For Render:** Add a persistent disk mounted at `/app/vault`

---

## API Reference

| Method | Endpoint                         | Description                    |
|--------|----------------------------------|--------------------------------|
| GET    | `/api/users`                     | List all registered users      |
| POST   | `/api/users/register`            | Register new user + gen keys   |
| GET    | `/api/users/{username}/exists`   | Check if user exists           |
| POST   | `/api/send`                      | Encrypt & send file            |
| GET    | `/api/inbox/{username}`          | List received files            |
| POST   | `/api/decrypt`                   | Decrypt a vault file           |
| GET    | `/api/download/{user}/{file}`    | Download decrypted file        |
| WS     | `/ws/{username}`                 | Real-time inbox notifications  |

---

## Security Notes

- Private keys are stored server-side (chmod 600 PEM files)
- For higher security, add passphrase encryption to private keys
- For multi-user production, consider per-user namespaced vault directories
- Add authentication (JWT/session tokens) if deploying publicly
- HTTPS is provided automatically by Railway/Render
