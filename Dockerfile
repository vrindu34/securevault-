FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/   ./backend/
COPY frontend/  ./frontend/
COPY vault/     ./vault/

# Create vault subdirectories
RUN mkdir -p vault/files vault/inbox vault/decrypted vault/private_keys

EXPOSE 8000

CMD uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8000}
