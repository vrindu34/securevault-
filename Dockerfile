FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/   ./backend/
COPY frontend/  ./frontend/

RUN mkdir -p vault/files vault/inbox vault/decrypted vault/private_keys

EXPOSE 8000

CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port $PORT"]
