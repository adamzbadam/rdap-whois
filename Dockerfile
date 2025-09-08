FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
# Render udostępnia PORT; fallback na 8080 lokalnie
CMD ["/bin/sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8080}"]
