FROM python:3.11-slim

# Install system dependencies (including Tesseract OCR)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tesseract-ocr \
        libtesseract-dev \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Environment variables commonly set on Render; override in dashboard as needed
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# By default, Tesseract is available on PATH as "tesseract".
# Your Config._default_tesseract_cmd() already handles the case where TESSERACT_CMD is unset.

# Default command: Celery worker
# On Render, you can override this in the Background Worker "Start Command" field.
CMD ["celery", "-A", "celery_worker.celery", "worker", "--loglevel=info"]


