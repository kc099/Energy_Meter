# syntax=docker/dockerfile:1.6

# --- Base image -------------------------------------------------------------
FROM python:3.11-slim AS base

ARG DJANGO_SECRET_KEY_BUILD="build-secret-placeholder"
ARG DEVICE_DATA_ENCRYPTION_KEY_BUILD="build-device-key-placeholder"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    DJANGO_SECRET_KEY="$DJANGO_SECRET_KEY_BUILD" \
    DEVICE_DATA_ENCRYPTION_KEY="$DEVICE_DATA_ENCRYPTION_KEY_BUILD"

WORKDIR /app

# System dependencies for building Python packages (mysqlclient, Pillow, etc.)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        default-libmysqlclient-dev \
        libpq-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# --- Python dependencies ----------------------------------------------------
FROM base AS deps

RUN python -m venv /opt/venv

# Copy requirement manifests (add requirements.txt before building)
COPY requirements.txt ./

RUN pip install --upgrade pip setuptools wheel \
    && pip install -r requirements.txt

# --- Runtime image ----------------------------------------------------------
FROM base AS runtime

COPY --from=deps /opt/venv /opt/venv

# Copy project code
COPY . .

# Collect static assets (expects DJANGO_SETTINGS_MODULE + DB config if needed)
RUN python manage.py collectstatic --no-input

EXPOSE 8000

# Gunicorn is expected to be listed in requirements.txt
CMD ["gunicorn", "EM_main.wsgi:application", "--bind", "0.0.0.0:8000"]
