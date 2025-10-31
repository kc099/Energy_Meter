# Energy Meter Platform

This repository hosts a Django-based energy monitoring and alerting platform. It includes a REST API for devices, Celery workers for scheduled tasks and reporting, and a React dashboard for operators.

## Project layout
- `EM_main/` – Django project configuration, Celery app setup, global settings.
- `accounts/`, `devices/`, `api/`, `andon/`, `gas_monitor/`, `device_gateway/` – domain apps that expose the core functionality.
- `frontend/` – Vite + React SPA for dashboards and device management.
- `start_all_services.sh` – helper script that boots Redis, Celery beat/worker, and the Django development server.
- `Dockerfile` – production-friendly container image that serves the Django app with Gunicorn.

## Prerequisites
- Python 3.11 (recommended) with `pip`
- Node.js 18+ (for the Vite frontend)
- MySQL 8.0 (or compatible) with credentials to create/manage the `energymeter` database
- Redis 7 (used as the Celery broker and result backend)
- Optional: Docker if you prefer containerized builds

## Backend setup
1. **Create a virtual environment**
   ```bash
   cd EM
   python -m venv .venv
   source .venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt
   ```
2. **Prepare the database** – create a MySQL database and user (customise names/passwords as needed):
   ```sql
   CREATE DATABASE energymeter CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   CREATE USER 'energymeter_user'@'%' IDENTIFIED BY 'strong-password';
   GRANT ALL PRIVILEGES ON energymeter.* TO 'energymeter_user'@'%';
   FLUSH PRIVILEGES;
   ```
3. **Configure environment variables** – create a `.env` file in the project root (or keep a private `.env.example` template) and populate it with values similar to the snippet below (never commit real secrets):
   ```dotenv
   # Django
   DJANGO_SECRET_KEY=<django-secret-key>
   DEVICE_DATA_ENCRYPTION_KEY=<32-byte-url-safe-key or leave blank to derive from secret>

   # Database
   MYSQL_DATABASE=energymeter
   MYSQL_USER=energymeter_user
   MYSQL_PASSWORD=<mysql-password>
   MYSQL_HOST=127.0.0.1
   MYSQL_PORT=3306

   # Redis / Celery
   CELERY_BROKER_URL=redis://localhost:6379/0
   CELERY_RESULT_BACKEND=redis://localhost:6379/0
   DEVICE_POLL_BEAT_INTERVAL=2

   # Email (required for automated report delivery)
   EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
   EMAIL_HOST=smtp.gmail.com
   EMAIL_PORT=587
   EMAIL_USE_TLS=True
   EMAIL_HOST_USER=<email-username>
   EMAIL_HOST_PASSWORD=<email-app-password>
   DEFAULT_FROM_EMAIL=<from-address>

   # API clients allowed to reach the REST layer
   API_ALLOWED_ORIGINS=http://localhost:5173
   ```
   Generate secure keys with e.g.:
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(50))"
   ```
4. **Apply database migrations and create an admin user**
   ```bash
   python manage.py migrate
   python manage.py createsuperuser
   ```

## Running the backend
- **Recommended:** use the helper script (requires `redis-server` in your PATH):
  ```bash
  ./start_all_services.sh
  ```
  This script loads `.env`, ensures PyMySQL is initialised, daemonises Redis, starts Celery beat + worker, and serves Django on `http://127.0.0.1:8000`.
- **Manual start (if you prefer individual terminals):**
  ```bash
  # Terminal 1
  redis-server

  # Terminal 2
  source .venv/bin/activate
  celery -A EM_main beat --loglevel=INFO

  # Terminal 3
  source .venv/bin/activate
  celery -A EM_main worker --loglevel=INFO --concurrency=1

  # Terminal 4
  source .venv/bin/activate
  python manage.py runserver 0.0.0.0:8000
  ```

## Frontend setup (optional dashboard)
```bash
cd frontend
npm install
npm run dev  # served on http://localhost:5173
```
Adjust `API_ALLOWED_ORIGINS` in your `.env` if you expose the dashboard from a different host/port.

## Running tests
```bash
source .venv/bin/activate
python manage.py test
```

## Docker usage
Build and run the backend using the provided Dockerfile (environment variables still need to be supplied at runtime):
```bash
docker build -t energy-meter-backend .
docker run --env-file .env -p 8000:8000 energy-meter-backend
```
Mount a volume for `/staticfiles` or run `collectstatic` during image build if you customise the Dockerfile.

## Troubleshooting
- **`DJANGO_SECRET_KEY is not set`** – ensure your `.env` exists and the variable name matches.
- **`mysqlclient`/PyMySQL errors** – confirm MySQL is reachable and credentials match; the helper script auto-injects `pymysql.install_as_MySQLdb()` if missing.
- **`redis-server: command not found`** – install Redis locally or run `docker run -p 6379:6379 redis:7`.
- **CORS failures from the frontend** – update `API_ALLOWED_ORIGINS` and restart the backend.

With these steps, anyone cloning the repository should be able to configure the environment and launch the energy meter server successfully.
