#!/bin/bash

# Energy Meter System - Auto PyMySQL Fix
echo "🚀 Starting Energy Meter System..."

# Load environment variables
if [ -f ".env" ]; then
    echo "📦 Loading environment from .env"
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
else
    echo "⚠️  .env file not found. Ensure required environment variables are exported."
fi

if [ -z "${DJANGO_SECRET_KEY}" ]; then
    echo "❌ DJANGO_SECRET_KEY is not set. Aborting startup."
    exit 1
fi

# Determine Python executable
PYTHON_BIN=${PYTHON_BIN:-python}
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "❌ Unable to locate python executable ('$PYTHON_BIN'). Set PYTHON_BIN to your interpreter."
    exit 1
fi

# Determine Celery invocation
if "$PYTHON_BIN" - <<'PY' >/dev/null 2>&1
import importlib.util
exit(0 if importlib.util.find_spec('celery') else 1)
PY
then
    CELERY_CMD=("$PYTHON_BIN" -m celery)
elif command -v celery >/dev/null 2>&1; then
    CELERY_CMD=(celery)
else
    echo "❌ Celery is not installed for '$PYTHON_BIN' and no global 'celery' command was found."
    echo "   Install Celery in your environment (pip install celery) or set PYTHON_BIN to the correct interpreter."
    exit 1
fi

# Apply PyMySQL fix
echo "🔧 Configuring PyMySQL..."
if [ ! -f "EM_main/__init__.py" ]; then
    echo "import pymysql" > EM_main/__init__.py
    echo "pymysql.install_as_MySQLdb()" >> EM_main/__init__.py
    echo "✅ Created PyMySQL configuration"
else
    if ! grep -q "pymysql.install_as_MySQLdb" EM_main/__init__.py; then
        echo "import pymysql" >> EM_main/__init__.py
        echo "pymysql.install_as_MySQLdb()" >> EM_main/__init__.py
        echo "✅ Added PyMySQL configuration"
    else
        echo "✅ PyMySQL already configured"
    fi
fi

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Stopping services..."
    pkill -f "celery" > /dev/null 2>&1
    pkill -f "redis-server" > /dev/null 2>&1
    pkill -f "python manage.py" > /dev/null 2>&1
    sleep 1
    echo "✅ All services stopped."
    exit 0
}

trap cleanup SIGINT

# Start services
echo "🔧 Starting Redis..."
redis-server --daemonize yes > /dev/null 2>&1
sleep 2

echo "📊 Starting Celery services..."
"${CELERY_CMD[@]}" -A EM_main beat --loglevel=INFO &
"${CELERY_CMD[@]}" -A EM_main worker --loglevel=INFO --concurrency=1 &
sleep 2

echo "✅ Background services started!"
echo "🌐 Starting Django server at http://localhost:8000"
echo "Press Ctrl+C to stop all services"
echo "=========================================="

# Start Django
"$PYTHON_BIN" manage.py runserver 0.0.0.0:8000

cleanup
