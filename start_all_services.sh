#!/bin/bash

# Energy Meter System - Auto PyMySQL Fix
echo "🚀 Starting Energy Meter System..."

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
celery -A EM_main beat --loglevel=ERROR > /dev/null 2>&1 &
celery -A EM_main worker --loglevel=ERROR --concurrency=1 > /dev/null 2>&1 &
sleep 2

echo "✅ Background services started!"
echo "🌐 Starting Django server at http://localhost:8000"
echo "Press Ctrl+C to stop all services"
echo "=========================================="

# Start Django
python manage.py runserver 0.0.0.0:8000

cleanup