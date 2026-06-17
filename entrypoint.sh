#!/bin/bash
set -e

# ════════════════════════════════════════════════════════════════
# Parse DATABASE_URL if provided (Railway, Heroku, etc.)
# Otherwise fall back to DB_HOST/DB_PORT (local Docker)
# ════════════════════════════════════════════════════════════════

if [ -n "$DATABASE_URL" ]; then
    echo "🔗 Using DATABASE_URL (production mode)"
    # Extract host and port from DATABASE_URL
    # Format: postgresql://user:password@host:port/dbname
    DB_HOST=$(echo "$DATABASE_URL" | sed -n 's|.*@\([^:]*\):.*|\1|p')
    DB_PORT=$(echo "$DATABASE_URL" | sed -n 's|.*:\([0-9]*\)/.*|\1|p')
    echo "   Parsed host: $DB_HOST"
    echo "   Parsed port: $DB_PORT"
else
    echo "🔗 Using DB_HOST/DB_PORT (local mode)"
    DB_HOST="${DB_HOST:-db}"
    DB_PORT="${DB_PORT:-5432}"
fi

# ════════════════════════════════════════════════════════════════
# Wait for PostgreSQL (max 60 seconds)
# ════════════════════════════════════════════════════════════════

echo "⏳ Waiting for PostgreSQL at $DB_HOST:$DB_PORT..."
RETRIES=60
while ! nc -z "$DB_HOST" "$DB_PORT" 2>/dev/null; do
    RETRIES=$((RETRIES - 1))
    if [ $RETRIES -le 0 ]; then
        echo "❌ PostgreSQL did not become available in 60s"
        exit 1
    fi
    sleep 1
done
echo "✅ PostgreSQL is up!"

# ════════════════════════════════════════════════════════════════
# Django setup
# ════════════════════════════════════════════════════════════════

echo "🔄 Running migrations..."
python manage.py migrate --noinput

echo "📦 Collecting static files..."
python manage.py collectstatic --noinput --clear

# ════════════════════════════════════════════════════════════════
# Start Gunicorn — bind to $PORT (Railway) or 8000 (local)
# ════════════════════════════════════════════════════════════════

PORT="${PORT:-8000}"
echo "🚀 Starting Gunicorn on port $PORT..."

exec gunicorn config.wsgi:application \
    --bind "0.0.0.0:$PORT" \
    --workers 2 \
    --timeout 120 \
    --access-logfile - \
    --error-logfile -
