#!/bin/bash
set -e

# Ensure the database file exists to avoid Docker creating it as a directory
touch /app/domyntrix.db

echo "Running database migrations..."
uv run alembic upgrade head

echo "Starting FastAPI server..."
exec uv run uvicorn main:app --host 0.0.0.0 --port 5000
