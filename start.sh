#!/bin/bash
# PSIRT Security Analysis Agent - Startup Script

set -e

echo "=========================================="
echo "  PSIRT Security Analysis Agent"
echo "=========================================="
echo ""

# Check for Docker
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed or not in PATH"
    echo "Please install Docker Desktop and enable WSL integration"
    echo "https://docs.docker.com/desktop/wsl/"
    exit 1
fi

# Check for docker-compose or docker compose
if command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
elif docker compose version &> /dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
else
    echo "ERROR: Docker Compose is not available"
    exit 1
fi

echo "Using: $COMPOSE_CMD"
echo ""

# Start services
echo "Starting services..."
$COMPOSE_CMD up -d

echo ""
echo "=========================================="
echo "  Services Started!"
echo "=========================================="
echo ""
echo "  Interfaces:"
echo "    - Admin UI:       http://localhost:8000/admin"
echo "    - User Q&A:       http://localhost:8000/user"
echo "    - Full Dashboard: http://localhost:8000/"
echo "    - API Docs:       http://localhost:8000/docs"
echo ""
echo "  First Steps:"
echo "    1. Go to Admin UI and configure your API keys"
echo "    2. Upload your device inventory (Excel file)"
echo "    3. Run analysis to fetch PSIRT advisories"
echo "    4. Ask questions in the User Q&A interface"
echo ""
echo "  To stop: $COMPOSE_CMD down"
echo "  To view logs: $COMPOSE_CMD logs -f"
echo ""
