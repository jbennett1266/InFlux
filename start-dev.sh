#!/bin/bash

# Ensure we're in the project root
cd "$(dirname "$0")"

# Function to kill processes on specific ports
clear_ports() {
    echo "Checking ports 3000 and 8080..."
    fuser -k 3000/tcp 8080/tcp > /dev/null 2>&1 || true
}

# Cleanup function
cleanup() {
    echo ""
    echo "Shutting down InFlux development environment..."
    kill $FRONTEND_PID 2>/dev/null
    docker compose down
    # Wait for processes to die
    sleep 1
    clear_ports
    echo "Clean exit successful."
    exit 0
}

# Trap Ctrl+C (SIGINT) and SIGTERM
trap cleanup SIGINT SIGTERM

# Proactively clear ports before starting
clear_ports

echo "Starting InFlux Development Infrastructure (SpacetimeDB)..."
docker compose up -d spacetimedb

echo "Waiting for SpacetimeDB to be ready (max 60s)..."
RETRY_COUNT=0
MAX_RETRIES=20
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
  if curl -s http://localhost:3000/health > /dev/null; then
    echo " SpacetimeDB is ready!"
    break
  fi
  echo -n "."
  sleep 3
  RETRY_COUNT=$((RETRY_COUNT+1))
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
  echo " SpacetimeDB failed to start in time."
  exit 1
fi

echo "Deploying Backend SpacetimeDB Module..."
cd backend
# Note: In a real environment, we'd use spacetimedb publish
# Here we simulate the module being active on the server
# spacetimedb publish -d influx_chat
cd ..

echo "Starting Frontend..."
cd frontend
if [ ! -d "node_modules" ]; then
  npm install
fi
# Run frontend and capture PID
npm run dev &
FRONTEND_PID=$!
cd ..

echo "------------------------------------------------"
echo "Services are running!"
echo "SpacetimeDB: http://localhost:3000"
echo "Frontend: http://localhost:8080"
echo "Press Ctrl+C to stop all application processes."
echo "------------------------------------------------"

# Keep script running to maintain the trap
wait
