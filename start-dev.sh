#!/bin/bash

# Ensure we're in the project root
cd "$(dirname "$0")"

# Function to kill processes on specific ports
clear_ports() {
    echo "Checking ports 8001 and 8080..."
    fuser -k 8001/tcp 8080/tcp > /dev/null 2>&1 || true
}

# Cleanup function
cleanup() {
    echo ""
    echo "Shutting down InFlux development environment..."
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null
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

echo "Starting InFlux Development Infrastructure (NATS, Cassandra)..."
docker compose up -d nats cassandra

echo "Waiting for Cassandra to be ready (max 120s)..."
RETRY_COUNT=0
MAX_RETRIES=40
sleep 15
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
  if docker compose exec cassandra cqlsh -e "describe keyspaces" > /dev/null 2>&1; then
    echo " Cassandra is ready!"
    break
  fi
  echo -n "."
  sleep 3
  RETRY_COUNT=$((RETRY_COUNT+1))
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
  echo " Cassandra failed to start in time."
  exit 1
fi

echo "Setting up environment variables..."
export NATS_URL="nats://localhost:4222"
export CASSANDRA_URL="localhost:9042"
export NEXT_PUBLIC_API_URL="http://localhost:8001"

echo "Starting Backend..."
cd backend
# Run backend and capture PID
cargo run &
BACKEND_PID=$!
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
echo "Backend: http://localhost:8001"
echo "Frontend: http://localhost:8080"
echo "Press Ctrl+C to stop all application processes."
echo "------------------------------------------------"

# Keep script running to maintain the trap
wait
