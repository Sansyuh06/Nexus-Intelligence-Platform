#!/bin/bash

echo "Starting servers..."

# Start FastAPI server in background (reads PORT from env, defaults to 8000)
FASTAPI_PORT="${PORT:-8000}"
echo "Starting FastAPI on port $FASTAPI_PORT..."
python3 -m uvicorn server.app:app --host 0.0.0.0 --port "$FASTAPI_PORT" &
FASTAPI_PID=$!
echo "FastAPI started with PID $FASTAPI_PID"

# Wait a bit for FastAPI to start
sleep 5
echo "Waited 5 seconds for FastAPI"

# Check if FastAPI is still running
if kill -0 $FASTAPI_PID 2>/dev/null; then
    echo "FastAPI is running"
else
    echo "FastAPI failed to start"
    exit 1
fi

# Start Next.js server in production mode on internal port 3000
echo "Starting Next.js on port 3000..."
export PORT=3000
npm start &

# Wait for FastAPI so container doesn't exit
wait $FASTAPI_PID