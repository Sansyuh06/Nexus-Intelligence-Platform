#!/bin/bash

# Activate virtual environment
source /opt/venv/bin/activate

# Start FastAPI server in background
uvicorn server.app:app --host 0.0.0.0 --port 8000 &

# Wait a bit for FastAPI to start
sleep 2

# Start Next.js server
npm start