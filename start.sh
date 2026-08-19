#!/bin/bash
# One-command startup for the KAVACH demo.
# Usage:
#   ./start.sh            -> normal demo mode (debug off, clean errors)
#   DEMO_DEBUG=1 ./start.sh -> development mode (debug on, full tracebacks)
#
# Run this from the project root (the folder containing app.py).

set -e

if [ ! -f "app.py" ]; then
  echo "Run this from the kavach project folder (app.py not found here)."
  exit 1
fi

if [ ! -d "venv" ]; then
  echo "Creating virtual environment (first run only)..."
  python3 -m venv venv
fi

source venv/bin/activate

echo "Checking dependencies..."
pip install -q -r requirements.txt

echo ""
echo "Starting KAVACH — The Sentinel Eye"
echo "Dashboard: http://localhost:5001"
echo "Press Ctrl+C to stop."
echo ""

python3 app.py