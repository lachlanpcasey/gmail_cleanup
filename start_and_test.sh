#!/bin/bash
# Quick script to restart Flask and test

echo "🔄 Stopping any running Python processes..."
taskkill -F -IM python.exe 2>/dev/null || true

echo ""
echo "🚀 Starting Flask server..."
echo "Visit: http://localhost:5000"
echo ""
echo "After logging in, press Ctrl+C here and run: python test_query.py"
echo ""

python -m flask --app app.main run --debug
