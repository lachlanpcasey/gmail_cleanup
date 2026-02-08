@echo off
echo ============================================
echo Gmail Cleanup - Restart and Test
echo ============================================
echo.

echo 1. Stopping any running Python processes...
taskkill /F /IM python.exe >nul 2>&1

echo.
echo 2. Starting FastAPI server with Uvicorn...
echo.
echo    Visit: http://localhost:8000
echo    Log in with your Gmail account
echo.
echo 3. After logging in successfully:
echo    - Press Ctrl+C to stop the server
echo    - Run: python test_query.py
echo    - This will show how many emails Gmail API can see
echo.
echo ============================================
echo.

python -m uvicorn app.main:app --log-level debug
