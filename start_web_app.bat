@echo off
echo ==============================================
echo Compy V2 Forensic Engine - Web Interface
echo ==============================================
echo.
echo Checking for Python virtual environment...

if not exist ".venv" (
    echo Creating virtual environment...
    python -m venv .venv
)

echo Activating virtual environment...
call .venv\Scripts\activate.bat

echo Installing required packages...
pip install -e .
pip install fastapi uvicorn python-multipart jinja2 reportlab aiofiles

echo.
echo ==============================================
echo Starting Web Server...
echo Please open http://127.0.0.1:8000 in your browser.
echo Press Ctrl+C to stop the server.
echo ==============================================
echo.

python -m uvicorn fmd.v2.adapters.web.app:app --host 127.0.0.1 --port 8000 --reload
pause
