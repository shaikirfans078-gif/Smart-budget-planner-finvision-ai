@echo off
REM Double-click to install (first time) and start FinVision on http://localhost:3000
cd /d "%~dp0backend"
if not exist node_modules (
  echo Installing packages, please wait...
  call npm install
)
echo.
echo Wait for the line "FinVision server running on port 3000", then open http://localhost:3000
echo.
call npm start
pause
