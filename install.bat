@echo off
title BalanceVault - Install Dependencies
cd /d "%~dp0"
echo =========================================================
echo   Installing Dependencies for BalanceVault...
echo =========================================================

if exist "%~dp0tools\node\npm.cmd" (
    SET "PATH=%~dp0tools\node;%PATH%"
    call "%~dp0tools\node\npm.cmd" install
    goto done
)

where npm >nul 2>nul
if %errorlevel% equ 0 (
    call npm install
    goto done
)

echo.
echo [ERROR] npm was not found on this system!
echo Please install Node.js from https://nodejs.org
echo.
pause
exit /b 1

:done
echo.
echo [SUCCESS] Dependencies installed! You can now double-click start.bat to run the app.
echo.
pause
