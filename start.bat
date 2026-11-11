@echo off
title BalanceVault Server
cd /d "%~dp0"
echo =========================================================
echo   Starting BalanceVault Web Application...
echo =========================================================

REM Check if portable node exists in tools directory
if exist "%~dp0tools\node\node.exe" (
    echo Using portable Node runtime...
    SET "PATH=%~dp0tools\node;%PATH%"
    "%~dp0tools\node\node.exe" server.js
    goto end
)

REM Otherwise check for system node
where node >nul 2>nul
if %errorlevel% equ 0 (
    echo Using system Node runtime...
    node server.js
    goto end
)

echo.
echo [ERROR] Node.js was not found on this system!
echo Please install Node.js from https://nodejs.org or keep the tools/node folder.
echo.
pause

:end
