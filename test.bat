@echo off
title BalanceVault Automated Test Runner
cd /d "%~dp0"
echo =========================================================
echo   Running BalanceVault Automated Test Suite...
echo =========================================================

REM Check if portable node exists in tools directory
if exist "%~dp0tools\node\node.exe" (
    SET "PATH=%~dp0tools\node;%PATH%"
    "%~dp0tools\node\node.exe" tests\ledger.test.js
    goto end
)

REM Otherwise check for system node
where node >nul 2>nul
if %errorlevel% equ 0 (
    node tests\ledger.test.js
    goto end
)

echo.
echo [ERROR] Node.js was not found on this system!
echo Please install Node.js from https://nodejs.org or keep the tools/node folder.
echo.
pause

:end
