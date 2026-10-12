@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0assinar-pedido-connect.ps1"
exit /b %errorlevel%
