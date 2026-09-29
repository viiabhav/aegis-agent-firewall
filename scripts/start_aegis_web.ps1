$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { throw "Missing .venv Python at $python" }
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) { throw "npm is not installed or not on PATH" }

$envFile = Join-Path $root ".env"
if (Test-Path $envFile) {
    $apiCommand = "Set-Location '$root'; & '$python' -m uvicorn api.main:app --reload --host 127.0.0.1 --port 8000 --env-file '$envFile'"
} else {
    $apiCommand = "Set-Location '$root'; & '$python' -m uvicorn api.main:app --reload --host 127.0.0.1 --port 8000"
}
$uiPath = Join-Path $root "frontend"
$uiCommand = "Set-Location '$uiPath'; npm run dev"

Write-Host "[AEGIS] Starting FastAPI on http://127.0.0.1:8000" -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", $apiCommand
Start-Sleep -Seconds 2
Write-Host "[AEGIS] Starting AEGIS Console on http://localhost:5173" -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", $uiCommand
Write-Host "[AEGIS] Two development terminals opened." -ForegroundColor Green
Write-Host "Open http://localhost:5173 in your browser." -ForegroundColor Green
