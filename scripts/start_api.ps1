$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { throw "Missing .venv Python at $python" }
$envFile = Join-Path $root ".env"
if (Test-Path $envFile) {
    Write-Host "[AEGIS] Loading local .env configuration" -ForegroundColor DarkGray
    & $python -m uvicorn api.main:app --reload --host 127.0.0.1 --port 8000 --env-file $envFile
} else {
    & $python -m uvicorn api.main:app --reload --host 127.0.0.1 --port 8000
}
