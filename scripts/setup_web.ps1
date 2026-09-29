$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "[AEGIS] Installing Python web dependencies..." -ForegroundColor Cyan
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    throw "Virtual environment not found at .venv. Create/activate it first."
}
& $python -m pip install -e ".[dev]"

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw "Node.js was not found. Install Node.js LTS, reopen PowerShell, then rerun this script."
}
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    throw "npm was not found. Reinstall Node.js LTS, reopen PowerShell, then rerun this script."
}

Write-Host "[AEGIS] Node: $(node --version)" -ForegroundColor DarkGray
Write-Host "[AEGIS] npm:  $(npm --version)" -ForegroundColor DarkGray
Write-Host "[AEGIS] Installing React dependencies..." -ForegroundColor Cyan
Set-Location (Join-Path $root "frontend")
npm install

Write-Host "[AEGIS] Building frontend for verification..." -ForegroundColor Cyan
npm run build

Set-Location $root
Write-Host "[AEGIS] Setup complete." -ForegroundColor Green
Write-Host "Next: .\scripts\start_aegis_web.ps1" -ForegroundColor Green
