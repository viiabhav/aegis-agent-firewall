$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Invoke-Checked {
    param(
        [Parameter(Mandatory=$true)][string]$Label,
        [Parameter(Mandatory=$true)][scriptblock]$Command
    )

    Write-Host $Label -ForegroundColor Cyan
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

Write-Host "[AEGIS] 1/6 Secret hygiene" -ForegroundColor Cyan
if (Test-Path .env) {
    Write-Host "  .env present locally (expected; must remain gitignored)."
}

$trackedSecret = Get-ChildItem -Recurse -File -Exclude *.zip | Where-Object {
    $_.FullName -notmatch "\\.venv|node_modules|\\.git" -and $_.Name -notmatch "^\.env($|\.)"
} | Select-String -Pattern "gsk_[A-Za-z0-9]{12,}" -ErrorAction SilentlyContinue

if ($trackedSecret) {
    throw "Potential Groq key found in repository files. Remove it before GitHub."
}

Invoke-Checked "[AEGIS] 2/6 Python tests" { python -m pytest }
Invoke-Checked "[AEGIS] 3/6 Provider-free replay" { python scripts/redteam_replay.py --no-semantic }
Invoke-Checked "[AEGIS] 4/6 Held-out offline sample" { python scripts/benchmark.py --no-semantic }

Write-Host "[AEGIS] 5/6 Frontend production build" -ForegroundColor Cyan
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    if (Test-Path "C:\Program Files\nodejs\node.exe") {
        $env:Path += ";C:\Program Files\nodejs"
    }
}
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    throw "npm was not found. Add C:\Program Files\nodejs to PATH and retry."
}

Push-Location frontend
try {
    npm run build
    if ($LASTEXITCODE -ne 0) {
        throw "Frontend build failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

Write-Host "[AEGIS] 6/6 Final status" -ForegroundColor Cyan
Write-Host "PASS - code/test/replay/benchmark/frontend gates completed." -ForegroundColor Green
Write-Host "Remaining human steps: public GitHub, deployment smoke, pitch deck, demo recording, submission." -ForegroundColor Yellow
