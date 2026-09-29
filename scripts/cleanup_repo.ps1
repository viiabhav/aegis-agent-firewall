$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "[AEGIS] Cleaning development-only artifacts..." -ForegroundColor Cyan

$legacyNotes = @(
    "README_PATCH.txt",
    "README_REPLAY.txt",
    "README_STEP7.txt",
    "README_STEP8.txt",
    "README_UI_ACCESSIBILITY.txt",
    "README_WEB_UI.md"
)

foreach ($file in $legacyNotes) {
    if (Test-Path $file) {
        Remove-Item $file -Force
        Write-Host "  removed $file"
    }
}

Get-ChildItem -Recurse -Directory -Force | Where-Object {
    $_.Name -eq "__pycache__" -or $_.Name -eq ".pytest_cache"
} | Sort-Object FullName -Descending | ForEach-Object {
    Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
}

if (Test-Path "frontend/dist") {
    Remove-Item "frontend/dist" -Recurse -Force
    Write-Host "  removed frontend/dist (rebuild before deployment)"
}

Write-Host "[AEGIS] Cleanup complete. Local .env was not touched." -ForegroundColor Green
