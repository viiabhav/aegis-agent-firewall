$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $root ".env"

Write-Host "AEGIS LLM Judge setup" -ForegroundColor Cyan
Write-Host "Your key will be written only to the local .env file, which is gitignored." -ForegroundColor DarkGray
$secure = Read-Host "Paste your Groq API key" -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $key = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}

if ([string]::IsNullOrWhiteSpace($key)) { throw "No API key entered." }

$lines = @()
if (Test-Path $envFile) { $lines = Get-Content $envFile }
$updated = $false
$newLines = foreach ($line in $lines) {
    if ($line -match '^GROQ_API_KEY=') {
        $updated = $true
        "GROQ_API_KEY=$key"
    } else { $line }
}
if (-not $updated) { $newLines += "GROQ_API_KEY=$key" }
if (-not ($newLines -match '^GROQ_MODEL=')) { $newLines += "GROQ_MODEL=openai/gpt-oss-20b" }
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllLines($envFile, [string[]]$newLines, $utf8NoBom)
$key = $null

Write-Host "Saved to $envFile" -ForegroundColor Green
Write-Host "Return to AEGIS and click Recheck provider. No key is sent to the browser UI." -ForegroundColor Green
