$ErrorActionPreference = 'Stop'
$directory = Join-Path $env:LOCALAPPDATA 'ForgeWarden\secrets'
New-Item -ItemType Directory -Force -Path $directory | Out-Null
$secretPath = Join-Path $directory 'anythingllm-api-key.dpapi'
$key = Read-Host 'Paste AnythingLLM API key (masked)' -AsSecureString
$key | ConvertFrom-SecureString | Set-Content -LiteralPath $secretPath -NoNewline
icacls.exe $directory /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" 'SYSTEM:(OI)(CI)F' | Out-Null
Write-Host 'AnythingLLM key stored with Windows DPAPI for the current user.'
