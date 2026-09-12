param(
  [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')][string]$Workspace,
  [Parameter(Mandatory=$true)][ValidatePattern('^phase2a-[a-z0-9]{24}$')][string]$SessionId
)
$ErrorActionPreference = 'Stop'
$localData = [Environment]::GetFolderPath('LocalApplicationData')
$secretPath = Join-Path $localData 'ForgeWarden\secrets\anythingllm-api-key.dpapi'
if (-not (Test-Path -LiteralPath $secretPath -PathType Leaf)) { throw 'AnythingLLM credential handle is unavailable' }
$prompt = [Console]::In.ReadToEnd()
if ([Text.Encoding]::UTF8.GetByteCount($prompt) -gt 48000) { throw 'AnythingLLM prompt exceeds bound' }
$secure = Get-Content -LiteralPath $secretPath -Raw | ConvertTo-SecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
$key = $null
try {
  $key = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
  $pids = @(Get-CimInstance Win32_Process | Where-Object {
    $_.Name -eq 'AnythingLLM.exe' -and $_.ExecutablePath -like (Join-Path $localData 'Programs\AnythingLLM\*')
  } | ForEach-Object ProcessId)
  $ports = @(Get-NetTCPConnection -State Listen | Where-Object {
    $pids -contains $_.OwningProcess -and $_.LocalAddress -in @('127.0.0.1','::1')
  } | ForEach-Object LocalPort | Sort-Object -Unique)
  $apis = @()
  foreach ($port in $ports) {
    try {
      $doc = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$port/api/docs/swagger-ui-init.js" -TimeoutSec 2
      if ($doc.Content -match 'AnythingLLM Developer API' -and $doc.Content -match '/v1/workspace/\{slug\}/chat') { $apis += $port }
    } catch {}
  }
  if ($apis.Count -ne 1) { throw 'AnythingLLM API endpoint is unavailable or ambiguous' }
  $uri = "http://127.0.0.1:$($apis[0])/api/v1/workspace/$Workspace/chat"
  $body = @{message=$prompt; mode='chat'; sessionId=$SessionId; reset=$true} | ConvertTo-Json -Compress
  $response = Invoke-RestMethod -Method Post -Uri $uri -Headers @{Authorization="Bearer $key"} -ContentType 'application/json' -Body $body -TimeoutSec 180
  if ($response.type -ne 'textResponse' -or -not $response.close -or $response.error) { throw 'AnythingLLM returned incomplete output' }
  [Console]::Out.Write([string]$response.textResponse)
} finally {
  $key = $null
  if ($ptr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}
