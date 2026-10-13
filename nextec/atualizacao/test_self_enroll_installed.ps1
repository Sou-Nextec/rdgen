#requires -version 5.1
<#
Teste integrado da inscricao global: instalar -> ler a chave -> POST self-enroll -> pendente.

Executa o Provisionar-Agente-Nextec.ps1 INSTALADO (pasta -InstallDir) contra um servidor HTTP local falso que
implementa o contrato do painel (200 {token,state:"pending"}, 404 retry, 401/409 manual, 403 parada) e confirma
que o POST sai com a enroll_key do inscricao.json instalado, id/uuid e proposed_token base64url de 43 a 128 chars.

  -InstallDir  pasta com os scripts e o inscricao.json como o MSI os instala (INSTALLFOLDER)
               padrao: esta pasta (scripts do repositorio) com um inscricao.json de teste gerado
Sem privilegio de administrador, as ACLs protegidas (SYSTEM/Administradores) sao substituidas por duplas
simples; o restante do codigo (parse, token, uuid, HTTP, recuo, diario) e o real. Como administrador (CI), tudo e real.
#>
[CmdletBinding()]
param([string]$InstallDir)
$ErrorActionPreference = 'Stop'
if (-not $InstallDir) { $InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$provisioner = Join-Path $InstallDir 'Provisionar-Agente-Nextec.ps1'
$installedEnrollment = Join-Path $InstallDir 'inscricao.json'
if (-not (Test-Path -LiteralPath $provisioner -PathType Leaf)) { throw "Provisioner not found in $InstallDir" }
function Assert($value, [string]$message) { if (-not $value) { throw $message } }

$work = Join-Path ([IO.Path]::GetTempPath()) ('nextec-selfenroll-int-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$generated = $false
if (-not (Test-Path -LiteralPath $installedEnrollment -PathType Leaf)) {
  # Execucao local sem pacote: gera um inscricao.json de teste no formato que o gerador produz.
  $installedEnrollment = Join-Path $work 'inscricao.json'
  [IO.File]::WriteAllText($installedEnrollment, '{"v":1,"painel":"https://painel-remoto.nex.tec.br","chave":"nx1.1790000000.AbCdEf0123456789_-AbCdEf0123456789"}', [Text.UTF8Encoding]::new($false))
  $generated = $true
}
$enrollment = Get-Content -LiteralPath $installedEnrollment -Raw -Encoding UTF8 | ConvertFrom-Json
$enrollKey = [string]$enrollment.chave
Assert ($enrollKey -match '^[\x21-\x7E]{16,256}$') 'Installed enrollment key is malformed'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Carrega as funcoes do script instalado (sem -Executar ele so as define).
. $provisioner 6>$null | Out-Null
$script:NextecProvisionScriptRoot = $InstallDir

if (-not $isAdmin) {
  function Initialize-NextecProvisionDirectory { param($Root) New-Item -ItemType Directory -Path $Root -Force | Out-Null }
  function Assert-NextecProvisionPath { param($Path) }
  function Assert-NextecProvisionFileAcl { param($Path) }
  function Write-NextecProvisionLog { param($Code,$Root) Add-Content -LiteralPath (Get-NextecProvisionPaths -Root $Root).Log -Value ([string]$Code) -Encoding UTF8 }
  function Write-NextecProtectedJson { param($Path,$Value) $Value | ConvertTo-Json -Depth 6 -Compress | Set-Content -LiteralPath $Path -Encoding UTF8 }
}

# Servidor falso do painel: HttpListener em 127.0.0.1, porta livre, em runspace proprio.
$port = $null
$probe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0); $probe.Start()
$port = ([Net.IPEndPoint]$probe.LocalEndpoint).Port; $probe.Stop()
$origin = "http://127.0.0.1:$port"
$state = [hashtable]::Synchronized(@{ Status = 200; Requests = New-Object System.Collections.ArrayList; Stop = $false })
$listener = [Net.HttpListener]::new()
$listener.Prefixes.Add("$origin/")
$listener.Start()
$runspace = [runspacefactory]::CreateRunspace(); $runspace.Open()
$runspace.SessionStateProxy.SetVariable('listener', $listener)
$runspace.SessionStateProxy.SetVariable('state', $state)
$pipe = [powershell]::Create(); $pipe.Runspace = $runspace
$null = $pipe.AddScript({
  while ($listener.IsListening) {
    try { $ctx = $listener.GetContext() } catch { break }
    try {
      $reader = New-Object IO.StreamReader($ctx.Request.InputStream, [Text.Encoding]::UTF8)
      $raw = $reader.ReadToEnd()
      $body = $null
      try { $body = $raw | ConvertFrom-Json } catch {}
      [void]$state.Requests.Add([pscustomobject]@{ Path = $ctx.Request.Url.AbsolutePath; Method = $ctx.Request.HttpMethod; Body = $body })
      $status = [int]$state.Status
      if ($status -eq 200) { $payload = @{ token = [string]$body.proposed_token; state = 'pending' } | ConvertTo-Json -Compress }
      else { $payload = '{"error":"test"}' }
      $bytes = [Text.Encoding]::UTF8.GetBytes($payload)
      $ctx.Response.StatusCode = $status
      $ctx.Response.ContentType = 'application/json'
      $ctx.Response.ContentLength64 = $bytes.Length
      $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    } catch {} finally { try { $ctx.Response.Close() } catch {} }
  }
})
$handle = $pipe.BeginInvoke()

$script:logs = $null
function New-CaseRoot {
  $root = Join-Path $work ('case-' + [Guid]::NewGuid().ToString('N'))
  Initialize-NextecProvisionDirectory -Root $root
  $paths = Get-NextecProvisionPaths -Root $root
  # O inscricao.json instalado entra na pasta de dados como o coordenador o copia (conteudo identico).
  Copy-Item -LiteralPath $installedEnrollment -Destination $paths.Enroll -Force
  if ($isAdmin) { Set-Acl -LiteralPath $paths.Enroll -AclObject (New-NextecProvisionAcl) }
  $state.Requests.Clear()
  return $root
}
function Invoke-Cycle {
  param([string]$Root, [int]$Status, [DateTime]$Now = [DateTime]::UtcNow)
  $state.Status = $Status
  $post = { param($panel, $body) Invoke-NextecSelfEnrollPost -Panel $panel -Body $body -TestOrigin $origin }.GetNewClosure()
  Invoke-NextecProvisioning -Root $Root -DiscoverId { '536822159' } -Now $Now -PostSelfEnroll $post `
    -PostBootstrap { param($p,$b) throw 'legacy bootstrap must not be used' } `
    -RegisterAgent { param($path) } -GetUuid { Get-NextecMachineUuid }
}
function Assert-NoSecretInLog {
  param([string]$Root, [string[]]$Secrets)
  $log = (Get-NextecProvisionPaths -Root $Root).Log
  if (Test-Path -LiteralPath $log) {
    $text = Get-Content -LiteralPath $log -Raw
    foreach ($secret in $Secrets) { if ($secret -and $text.Contains($secret)) { throw 'Secret leaked into provisioning log' } }
  }
}

try {
  $t0 = [DateTime]::SpecifyKind([DateTime]'2026-10-12T12:00:00', [DateTimeKind]::Utc)

  # 1) 200 pendente: POST com a chave do inscricao.json instalado, id, uuid e token proposto base64url.
  $root = New-CaseRoot
  $result = Invoke-Cycle -Root $root -Status 200 -Now $t0
  Assert ($result -eq 'complete') "Self enrollment did not complete: $result"
  Assert ($state.Requests.Count -eq 1) "Expected one POST, got $($state.Requests.Count)"
  $req = $state.Requests[0]
  Assert ($req.Method -eq 'POST' -and $req.Path -eq '/api/nextec/agent/self-enroll') 'Wrong method or route'
  $b = $req.Body
  Assert ($b.enroll_key -ceq $enrollKey) 'POST enroll_key differs from the installed inscricao.json'
  Assert ($b.id -ceq '536822159') 'POST id wrong'
  Assert ([string]$b.uuid -match '^[A-Za-z0-9+/]+={0,2}$') 'POST uuid is not standard base64'
  Assert ([string]$b.proposed_token -match '^[A-Za-z0-9_-]{43,128}$') 'POST proposed_token is not base64url 43-128'
  Assert (@($b.PSObject.Properties).Count -eq 4) 'POST body has unexpected fields'
  $paths = Get-NextecProvisionPaths -Root $root
  $cfg = Read-NextecAgentTokenConfig -Path $paths.AgentConfig
  Assert ($cfg.token -ceq $b.proposed_token -and $cfg.id -ceq '536822159') 'Token was not stored for the agent'
  Assert-NoSecretInLog -Root $root -Secrets @($enrollKey, [string]$b.proposed_token)
  Write-Host 'PASS Install_ReadKey_PostSelfEnroll_Pending'

  # 2) 404 (maquina ainda nao no painel): tenta de novo com recuo e reenvia o MESMO token proposto.
  $root = New-CaseRoot
  $r1 = Invoke-Cycle -Root $root -Status 404 -Now $t0
  Assert ($r1 -eq 'network_retry') "404 should retry, got $r1"
  $r2 = Invoke-Cycle -Root $root -Status 200 -Now $t0.AddMinutes(2)
  Assert ($r2 -eq 'self_backoff' -and $state.Requests.Count -eq 1) 'Backoff did not hold the second attempt'
  $r3 = Invoke-Cycle -Root $root -Status 200 -Now $t0.AddMinutes(6)
  Assert ($r3 -eq 'complete' -and $state.Requests.Count -eq 2) '404 retry did not complete after backoff'
  Assert ($state.Requests[0].Body.proposed_token -ceq $state.Requests[1].Body.proposed_token) 'Retry changed the proposed token'
  Assert ($state.Requests[1].Body.enroll_key -ceq $enrollKey) 'Retry enroll_key wrong'
  Write-Host 'PASS Retry_404_BackoffSameToken'

  # 3) 401 e 409: autorizacao manual, sem insistir.
  foreach ($status in @(401, 409)) {
    $root = New-CaseRoot
    $r = Invoke-Cycle -Root $root -Status $status -Now $t0
    Assert ($r -eq 'manual_authorization_required') "HTTP $status should require manual authorization, got $r"
    $r = Invoke-Cycle -Root $root -Status 200 -Now $t0.AddHours(5)
    Assert ($r -eq 'manual_authorization_required' -and $state.Requests.Count -eq 1) "HTTP $status was retried"
    Assert (-not (Test-Path -LiteralPath (Get-NextecProvisionPaths -Root $root).AgentConfig)) "HTTP $status created an agent token"
  }
  Write-Host 'PASS Manual_401_409_NoRetry'

  # 4) 403: parada de 24 h, sem novas chamadas.
  $root = New-CaseRoot
  $r = Invoke-Cycle -Root $root -Status 403 -Now $t0
  Assert ($r -eq 'blocked') "403 should stop, got $r"
  $r = Invoke-Cycle -Root $root -Status 200 -Now $t0.AddHours(2)
  Assert ($r -eq 'blocked' -and $state.Requests.Count -eq 1) '403 was retried inside the stop window'
  Write-Host 'PASS Blocked_403_Stops'

  Write-Output ("PASS: installed self-enrollment against a local fake panel" + $(if ($generated) { ' (generated test inscricao.json)' } else { '' }))
} finally {
  try { $listener.Stop(); $listener.Close() } catch {}
  try { $pipe.Stop() } catch {}
  try { $runspace.Close() } catch {}
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
