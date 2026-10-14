#requires -version 5.1
<#
Regressao do pendente de OUTRO painel contra o PAYLOAD INSTALADO (pasta -InstallDir, como o MSI a instala).

Reproduz a maquina que trocou de dominio: provisionamento-agente.json (journal pendente) gravado para o painel anterior e o
inscricao.json do instalador apontando para o painel atual. O Provisionar-Agente-Nextec.ps1 INSTALADO, executado em 0 e em
20 minutos, precisa:
  - descartar o pendente do painel anterior (log pending_other_panel), sem identity_conflict e sem manter o journal;
  - chegar ao self-enroll no painel atual (servidor HTTP falso local) e concluir.
Casos de controle:
  - pendente do MESMO painel: aos 0 minutos fica (nenhum self-enroll); aos 20 minutos expira (pending_expired) e reinscreve;
  - 401 triplo do agente (test_agent_401_integration.ps1 do mesmo -InstallDir) continua descartando e reinscrevendo.

O script de painel anterior ao #90 (commit 99ddd982) falha este teste com identity_conflict.
Sem administrador, ACLs e log protegido sao duplas simples; o resto (journal, DPAPI, parse, HTTP) e o codigo real.
#>
[CmdletBinding()]
param([string]$InstallDir)
$ErrorActionPreference = 'Stop'
if (-not $InstallDir) { $InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$provisioner = Join-Path $InstallDir 'Provisionar-Agente-Nextec.ps1'
if (-not (Test-Path -LiteralPath $provisioner -PathType Leaf)) { throw "Provisioner not found in $InstallDir" }
function Assert($value, [string]$message) { if (-not $value) { throw "ASSERT: $message" } }

$work = Join-Path ([IO.Path]::GetTempPath()) ('nextec-outro-painel-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$enrollKey = 'nx1.1790000000.AbCdEf0123456789_-AbCdEf0123456789'
$currentPanel = 'https://painel-remoto.nex.tec.br'
$otherPanel = 'https://painel-anterior.exemplo.test'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

. $provisioner 6>$null | Out-Null
$script:NextecProvisionScriptRoot = $InstallDir
# O painel que o instalador gravou: o mesmo do inscricao.json de cada caso.
$script:NextecPainelFixo = $currentPanel

if (-not $isAdmin) {
  function Initialize-NextecProvisionDirectory { param($Root) New-Item -ItemType Directory -Path $Root -Force | Out-Null }
  function Assert-NextecProvisionPath { param($Path) }
  function Assert-NextecProvisionFileAcl { param($Path) }
  function Write-NextecProvisionLog { param($Code,$Root) Add-Content -LiteralPath (Get-NextecProvisionPaths -Root $Root).Log -Value ([string]$Code) -Encoding UTF8 }
  function Write-NextecProtectedJson { param($Path,$Value) $Value | ConvertTo-Json -Depth 6 -Compress | Set-Content -LiteralPath $Path -Encoding UTF8 }
}

$probe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0); $probe.Start()
$port = ([Net.IPEndPoint]$probe.LocalEndpoint).Port; $probe.Stop()
$origin = "http://127.0.0.1:$port"
$state = [hashtable]::Synchronized(@{ Requests = New-Object System.Collections.ArrayList })
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
      $raw = (New-Object IO.StreamReader($ctx.Request.InputStream, [Text.Encoding]::UTF8)).ReadToEnd()
      $body = $null
      try { $body = $raw | ConvertFrom-Json } catch {}
      [void]$state.Requests.Add([pscustomobject]@{ Path = $ctx.Request.Url.AbsolutePath; Body = $body })
      $payload = @{ token = [string]$body.proposed_token; state = 'pending' } | ConvertTo-Json -Compress
      $bytes = [Text.Encoding]::UTF8.GetBytes($payload)
      $ctx.Response.StatusCode = 200
      $ctx.Response.ContentType = 'application/json'
      $ctx.Response.ContentLength64 = $bytes.Length
      $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    } catch {} finally { try { $ctx.Response.Close() } catch {} }
  }
})
$null = $pipe.BeginInvoke()

function New-CaseRoot {
  param([string]$JournalPanel, [DateTime]$Created)
  $root = Join-Path $work ('case-' + [Guid]::NewGuid().ToString('N'))
  Initialize-NextecProvisionDirectory -Root $root
  $paths = Get-NextecProvisionPaths -Root $root
  [IO.File]::WriteAllText($paths.Enroll, (@{ v = 1; painel = $currentPanel; chave = $enrollKey } | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
  if ($isAdmin) { Set-Acl -LiteralPath $paths.Enroll -AclObject (New-NextecProvisionAcl) }
  $journal = [pscustomobject]@{
    painel = $JournalPanel; id = '536822159'; uuid = [Convert]::ToBase64String([Guid]::NewGuid().ToByteArray())
    bootstrap = 'nxb1.AbCdEf0123456789_-AbCdEf0123456789'; proposed_token = 'AbCdEf0123456789AbCdEf0123456789AbCdEf01234'
    created_utc = $Created; state = 'pending'
  }
  Save-NextecProvisionJournal -Journal $journal -Path $paths.Journal
  if ($isAdmin) { Set-Acl -LiteralPath $paths.Journal -AclObject (New-NextecProvisionAcl) }
  $state.Requests.Clear()
  return $root
}
function Invoke-Cycle {
  param([string]$Root, [DateTime]$Now)
  $post = { param($panel, $body) Invoke-NextecSelfEnrollPost -Panel $panel -Body $body -TestOrigin $origin }.GetNewClosure()
  Invoke-NextecProvisioning -Root $Root -DiscoverId { '536822159' } -Now $Now -PostSelfEnroll $post `
    -PostBootstrap { param($p,$b) throw 'network down' } -RegisterAgent { param($path) } -GetUuid { Get-NextecMachineUuid } `
    -AgentTaskReady { param($r) $true }
}
function Get-LogText([string]$Root) {
  $log = (Get-NextecProvisionPaths -Root $Root).Log
  if (Test-Path -LiteralPath $log) { return (Get-Content -LiteralPath $log -Raw) }
  return ''
}

try {
  $t0 = [DateTime]::SpecifyKind([DateTime]'2026-10-12T12:00:00', [DateTimeKind]::Utc)

  # 1) pendente de OUTRO painel, em 0 e em 20 minutos: descartado e self-enroll no painel atual, nunca identity_conflict.
  foreach ($minutes in @(0, 20)) {
    $root = New-CaseRoot -JournalPanel $otherPanel -Created $t0
    $paths = Get-NextecProvisionPaths -Root $root
    Assert (Test-Path -LiteralPath $paths.Journal -PathType Leaf) 'fixture sem journal pendente'
    $result = $null
    try { $result = Invoke-Cycle -Root $root -Now $t0.AddMinutes($minutes) }
    catch { throw "ASSERT: pendente de outro painel aos $minutes min deveria chegar ao self-enroll, mas lancou: $($_.Exception.Message)" }
    $text = Get-LogText $root
    Assert ($text -notmatch 'identity_conflict') "identity_conflict aos $minutes min com pendente de outro painel"
    Assert ($text -match 'pending_other_panel') "descarte do pendente de outro painel nao foi registrado aos $minutes min"
    Assert (-not (Test-Path -LiteralPath $paths.Journal -PathType Leaf)) "journal de outro painel foi mantido aos $minutes min"
    Assert ($result -eq 'complete') "self-enroll nao concluiu aos $minutes min: $result"
    Assert ($state.Requests.Count -eq 1 -and $state.Requests[0].Path -eq '/api/nextec/agent/self-enroll') "self-enroll nao foi chamado aos $minutes min"
    Assert ($state.Requests[0].Body.enroll_key -ceq $enrollKey) 'self-enroll saiu sem a chave do inscricao.json'
    Assert ($text.Contains($enrollKey) -eq $false) 'chave de inscricao vazou para o log'
    Write-Host "PASS OtherPanelPending_DiscardedAndSelfEnrolled_${minutes}min"
  }

  # 2) pendente do MESMO painel: aos 0 min fica (sem self-enroll); aos 20 min expira e reinscreve.
  $root = New-CaseRoot -JournalPanel $currentPanel -Created $t0
  $paths = Get-NextecProvisionPaths -Root $root
  $result = Invoke-Cycle -Root $root -Now $t0
  Assert ($state.Requests.Count -eq 0) 'pendente do mesmo painel nao deveria inscrever aos 0 min'
  Assert ($result -eq 'network_retry') "pendente do mesmo painel aos 0 min: esperado network_retry, veio $result"
  Assert (Test-Path -LiteralPath $paths.Journal -PathType Leaf) 'pendente do mesmo painel foi descartado cedo demais'
  Assert ((Get-LogText $root) -notmatch 'pending_other_panel|identity_conflict') 'mesmo painel tratado como outro painel'
  $result = Invoke-Cycle -Root $root -Now $t0.AddMinutes(20)
  Assert ($result -eq 'complete') "pendente expirado do mesmo painel nao reinscreveu aos 20 min: $result"
  Assert ((Get-LogText $root) -match 'pending_expired') 'expiracao do pendente nao foi registrada'
  Assert (-not (Test-Path -LiteralPath $paths.Journal -PathType Leaf)) 'journal expirado foi mantido'
  Assert ($state.Requests.Count -eq 1) 'reinscricao apos expirar nao chamou o self-enroll'
  Write-Host 'PASS SamePanelPending_KeptThenExpired'

  # 3) 401 triplo do agente do MESMO payload (achado anterior).
  $auth401 = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'test_agent_401_integration.ps1'
  $out = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $auth401 -InstallDir $InstallDir 2>&1 | Out-String)
  if ($LASTEXITCODE -ne 0 -or $out -notmatch 'PASS: agent 401 recovery') { throw "ASSERT: 401 triplo falhou: $out" }
  Write-Host 'PASS Agent401Triple_StillRecovers'

  Write-Output 'PASS: other-panel pending journal regression against the installed payload'
} finally {
  try { $listener.Stop(); $listener.Close() } catch {}
  try { $pipe.Stop() } catch {}
  try { $runspace.Close() } catch {}
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
