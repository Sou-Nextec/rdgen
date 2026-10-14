#requires -version 5.1
<#
Integracao da recuperacao de credencial: o agente REAL (Agente-Senha-Nextec.ps1) fala com um servidor HTTP falso local
(HttpListener em 127.0.0.1) que responde 401 ao sync. Confirma, com respostas HTTP de verdade:
  - 1 ou 2 respostas 401 seguidas NAO descartam a credencial (e uma falha diferente, como 503, zera a contagem);
  - a 3a resposta 401 seguida guarda a credencial em agente-senha.json.anterior;
  - na tentativa seguinte o provisionador REAL refaz o cadastro (self-enroll) e grava uma credencial nova.

  -InstallDir  pasta com Agente-Senha-Nextec.ps1 e Provisionar-Agente-Nextec.ps1 (padrao: esta pasta)

Sem administrador, ACLs e log protegido do provisionador sao substituidos por duplas simples; o restante e o codigo real.
#>
[CmdletBinding()]
param([string]$InstallDir)
$ErrorActionPreference = 'Stop'
if (-not $InstallDir) { $InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
function Assert($value, [string]$message) { if (-not $value) { throw "ASSERT: $message" } }

Add-Type -AssemblyName System.Security
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

foreach ($name in @('Agente-Senha-Nextec.ps1', 'Provisionar-Agente-Nextec.ps1')) {
  $path = Join-Path $InstallDir $name
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Script nao encontrado: $path" }
  $tokens = $null; $errors = $null
  $ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
  if ($errors.Count) { throw "$name nao compilou: $($errors[0].Message)" }
  foreach ($definition in $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
    . ([scriptblock]::Create($definition.Extent.Text))
  }
}
Assert ((Get-Command Invoke-NextecAgentExecute -ErrorAction SilentlyContinue)) 'Invoke-NextecAgentExecute ausente no agente'

# servidor falso: sync responde o status em $state.SyncStatus; self-enroll aceita e devolve o token proposto
$probe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0); $probe.Start()
$port = ([Net.IPEndPoint]$probe.LocalEndpoint).Port; $probe.Stop()
$script:testOrigin = "http://127.0.0.1:$port"
$state = [hashtable]::Synchronized(@{ SyncStatus = 401; Requests = New-Object System.Collections.ArrayList })
$listener = [Net.HttpListener]::new()
$listener.Prefixes.Add("$($script:testOrigin)/")
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
      $path = $ctx.Request.Url.AbsolutePath
      [void]$state.Requests.Add([pscustomobject]@{ Path = $path; Body = $body })
      if ($path -eq '/api/nextec/agent/sync') { $status = [int]$state.SyncStatus; $payload = '{"error":"unauthorized"}' }
      elseif ($path -eq '/api/nextec/agent/self-enroll') { $status = 200; $payload = (@{ token = [string]$body.proposed_token; state = 'pending' } | ConvertTo-Json -Compress) }
      else { $status = 404; $payload = '{"error":"not_found"}' }
      $bytes = [Text.Encoding]::UTF8.GetBytes($payload)
      $ctx.Response.StatusCode = $status
      $ctx.Response.ContentType = 'application/json'
      $ctx.Response.ContentLength64 = $bytes.Length
      $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    } catch {} finally { try { $ctx.Response.Close() } catch {} }
  }
})
$handle = $pipe.BeginInvoke()

$work = Join-Path ([IO.Path]::GetTempPath()) ('nextec-401-int-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null
try {
  # O agente e o provisionador enxergam o painel falso (http loopback) so neste teste; o resto do codigo e o real.
  $realConvert = (Get-Command ConvertTo-NextecPainelUrl).ScriptBlock
  function ConvertTo-NextecPainelUrl { param([string]$Url) if ($Url -ceq $script:testOrigin) { return $Url }; return (& $script:realConvert -Url $Url) }
  function Get-NextecPainelConfigurado { param($Root, $Padrao, $RegistryKey) $script:NextecPainelOrigem = 'teste'; return $script:testOrigin }
  function MeuId { return '536822159' }
  if (-not $isAdmin) {
    function Initialize-NextecProvisionDirectory { param($Root) New-Item -ItemType Directory -Path $Root -Force | Out-Null }
    function Assert-NextecProvisionPath { param($Path) }
    function Assert-NextecProvisionFileAcl { param($Path) }
    function Write-NextecProvisionLog { param($Code, $Root) Add-Content -LiteralPath (Get-NextecProvisionPaths -Root $Root).Log -Value ([string]$Code) -Encoding UTF8 }
    function Write-NextecProtectedJson { param($Path, $Value) $Value | ConvertTo-Json -Depth 6 -Compress | Set-Content -LiteralPath $Path -Encoding UTF8 }
    function Set-Acl { param($LiteralPath, $AclObject) }
  }

  # variaveis que o corpo do agente le do escopo do script
  $PastaDados = Join-Path $work 'dados'
  New-Item -ItemType Directory -Path $PastaDados -Force | Out-Null
  $Config = Join-Path $PastaDados 'agente-senha.json'
  $Log = Join-Path $PastaDados 'agente-senha.log'
  $Instalar = $false; $Simular = $false
  $script:NextecPainelFixo = $script:testOrigin

  $falhas = Join-Path $PastaDados 'agente-senha.falhas'
  $deadToken = 'AbCdEf0123456789AbCdEf0123456789AbCdEf01234'
  function Write-DeadCredential {
    $json = @{ painel = $script:testOrigin; id = '536822159'; token = (Proteger $deadToken) } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($Config, $json, [Text.UTF8Encoding]::new($false))
  }
  function Get-SyncCount { return @($state.Requests | Where-Object { $_.Path -eq '/api/nextec/agent/sync' }).Count }

  # 1) 401, 401, 503, 401, 401: nada descarta (a sequencia foi interrompida pelo 503)
  Write-DeadCredential
  foreach ($status in @(401, 401, 503, 401, 401)) {
    $state.SyncStatus = $status
    $ok = Invoke-NextecAgentExecute
    Assert (-not $ok) "ciclo com HTTP $status deveria falhar"
    Assert (Test-Path -LiteralPath $Config -PathType Leaf) "credencial descartada cedo demais (HTTP $status)"
  }
  Assert ((Get-SyncCount) -eq 5) "esperava 5 chamadas de sync reais, houve $(Get-SyncCount)"
  Assert (-not (Test-Path -LiteralPath ($Config + '.anterior'))) 'credencial foi guardada ao lado antes de 3 respostas 401 seguidas'
  Write-Host 'PASS Integration_OneOrTwo401DoNotDiscard'

  # 2) o 3o 401 seguido descarta: a credencial vai para .anterior, sem chamar o cadastro ainda
  $state.SyncStatus = 401
  $ok = Invoke-NextecAgentExecute
  Assert (-not $ok) '3o ciclo 401 deveria falhar'
  Assert (-not (Test-Path -LiteralPath $Config -PathType Leaf)) 'credencial continuou ativa depois de 3 respostas 401 seguidas'
  Assert (Test-Path -LiteralPath ($Config + '.anterior') -PathType Leaf) 'credencial descartada nao foi guardada em .anterior'
  Assert ((Get-SyncCount) -eq 6) 'contagem de sync inesperada'
  Assert (@($state.Requests | Where-Object { $_.Path -eq '/api/nextec/agent/self-enroll' }).Count -eq 0) 'cadastro novo antes da tentativa seguinte'
  $logText = Get-Content -LiteralPath $Log -Raw
  Assert ($logText -match '3 vezes seguidas') 'descarte nao foi registrado no log do agente'
  Assert (-not $logText.Contains($deadToken)) 'token vazou no log do agente'
  Write-Host 'PASS Integration_Third401DiscardsCredential'

  # 3) tentativa seguinte: o provisionador real refaz o cadastro (self-enroll) e grava credencial nova
  $enrollKey = 'nx1.1790000000.AbCdEf0123456789_-AbCdEf0123456789'
  [IO.File]::WriteAllText((Join-Path $PastaDados 'inscricao.json'), (@{ v = 1; painel = $script:testOrigin; chave = $enrollKey } | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
  if ($isAdmin) { Set-Acl -LiteralPath (Join-Path $PastaDados 'inscricao.json') -AclObject (New-NextecProvisionAcl) }
  $post = { param($panel, $body) Invoke-NextecSelfEnrollPost -Panel $panel -Body $body -TestOrigin $script:testOrigin }
  $result = Invoke-NextecProvisioning -Root $PastaDados -DiscoverId { '536822159' } -Now ([DateTime]::UtcNow) -PostSelfEnroll $post `
    -PostBootstrap { param($p, $b) throw 'legacy bootstrap must not be used' } -RegisterAgent { param($path) } -GetUuid { Get-NextecMachineUuid } `
    -AgentTaskReady { param($r) $true }
  Assert ($result -eq 'complete') "novo cadastro nao concluiu: $result"
  $enrolls = @($state.Requests | Where-Object { $_.Path -eq '/api/nextec/agent/self-enroll' })
  Assert ($enrolls.Count -eq 1) "esperava 1 cadastro novo, houve $($enrolls.Count)"
  Assert (([string]$enrolls[0].Body.proposed_token) -match '^[A-Za-z0-9_-]{43,128}$') 'token proposto fora do formato'
  Assert ([string]$enrolls[0].Body.proposed_token -cne $deadToken) 'cadastro novo reaproveitou o token morto'
  Assert (Test-Path -LiteralPath $Config -PathType Leaf) 'credencial nova nao foi gravada depois do cadastro'
  $fresh = Read-NextecAgentTokenConfig -Path $Config
  Assert ($fresh.token -ceq [string]$enrolls[0].Body.proposed_token -and $fresh.id -ceq '536822159') 'credencial nova nao corresponde ao cadastro'
  Write-Host 'PASS Integration_NewEnrollmentAfterDiscard'

  Write-Output 'PASS: agent 401 recovery against a local fake panel (real HTTP 401 x3 -> discard -> self-enroll)'
} finally {
  try { $listener.Stop(); $listener.Close() } catch {}
  try { $pipe.Stop() } catch {}
  try { $runspace.Close() } catch {}
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
