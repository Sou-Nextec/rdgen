#requires -version 5.1
[CmdletBinding()]
param(
  [switch]$Executar,
  [switch]$Receber,
  [string]$PastaDados = (Join-Path $env:ProgramData 'Nextec\Acesso')
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Security

$script:NextecPainelFixo = 'https://painel-remoto.nex.tec.br'
$script:NextecTaskName = 'Nextec Acesso - Cadastro de agente'
$script:NextecProvisionScriptRoot = $PSScriptRoot

function Get-NextecProvisionPaths {
  param([string]$Root = (Join-Path $env:ProgramData 'Nextec\Acesso'))
  [pscustomobject]@{
    Root = [IO.Path]::GetFullPath($Root)
    Input = Join-Path $Root 'bootstrap.json'
    Journal = Join-Path $Root 'provisionamento-agente.json'
    AgentConfig = Join-Path $Root 'agente-senha.json'
    AgentScript = Join-Path $Root 'Agente-Senha-Nextec.ps1'
    Log = Join-Path $Root 'provisionamento-agente.log'
    Enroll = Join-Path $Root 'inscricao.json'
    SelfState = Join-Path $Root 'inscricao-estado.json'
  }
}

function New-NextecProvisionAcl {
  param([switch]$Directory)
  $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
  $adminSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
  $acl = if ($Directory) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
  $acl.SetAccessRuleProtection($true, $false)
  $acl.SetOwner($adminSid)
  $inheritance = if ($Directory) { [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit } else { [Security.AccessControl.InheritanceFlags]::None }
  foreach ($sid in @($systemSid, $adminSid)) {
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
  }
  return $acl
}

function Assert-NextecProvisionPath {
  param([Parameter(Mandatory)][string]$Path)
  $current = [IO.Path]::GetFullPath($Path)
  while ($current) {
    if (Test-Path -LiteralPath $current) {
      $item = Get-Item -LiteralPath $current -Force
      if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'unsafe_path' }
    }
    $parent = [IO.Path]::GetDirectoryName($current.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar))
    if (-not $parent -or $parent -eq $current) { break }
    $current = $parent
  }
}

function Assert-NextecProvisionFileAcl {
  param([Parameter(Mandatory)][string]$Path)
  Assert-NextecProvisionPath -Path $Path
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'unsafe_path' }
  $acl = Get-Acl -LiteralPath $Path
  $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  $allowed = @('S-1-5-18','S-1-5-32-544')
  if ($owner -notin $allowed -or -not $acl.AreAccessRulesProtected -or $acl.Access.Count -ne 2) { throw 'unsafe_path' }
  foreach ($rule in $acl.Access) {
    $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    if ($sid -notin $allowed -or $rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl) { throw 'unsafe_path' }
  }
  foreach ($sid in $allowed) {
    if (@($acl.Access | Where-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $sid }).Count -ne 1) { throw 'unsafe_path' }
  }
}

function Initialize-NextecProvisionDirectory {
  param([string]$Root = (Join-Path $env:ProgramData 'Nextec\Acesso'))
  Assert-NextecProvisionPath -Path $Root
  New-Item -ItemType Directory -Path $Root -Force | Out-Null
  Assert-NextecProvisionPath -Path $Root
  Set-Acl -LiteralPath $Root -AclObject (New-NextecProvisionAcl -Directory)
}

function Protect-NextecProvisionValue {
  param([Parameter(Mandatory)][string]$Value)
  $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
  [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine))
}

function Unprotect-NextecProvisionValue {
  param([Parameter(Mandatory)][string]$Value)
  $bytes = [Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($Value), $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
  [Text.Encoding]::UTF8.GetString($bytes)
}

function Write-NextecProtectedJson {
  param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Value)
  Assert-NextecProvisionPath -Path $Path
  $temp = Join-Path ([IO.Path]::GetDirectoryName($Path)) ('.provision-' + [Guid]::NewGuid().ToString('N') + '.tmp')
  try {
    $stream = [IO.File]::Open($temp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $stream.Dispose()
    Set-Acl -LiteralPath $temp -AclObject (New-NextecProvisionAcl)
    [IO.File]::WriteAllText($temp, ($Value | ConvertTo-Json -Depth 6 -Compress), [Text.UTF8Encoding]::new($false))
    if (Test-Path -LiteralPath $Path) {
      Assert-NextecProvisionPath -Path $Path
      [IO.File]::Replace($temp, $Path, [NullString]::Value)
    } else { [IO.File]::Move($temp, $Path) }
    Set-Acl -LiteralPath $Path -AclObject (New-NextecProvisionAcl)
  } finally { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
}

function Read-NextecProvisionJson {
  param([Parameter(Mandatory)][string]$Path)
  Assert-NextecProvisionPath -Path $Path
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
  Assert-NextecProvisionFileAcl -Path $Path
  $item = Get-Item -LiteralPath $Path -Force
  if ($item.Length -gt 4096) { throw 'invalid_input' }
  Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function ConvertFrom-NextecStrictBootstrapJson {
  param([Parameter(Mandatory)][string]$Json)
  if ([string]::IsNullOrWhiteSpace($Json) -or $Json.Length -gt 4096) { throw 'invalid_input' }
  try { $value = $Json | ConvertFrom-Json -ErrorAction Stop } catch { throw 'invalid_input' }
  if ($null -eq $value -or $value -isnot [pscustomobject]) { throw 'invalid_input' }
  $properties = @($value.PSObject.Properties)
  $names = @($properties | ForEach-Object { $_.Name })
  if ($properties.Count -ne 4 -or @('painel','id','uuid','bootstrap' | Where-Object { $_ -notin $names }).Count -ne 0) { throw 'invalid_input' }
  foreach ($property in $properties) { if ($property.Value -isnot [string]) { throw 'invalid_input' } }
  if ($value.painel -cne $script:NextecPainelFixo) { throw 'invalid_panel' }
  if ($value.id -notmatch '^\d{6,64}$' -or [string]::IsNullOrWhiteSpace($value.uuid) -or $value.uuid.Length -gt 128) { throw 'invalid_identity' }
  if ($value.bootstrap -notmatch '^[A-Za-z0-9_-]{32,128}$') { throw 'invalid_bootstrap' }
  [pscustomobject]@{ painel=$value.painel; id=$value.id; uuid=$value.uuid; bootstrap=$value.bootstrap }
}

function Read-NextecSecureInput {
  $secure = Read-Host 'Cole o JSON de autorização temporária' -AsSecureString
  $pointer = [IntPtr]::Zero
  try {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
  } finally {
    if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    if ($secure) { $secure.Dispose() }
  }
}

function New-NextecProposedToken {
  $bytes = New-Object byte[] 32
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
  [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}

function Write-NextecProvisionLog {
  param([Parameter(Mandatory)][string]$Code, [string]$Root = (Join-Path $env:ProgramData 'Nextec\Acesso'))
  if ($Code -notmatch '^(pending|complete|network_retry|manual_authorization_required|already_configured|identity_conflict|already_enrolled|registration_retry|invalid_input|invalid_panel|invalid_identity|invalid_bootstrap|protocol_error|unsafe_path|component_missing|self_enrolled|self_backoff|self_blocked|self_manual|peer_not_registered|rate_limited)$') { $Code = 'protocol_error' }
  $paths = Get-NextecProvisionPaths -Root $Root
  Assert-NextecProvisionPath -Path $paths.Root
  if (-not (Test-Path -LiteralPath $paths.Root -PathType Container)) { Initialize-NextecProvisionDirectory -Root $paths.Root }
  if (Test-Path -LiteralPath $paths.Log -PathType Leaf) { Assert-NextecProvisionFileAcl -Path $paths.Log }
  else {
    [IO.File]::WriteAllText($paths.Log, '', [Text.UTF8Encoding]::new($false))
    Set-Acl -LiteralPath $paths.Log -AclObject (New-NextecProvisionAcl)
  }
  Assert-NextecProvisionPath -Path $paths.Log
  if (-not (Test-Path -LiteralPath $paths.Log -PathType Leaf)) { throw 'unsafe_path' }
  Assert-NextecProvisionFileAcl -Path $paths.Log
  Add-Content -LiteralPath $paths.Log -Value ('{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $Code) -Encoding UTF8
}

function Import-NextecIdentityFunctions {
  if (Get-Module -Name NextecProvisionIdentity) { return }
  $agentScript = Join-Path $script:NextecProvisionScriptRoot 'Agente-Senha-Nextec.ps1'
  if (-not (Test-Path -LiteralPath $agentScript -PathType Leaf)) { throw 'component_missing' }
  $tokens = $null; $errors = $null
  $ast = [Management.Automation.Language.Parser]::ParseFile($agentScript, [ref]$tokens, [ref]$errors)
  if ($errors.Count) { throw 'component_missing' }
  $required = @('Get-NextecServiceExecutablePath','Get-NextecServiceProfileRoot','Get-NextecPeerId','Get-NextecInstalledClient')
  $definitions = @()
  foreach ($name in $required) {
    $definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    if (-not $definition) { throw 'component_missing' }
    $definitions += ('function {0} ' -f $name) + $definition.Body.Extent.Text
  }
  $moduleText = ($definitions -join "`n`n") + "`nExport-ModuleMember -Function $($required -join ',')"
  $module = New-Module -Name NextecProvisionIdentity -ScriptBlock ([scriptblock]::Create($moduleText))
  Import-Module $module -Global -ErrorAction Stop
}

function Get-NextecProvisionLocalId {
  param([object[]]$Services, [scriptblock]$PeerIdReader)
  Import-NextecIdentityFunctions
  $client = Get-NextecInstalledClient -Services $Services -PeerIdReader $PeerIdReader
  [string]$client.PeerId
}

function Read-NextecProvisionJournal {
  param([Parameter(Mandatory)][string]$Path)
  $journal = Read-NextecProvisionJson -Path $Path
  if (-not $journal) { return $null }
  $expected = @('painel','id','uuid','bootstrap_protected','proposed_token_protected','created_utc_ticks','state')
  $actual = @($journal.PSObject.Properties | ForEach-Object { $_.Name })
  if ($actual.Count -ne $expected.Count -or @($expected | Where-Object { $_ -notin $actual }).Count -ne 0) { throw 'protocol_error' }
  [pscustomobject]@{
    painel = [string]$journal.painel
    id = [string]$journal.id
    uuid = [string]$journal.uuid
    bootstrap = Unprotect-NextecProvisionValue ([string]$journal.bootstrap_protected)
    proposed_token = Unprotect-NextecProvisionValue ([string]$journal.proposed_token_protected)
    created_utc = [DateTime]::new([long]$journal.created_utc_ticks, [DateTimeKind]::Utc)
    state = [string]$journal.state
  }
}

function Save-NextecProvisionJournal {
  param([Parameter(Mandatory)]$Journal, [Parameter(Mandatory)][string]$Path)
  $stored = [pscustomobject]@{
    painel = $Journal.painel; id = $Journal.id; uuid = $Journal.uuid
    bootstrap_protected = Protect-NextecProvisionValue ([string]$Journal.bootstrap)
    proposed_token_protected = Protect-NextecProvisionValue ([string]$Journal.proposed_token)
    created_utc_ticks = ([DateTime]$Journal.created_utc).ToUniversalTime().Ticks
    state = [string]$Journal.state
  }
  Write-NextecProtectedJson -Path $Path -Value $stored
}

function Save-NextecAgentTokenConfig {
  param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Panel, [Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][string]$Token)
  $stored = [pscustomobject]@{ painel=$Panel; id=$Id; token=(Protect-NextecProvisionValue $Token) }
  Write-NextecProtectedJson -Path $Path -Value $stored
}

function Read-NextecAgentTokenConfig {
  param([Parameter(Mandatory)][string]$Path)
  $config = Read-NextecProvisionJson -Path $Path
  if (-not $config) { return $null }
  if ([string]$config.painel -cne $script:NextecPainelFixo -or [string]$config.id -notmatch '^\d{6,64}$' -or -not $config.token) { throw 'protocol_error' }
  [pscustomobject]@{ painel=[string]$config.painel; id=[string]$config.id; token=(Unprotect-NextecProvisionValue ([string]$config.token)) }
}

function Invoke-NextecBootstrapPost {
  param([Parameter(Mandatory)][string]$Panel, [Parameter(Mandatory)]$Body)
  $uri = ([Uri]::new($Panel.TrimEnd('/') + '/api/nextec/agent/bootstrap'))
  if ($uri.Scheme -cne 'https' -or $uri.Host -cne 'painel-remoto.nex.tec.br' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment) { throw 'invalid_panel' }
  Invoke-RestMethod -Uri $uri.AbsoluteUri -Method Post -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Compress) -TimeoutSec 30 -MaximumRedirection 0 -UserAgent 'Nextec-Connect-Agent/1'
}

function Invoke-NextecAgentRegistration {
  param([Parameter(Mandatory)][string]$ScriptPath)
  if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) { throw 'component_missing' }
  & $ScriptPath -Registrar
}

function ConvertFrom-NextecStrictEnrollmentJson {
  param([Parameter(Mandatory)][string]$Json)
  if ([string]::IsNullOrWhiteSpace($Json) -or $Json.Length -gt 4096) { throw 'invalid_input' }
  try { $value = $Json | ConvertFrom-Json -ErrorAction Stop } catch { throw 'invalid_input' }
  if ($null -eq $value -or $value -isnot [pscustomobject]) { throw 'invalid_input' }
  $properties = @($value.PSObject.Properties)
  $names = @($properties | ForEach-Object { $_.Name })
  if ($properties.Count -ne 3 -or @('v','painel','chave' | Where-Object { $_ -notin $names }).Count -ne 0) { throw 'invalid_input' }
  if ($value.v -isnot [int] -or [int]$value.v -ne 1) { throw 'invalid_input' }
  if ($value.painel -isnot [string] -or $value.chave -isnot [string]) { throw 'invalid_input' }
  if ($value.painel -cne $script:NextecPainelFixo) { throw 'invalid_panel' }
  if ($value.chave -notmatch '^[\x21-\x7E]{16,256}$') { throw 'invalid_input' }
  [pscustomobject]@{ painel=$value.painel; chave=$value.chave }
}

function Get-NextecMachineUuid {
  # Mesmo valor que o RustDesk 1.5.0 informa em heartbeat/sysinfo: base64 padrao (com
  # preenchimento) do MachineGuid, lido na visao de 64 bits do registro e sem espacos nas pontas.
  param([scriptblock]$GuidReader)
  if ($GuidReader) { $guid = [string](& $GuidReader) }
  else {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
      $key = $base.OpenSubKey('SOFTWARE\Microsoft\Cryptography')
      if (-not $key) { throw 'identity_conflict' }
      try { $guid = [string]$key.GetValue('MachineGuid') } finally { $key.Dispose() }
    } finally { $base.Dispose() }
  }
  $guid = $guid.Trim()
  if (-not $guid) { throw 'identity_conflict' }
  $uuid = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($guid))
  if ($uuid.Length -gt 128) { throw 'identity_conflict' }
  $uuid
}

function Get-NextecSha256Hex {
  param([Parameter(Mandatory)][string]$Value)
  $sha = [Security.Cryptography.SHA256]::Create()
  try { ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)) | ForEach-Object { $_.ToString('x2') }) -join '' } finally { $sha.Dispose() }
}

function Read-NextecSelfState {
  param([Parameter(Mandatory)][string]$Path)
  $raw = Read-NextecProvisionJson -Path $Path
  if (-not $raw) { return $null }
  $expected = @('state','chave_sha256','proposed_token_protected','attempts','next_try_utc_ticks','blocked_until_utc_ticks')
  $actual = @($raw.PSObject.Properties | ForEach-Object { $_.Name })
  if ($actual.Count -ne $expected.Count -or @($expected | Where-Object { $_ -notin $actual }).Count -ne 0) { throw 'protocol_error' }
  if ([string]$raw.state -notin @('self','manual','blocked')) { throw 'protocol_error' }
  $token = ''
  if ([string]$raw.proposed_token_protected) { $token = Unprotect-NextecProvisionValue ([string]$raw.proposed_token_protected) }
  [pscustomobject]@{
    state = [string]$raw.state
    chave_sha256 = [string]$raw.chave_sha256
    proposed_token = $token
    attempts = [int]$raw.attempts
    next_try_utc = [long]$raw.next_try_utc_ticks
    blocked_until_utc = [long]$raw.blocked_until_utc_ticks
  }
}

function Save-NextecSelfState {
  param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$State)
  $protected = ''
  if ([string]$State.proposed_token) { $protected = Protect-NextecProvisionValue ([string]$State.proposed_token) }
  Write-NextecProtectedJson -Path $Path -Value ([pscustomobject]@{
    state = [string]$State.state
    chave_sha256 = [string]$State.chave_sha256
    proposed_token_protected = $protected
    attempts = [int]$State.attempts
    next_try_utc_ticks = [long]$State.next_try_utc
    blocked_until_utc_ticks = [long]$State.blocked_until_utc
  })
}

function Invoke-NextecSelfEnrollPost {
  # Retorna sempre um objeto {status;token;state}; nunca lanca por status HTTP.
  # TestOrigin so e aceito para http://127.0.0.1:porta (servidor falso dos testes).
  param([Parameter(Mandatory)][string]$Panel, [Parameter(Mandatory)]$Body, [string]$TestOrigin)
  if ($TestOrigin) {
    if ($TestOrigin -notmatch '^http://127\.0\.0\.1:\d{2,5}$') { throw 'invalid_panel' }
    $target = $TestOrigin + '/api/nextec/agent/self-enroll'
  } else {
    $uri = [Uri]::new($Panel.TrimEnd('/') + '/api/nextec/agent/self-enroll')
    if ($uri.Scheme -cne 'https' -or $uri.Host -cne 'painel-remoto.nex.tec.br' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment) { throw 'invalid_panel' }
    $target = $uri.AbsoluteUri
  }
  try {
    $response = Invoke-RestMethod -Uri $target -Method Post -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Compress) -TimeoutSec 30 -MaximumRedirection 0 -UserAgent 'Nextec-Connect-Agent/1'
    return [pscustomobject]@{ status = 200; token = [string]$response.token; state = [string]$response.state }
  } catch {
    $status = 0
    if ($_.Exception.Response -and $_.Exception.Response.StatusCode) { $status = [int]$_.Exception.Response.StatusCode }
    return [pscustomobject]@{ status = $status; token = ''; state = '' }
  }
}

function Invoke-NextecSelfEnrollment {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$LocalId,
    [Parameter(Mandatory)][DateTime]$Now,
    [Parameter(Mandatory)][scriptblock]$PostSelfEnroll,
    [Parameter(Mandatory)][scriptblock]$NewToken,
    [Parameter(Mandatory)][scriptblock]$RegisterAgent,
    [Parameter(Mandatory)][scriptblock]$GetUuid
  )
  $paths = Get-NextecProvisionPaths -Root $Root
  Assert-NextecProvisionPath -Path $paths.Enroll
  Assert-NextecProvisionPath -Path $paths.SelfState
  if (-not (Test-Path -LiteralPath $paths.Enroll -PathType Leaf)) {
    Write-NextecProvisionLog 'manual_authorization_required' -Root $Root
    return 'manual_authorization_required'
  }
  Assert-NextecProvisionFileAcl -Path $paths.Enroll
  $enroll = ConvertFrom-NextecStrictEnrollmentJson -Json (Get-Content -LiteralPath $paths.Enroll -Raw -Encoding UTF8)
  $keyHash = Get-NextecSha256Hex -Value $enroll.chave
  $utc = $Now.ToUniversalTime()
  $state = Read-NextecSelfState -Path $paths.SelfState
  if ($state -and $state.chave_sha256 -cne $keyHash) { $state = $null }

  if ($state -and $state.state -eq 'manual') {
    Write-NextecProvisionLog 'self_manual' -Root $Root
    return 'manual_authorization_required'
  }
  if ($state -and $state.state -eq 'blocked' -and $utc.Ticks -lt $state.blocked_until_utc) {
    Write-NextecProvisionLog 'self_blocked' -Root $Root
    return 'blocked'
  }
  if ($state -and $state.state -eq 'self' -and $state.attempts -gt 0 -and $utc.Ticks -lt $state.next_try_utc) {
    Write-NextecProvisionLog 'self_backoff' -Root $Root
    return 'self_backoff'
  }

  if (-not $state -or -not $state.proposed_token) {
    $proposed = [string](& $NewToken)
    if ($proposed -notmatch '^[A-Za-z0-9_-]{43}$') { Write-NextecProvisionLog 'protocol_error' -Root $Root; throw 'protocol_error' }
    $state = [pscustomobject]@{ state='self'; chave_sha256=$keyHash; proposed_token=$proposed; attempts=0; next_try_utc=0L; blocked_until_utc=0L }
  } else {
    $state.state = 'self'
  }
  # O token proposto fica gravado antes da chamada: o replay reenvia o mesmo par id/uuid/token.
  Save-NextecSelfState -Path $paths.SelfState -State $state

  $uuid = [string](& $GetUuid)
  $result = & $PostSelfEnroll $enroll.painel @{ enroll_key=$enroll.chave; id=$LocalId; uuid=$uuid; proposed_token=$state.proposed_token }
  $status = 0
  if ($result -and $null -ne $result.status) { $status = [int]$result.status }

  if ($status -eq 200) {
    if ([string]$result.token -cne $state.proposed_token -or [string]$result.state -notin @('pending','assigned')) {
      Write-NextecProvisionLog 'protocol_error' -Root $Root; throw 'protocol_error'
    }
    if (Test-Path -LiteralPath $paths.AgentConfig -PathType Leaf) { Write-NextecProvisionLog 'already_enrolled' -Root $Root; throw 'already_enrolled' }
    Save-NextecAgentTokenConfig -Path $paths.AgentConfig -Panel $enroll.painel -Id $LocalId -Token $state.proposed_token
    try { & $RegisterAgent $paths.AgentScript }
    catch { Write-NextecProvisionLog 'registration_retry' -Root $Root; return 'registration_retry' }
    $state.proposed_token = ''; $state.attempts = 0; $state.next_try_utc = 0L; $state.blocked_until_utc = 0L
    Save-NextecSelfState -Path $paths.SelfState -State $state
    Write-NextecProvisionLog 'self_enrolled' -Root $Root
    return 'complete'
  }
  if ($status -eq 401 -or $status -eq 409) {
    $state.state = 'manual'
    Save-NextecSelfState -Path $paths.SelfState -State $state
    $manualCode = 'manual_authorization_required'
    if ($status -eq 409) { $manualCode = 'already_enrolled' }
    Write-NextecProvisionLog $manualCode -Root $Root
    return 'manual_authorization_required'
  }
  if ($status -eq 403) {
    $state.state = 'blocked'
    $state.blocked_until_utc = $utc.AddHours(24).Ticks
    Save-NextecSelfState -Path $paths.SelfState -State $state
    Write-NextecProvisionLog 'self_blocked' -Root $Root
    return 'blocked'
  }
  # 404, 429, 400, 5xx e falha de rede: nova tentativa com recuo (5, 10, 20, 40, 60 min), sem martelar.
  $state.attempts = [Math]::Min($state.attempts + 1, 10)
  $delay = [Math]::Min(3600, 300 * [Math]::Pow(2, $state.attempts - 1)) - 30
  $state.next_try_utc = $utc.AddSeconds($delay).Ticks
  Save-NextecSelfState -Path $paths.SelfState -State $state
  $retryCode = 'network_retry'
  if ($status -eq 404) { $retryCode = 'peer_not_registered' }
  elseif ($status -eq 429) { $retryCode = 'rate_limited' }
  elseif ($status -eq 400) { $retryCode = 'protocol_error' }
  Write-NextecProvisionLog $retryCode -Root $Root
  return 'network_retry'
}

function Invoke-NextecProvisioning {
  [CmdletBinding()]
  param(
    [string]$Root = (Join-Path $env:ProgramData 'Nextec\Acesso'),
    [scriptblock]$DiscoverId = { Get-NextecProvisionLocalId },
    [scriptblock]$PostBootstrap = { param($panel,$body) Invoke-NextecBootstrapPost -Panel $panel -Body $body },
    [scriptblock]$RegisterAgent = { param($path) Invoke-NextecAgentRegistration -ScriptPath $path },
    [DateTime]$Now = [DateTime]::UtcNow,
    [scriptblock]$NewToken = { New-NextecProposedToken },
    [scriptblock]$PostSelfEnroll = { param($panel,$body) Invoke-NextecSelfEnrollPost -Panel $panel -Body $body },
    [scriptblock]$GetUuid = { Get-NextecMachineUuid }
  )
  $paths = Get-NextecProvisionPaths -Root $Root
  Initialize-NextecProvisionDirectory -Root $Root
  foreach ($path in @($paths.Input,$paths.Journal,$paths.AgentConfig,$paths.Log)) { Assert-NextecProvisionPath -Path $path }

  $localId = [string](& $DiscoverId)
  if ($localId -notmatch '^\d{6,64}$') { Write-NextecProvisionLog 'identity_conflict' -Root $Root; throw 'identity_conflict' }

  $journal = Read-NextecProvisionJournal -Path $paths.Journal
  if ($journal -and $journal.state -notin @('pending','manual')) { throw 'protocol_error' }
  $input = $null
  if (Test-Path -LiteralPath $paths.Input -PathType Leaf) {
    $raw = Get-Content -LiteralPath $paths.Input -Raw -Encoding UTF8
    $input = ConvertFrom-NextecStrictBootstrapJson -Json $raw
    if ($journal) {
      if ($input.id -eq $journal.id -and $input.uuid -ceq $journal.uuid -and $input.bootstrap -ceq $journal.bootstrap) {
        Remove-Item -LiteralPath $paths.Input -Force
        $input = $null
      } else {
        $journalAge = ($Now.ToUniversalTime() - $journal.created_utc).TotalSeconds
        $journalTerminal = $journal.state -eq 'manual' -or $journalAge -ge 900 -or $journalAge -lt -60
        if ($journalTerminal) { $journal = $null }
        else { Write-NextecProvisionLog 'pending' -Root $Root; throw 'pending_authorization' }
      }
    }
  }

  if ($journal -and $journal.state -eq 'manual' -and -not $input) {
    Write-NextecProvisionLog 'manual_authorization_required' -Root $Root
    return 'manual_authorization_required'
  }

  if (-not $journal -and $input) {
    if ($input.id -cne $localId) { Write-NextecProvisionLog 'identity_conflict' -Root $Root; throw 'identity_conflict' }
    if (Test-Path -LiteralPath $paths.AgentConfig -PathType Leaf) { Write-NextecProvisionLog 'already_enrolled' -Root $Root; throw 'already_enrolled' }
    $proposed = [string](& $NewToken)
    if ($proposed -notmatch '^[A-Za-z0-9_-]{43}$') { Write-NextecProvisionLog 'protocol_error' -Root $Root; throw 'protocol_error' }
    $now = $Now.ToUniversalTime()
    $journal = [pscustomobject]@{
      painel=$input.painel; id=$input.id; uuid=$input.uuid; bootstrap=$input.bootstrap
      proposed_token=$proposed; created_utc=$now; state='pending'
    }
    Save-NextecProvisionJournal -Journal $journal -Path $paths.Journal
    Remove-Item -LiteralPath $paths.Input -Force
  }

  if (-not $journal) {
    if (Test-Path -LiteralPath $paths.AgentConfig -PathType Leaf) {
      $existing = Read-NextecAgentTokenConfig -Path $paths.AgentConfig
      if ($existing.id -cne $localId) { Write-NextecProvisionLog 'identity_conflict' -Root $Root; throw 'identity_conflict' }
      & $RegisterAgent $paths.AgentScript
      if (Test-Path -LiteralPath $paths.SelfState -PathType Leaf) {
        # Inscricao propria concluida mas interrompida antes de limpar o token proposto.
        $selfState = Read-NextecSelfState -Path $paths.SelfState
        if ($selfState -and $selfState.proposed_token -and $selfState.proposed_token -ceq $existing.token) {
          $selfState.proposed_token = ''; $selfState.attempts = 0; $selfState.next_try_utc = 0L; $selfState.blocked_until_utc = 0L
          Save-NextecSelfState -Path $paths.SelfState -State $selfState
        }
      }
      Write-NextecProvisionLog 'already_configured' -Root $Root
      return 'already_configured'
    }
    # Sem bootstrap.json e sem agente-senha.json: inscricao global (inscricao.json do MSI).
    return (Invoke-NextecSelfEnrollment -Root $Root -LocalId $localId -Now $Now -PostSelfEnroll $PostSelfEnroll -NewToken $NewToken -RegisterAgent $RegisterAgent -GetUuid $GetUuid)
  }

  if ($journal.painel -cne $script:NextecPainelFixo -or $journal.id -cne $localId) { Write-NextecProvisionLog 'identity_conflict' -Root $Root; throw 'identity_conflict' }
  $age = ($Now.ToUniversalTime() - $journal.created_utc).TotalSeconds
  if ($age -ge 900 -or $age -lt -60) {
    Remove-Item -LiteralPath $paths.Journal -Force
    Write-NextecProvisionLog 'manual_authorization_required' -Root $Root
    return 'manual_authorization_required'
  }

  if (Test-Path -LiteralPath $paths.AgentConfig -PathType Leaf) {
    $existing = Read-NextecAgentTokenConfig -Path $paths.AgentConfig
    if ($existing.id -cne $journal.id -or $existing.token -cne $journal.proposed_token) {
      Write-NextecProvisionLog 'already_enrolled' -Root $Root; throw 'already_enrolled'
    }
    & $RegisterAgent $paths.AgentScript
    Remove-Item -LiteralPath $paths.Journal -Force
    Write-NextecProvisionLog 'complete' -Root $Root
    return 'complete'
  }

  try {
    $response = & $PostBootstrap $journal.painel @{ bootstrap=$journal.bootstrap; id=$journal.id; uuid=$journal.uuid; proposed_token=$journal.proposed_token }
  } catch {
    $status = 0
    if ($_.Exception.Response -and $_.Exception.Response.StatusCode) { $status = [int]$_.Exception.Response.StatusCode }
    if ($status -eq 401 -or $status -eq 409) {
      Remove-Item -LiteralPath $paths.Journal -Force
      $code = if ($status -eq 409) { 'already_enrolled' } else { 'manual_authorization_required' }
      Write-NextecProvisionLog $code -Root $Root
      throw $code
    }
    Write-NextecProvisionLog 'network_retry' -Root $Root
    return 'network_retry'
  }

  if (-not $response -or [string]$response.token -cne $journal.proposed_token) {
    Write-NextecProvisionLog 'protocol_error' -Root $Root; throw 'protocol_error'
  }

  Save-NextecAgentTokenConfig -Path $paths.AgentConfig -Panel $journal.painel -Id $journal.id -Token $journal.proposed_token
  try { & $RegisterAgent $paths.AgentScript }
  catch { Write-NextecProvisionLog 'registration_retry' -Root $Root; return 'registration_retry' }
  Remove-Item -LiteralPath $paths.Journal -Force
  Write-NextecProvisionLog 'complete' -Root $Root
  return 'complete'
}

function Receive-NextecBootstrapAuthorization {
  param([string]$Root = (Join-Path $env:ProgramData 'Nextec\Acesso'), [scriptblock]$ReadInput = { Read-NextecSecureInput }, [scriptblock]$DiscoverId = { Get-NextecProvisionLocalId })
  Initialize-NextecProvisionDirectory -Root $Root
  $paths = Get-NextecProvisionPaths -Root $Root
  if (Test-Path -LiteralPath $paths.Input) { throw 'pending_authorization' }
  $payload = ConvertFrom-NextecStrictBootstrapJson -Json ([string](& $ReadInput))
  $localId = [string](& $DiscoverId)
  if ($payload.id -cne $localId) { throw 'identity_conflict' }
  Write-NextecProtectedJson -Path $paths.Input -Value $payload
  Assert-NextecProvisionPath -Path $paths.Input
  Set-Acl -LiteralPath $paths.Input -AclObject (New-NextecProvisionAcl)
  'Autorização temporária gravada em local protegido; o coordenador tentará o cadastro por até 15 minutos.'
}

if ($Receber) { Receive-NextecBootstrapAuthorization -Root $PastaDados; return }
if ($Executar) {
  try {
    Assert-NextecProvisionFileAcl -Path $PSCommandPath
    Invoke-NextecProvisioning -Root $PastaDados | Out-Null
  }
  catch { Write-NextecProvisionLog ([string]$_.Exception.Message) -Root $PastaDados; exit 1 }
  return
}
Write-Host 'Use -Receber para inserir a autorização temporária pela sessão remota ou -Executar (coordenador SYSTEM).'
