#requires -version 5.1
[CmdletBinding()]
param(
  [switch]$Executar,
  [switch]$Receber,
  [switch]$SubstituirAgenteAntigo,
  [string]$PastaDados = (Join-Path $env:ProgramData 'Nextec\Acesso')
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Security

$script:NextecPainelFixo = 'https://painel-remoto.nex.tec.br'
$script:NextecTaskName = 'Nextec Acesso - Cadastro de agente'
$script:NextecProvisionScriptRoot = $PSScriptRoot

# Painel configuravel: o host vem do inscricao.json local (ou do marcador), nunca da rede.
function ConvertTo-NextecPainelUrl {
  param([string]$Url)
  if ([string]::IsNullOrWhiteSpace($Url) -or $Url.Length -gt 253 -or $Url -match '[\s\@]') { return $null }
  $u = $null
  if (-not [Uri]::TryCreate($Url.Trim(), [UriKind]::Absolute, [ref]$u)) { return $null }
  if ($u.Scheme -cne 'https' -or $u.UserInfo -or $u.Query -or $u.Fragment -or $u.AbsolutePath -cne '/' -or -not $u.IsDefaultPort) { return $null }
  if ($u.HostNameType -ne [UriHostNameType]::Dns) { return $null }
  if ($u.Host -cnotmatch '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$') { return $null }
  return ('https://' + $u.Host)
}

function Get-NextecPainelConfigurado {
  param(
    [string]$Root = (Join-Path $env:ProgramData 'Nextec\Acesso'),
    [string]$Padrao = 'https://painel-remoto.nex.tec.br',
    [string]$RegistryKey = 'HKLM:\SOFTWARE\Nextec\Agente'
  )
  foreach ($nome in @('inscricao.json', 'nextec-marker.json')) {
    $arquivo = Join-Path $Root $nome
    try {
      if (-not (Test-Path -LiteralPath $arquivo -PathType Leaf)) { continue }
      if ((Get-Item -LiteralPath $arquivo).Length -gt 4096) { continue }
      $valor = [IO.File]::ReadAllText($arquivo, [Text.Encoding]::UTF8).TrimStart([char]0xFEFF) | ConvertFrom-Json
      $painel = ConvertTo-NextecPainelUrl ([string]$valor.painel)
      if ($painel) { $script:NextecPainelOrigem = $arquivo; return $painel }
    } catch { }
  }
  # Marcador do MSI no registro (chave Nextec Agente em HKLM, valor Painel): o painel do build persiste mesmo sem inscricao.json.
  try {
    $reg = Get-ItemProperty -LiteralPath $RegistryKey -ErrorAction Stop
    $painel = ConvertTo-NextecPainelUrl ([string]$reg.Painel)
    if ($painel) { $script:NextecPainelOrigem = $RegistryKey; return $painel }
  } catch { }
  $script:NextecPainelOrigem = 'padrao'
  return $Padrao
}

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
    Invite = Join-Path $Root 'convite.json'
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

# Codigos que os scripts do agente podem gravar em provisionamento-agente.log. UNICA fonte: o gravador
# (Write-NextecProvisionLog) e o teste de guarda (nextec/testes/codigos-log-provisionamento.test.mjs, que tambem confere os
# codigos lidos pelo Ativar-Nextec-<ID>.cmd) consomem esta lista. Codigo novo entra aqui, em nenhum outro lugar.
function Get-NextecProvisionLogCodes {
  @(
    'pending', 'complete', 'network_retry', 'manual_authorization_required', 'already_configured', 'identity_conflict',
    'already_enrolled', 'registration_retry', 'invalid_input', 'invalid_panel', 'invalid_identity', 'invalid_bootstrap',
    'protocol_error', 'unsafe_path', 'component_missing', 'self_enrolled', 'self_backoff', 'self_blocked', 'self_manual',
    'peer_not_registered', 'rate_limited', 'painel_padrao', 'agent_config_replaced', 'agent_config_unreadable',
    'identity_changed', 'bootstrap_discarded', 'old_agent_replaced', 'old_agent_kept', 'panel_unreachable',
    'pending_other_panel', 'pending_expired', 'pending_authorization',
    'old_agent_replace_formato_antigo', 'old_agent_replace_outro_id', 'old_agent_replace_token_recusado',
    'old_agent_replace_agente_parado', 'agent_repaired', 'invite_claimed', 'invite_retry', 'invite_discarded', 'unknown_code'
  )
}

# Codigo fora da lista nunca derruba o fluxo: vira "unknown_code [texto]". O texto e so diagnostico: caracteres seguros,
# no maximo 48, e qualquer sequencia longa (parece token ou segredo) e trocada por [redigido]. Entre colchetes para o
# Ativar-Nextec-<ID>.cmd (que le o codigo no FIM da linha) nunca confundir o texto com um codigo de falha.
function ConvertTo-NextecProvisionLogLine {
  param([string]$Code)
  if ($null -eq $Code) { $Code = '' }
  $Code = $Code.Trim()
  if ($Code -cin (Get-NextecProvisionLogCodes)) { return $Code }
  $text = [regex]::Replace($Code, '[A-Za-z0-9_-]{24,}', 'redigido')
  $text = [regex]::Replace($text, '[^A-Za-z0-9_. :-]', '?')
  if ($text.Length -gt 48) { $text = $text.Substring(0, 48) }
  return ('unknown_code [' + $text + ']')
}

function Write-NextecProvisionLog {
  param([Parameter(Mandatory)][string]$Code, [string]$Root = (Join-Path $env:ProgramData 'Nextec\Acesso'))
  $Code = ConvertTo-NextecProvisionLogLine -Code $Code
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
  Add-Content -LiteralPath $paths.Log -Value ('{0} {1}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture), $Code) -Encoding UTF8
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

# A credencial so vale para o painel em que foi cadastrada. Com painel configurado (inscricao.json, marcador ou registro),
# uma credencial gravada para OUTRO painel nao e reaproveitada: iria ao painel novo e seria recusada (401) ou, pior, exposta.
# Sem configuracao (painel padrao por compatibilidade) nada e comparado.
function Test-NextecCredentialPanelCompatible {
  param([string]$StoredPanel)
  if ($script:NextecPainelOrigem -ceq 'padrao') { return $true }
  $stored = ConvertTo-NextecPainelUrl $StoredPanel
  return [bool]($stored -and $stored -ceq (ConvertTo-NextecPainelUrl ([string]$script:NextecPainelFixo)))
}

function Read-NextecAgentTokenConfig {
  param([Parameter(Mandatory)][string]$Path)
  $config = Read-NextecProvisionJson -Path $Path
  if (-not $config) { return $null }
  if (-not (ConvertTo-NextecPainelUrl ([string]$config.painel)) -or [string]$config.id -notmatch '^\d{6,64}$' -or -not $config.token) { throw 'protocol_error' }
  # troca de dominio: o painel valido e o configurado hoje, nao o gravado no cadastro
  [pscustomobject]@{ painel=[string]$script:NextecPainelFixo; painel_gravado=[string]$config.painel; id=[string]$config.id; token=(Unprotect-NextecProvisionValue ([string]$config.token)) }
}

function Invoke-NextecBootstrapPost {
  param([Parameter(Mandatory)][string]$Panel, [Parameter(Mandatory)]$Body)
  $uri = ([Uri]::new($Panel.TrimEnd('/') + '/api/nextec/agent/bootstrap'))
  if ($uri.Scheme -cne 'https' -or $uri.Host -cne ([Uri]$script:NextecPainelFixo).Host -or $uri.UserInfo -or $uri.Query -or $uri.Fragment) { throw 'invalid_panel' }
  Invoke-RestMethod -Uri $uri.AbsoluteUri -Method Post -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Compress) -TimeoutSec 30 -MaximumRedirection 0 -UserAgent 'Nextec-Connect-Agent/1'
}

# Credencial local que nao serve mais (ID do RustDesk mudou, arquivo ilegivel ou trocada por autorizacao nova):
# vai para agente-senha.json.anterior e a inscricao recomeca. A maquina nunca fica parada pedindo acao manual.
function Move-NextecAgentConfigAside {
  param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Reason)
  $paths = Get-NextecProvisionPaths -Root $Root
  Assert-NextecProvisionPath -Path $paths.AgentConfig
  if (Test-Path -LiteralPath $paths.AgentConfig -PathType Leaf) {
    $aside = $paths.AgentConfig + '.anterior'
    Assert-NextecProvisionPath -Path $aside
    Remove-Item -LiteralPath $aside -Force -ErrorAction SilentlyContinue
    Move-Item -LiteralPath $paths.AgentConfig -Destination $aside -Force
    try { Set-Acl -LiteralPath $aside -AclObject (New-NextecProvisionAcl) } catch { }
  }
  Remove-Item -LiteralPath $paths.SelfState -Force -ErrorAction SilentlyContinue
  Write-NextecProvisionLog $Reason -Root $Root
}

# Intervalos das tarefas do agente: a FONTE UNICA e a funcao Get-NextecAgentIntervals de Agente-Senha-Nextec.ps1. Aqui o
# arquivo e lido sem executar nada (so os literais do hashtable retornado). Se a funcao nao existe ou os valores sao
# invalidos (script de agente de uma versao anterior, que sempre registrou 5 minutos), vale o legado de 5 minutos.
function Get-NextecConfiguredAgentIntervals {
  param([Parameter(Mandatory)][string]$AgentScript)
  $legacy = [pscustomobject]@{ PasswordMinutes = 5; CoordinatorMinutes = 5; Source = 'legado' }
  try {
    if (-not (Test-Path -LiteralPath $AgentScript -PathType Leaf)) { return $legacy }
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($AgentScript, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { return $legacy }
    $function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-NextecAgentIntervals' }, $true)
    if (-not $function) { return $legacy }
    $table = $function.Body.Find({ param($node) $node -is [Management.Automation.Language.HashtableAst] }, $true)
    if (-not $table) { return $legacy }
    $values = $table.SafeGetValue()
    $password = [int]$values['PasswordMinutes']
    $coordinator = [int]$values['CoordinatorMinutes']
    if ($password -lt 1 -or $password -gt 60 -or $coordinator -lt 1 -or $coordinator -gt 60) { return $legacy }
    return [pscustomobject]@{ PasswordMinutes = $password; CoordinatorMinutes = $coordinator; Source = 'agente' }
  } catch { return $legacy }
}

# A tarefa de senha so e (re)registrada quando falta ou aponta para outro script: recriar a tarefa
# a cada execucao gera ruido em EDR e no log do Agendador de Tarefas.
function Test-NextecAgentTaskReady {
  param([Parameter(Mandatory)][string]$Root)
  try {
    $task = Get-ScheduledTask -TaskName 'Nextec Acesso - Senha' -ErrorAction Stop
    return (Test-NextecAgentTaskShape -Task $task -Root $Root)
  } catch { return $false }
}

# Nome de conta (localizado ou nao) para SID. Aceita o proprio SID. Vazio quando nao resolve.
function ConvertTo-NextecAccountSid {
  param([string]$Account)
  $name = ([string]$Account).Trim()
  if (-not $name) { return '' }
  if ($name -match '^(?i)S-1-\d+(-\d+)+$') { return $name.ToUpperInvariant() }
  try { return (New-Object Security.Principal.NTAccount($name)).Translate([Security.Principal.SecurityIdentifier]).Value }
  catch { return '' }
}

# Tarefa correta = conta SYSTEM (S-1-5-18) com RunLevel Highest, uma unica acao com o powershell.exe 5.1 do sistema,
# "-File" apontando para o script do agente em $Root, "-Executar", gatilho periodico de no maximo PasswordMinutes (o valor
# de Get-NextecAgentIntervals no script do agente em $Root) e habilitada.
# Qualquer divergencia (tarefa antiga de 5 minutos, outro caminho, outra conta, gatilho sem repeticao) faz o coordenador
# registrar de novo: e assim que as tarefas ja instaladas migram para o intervalo atual.
function Test-NextecAgentTaskShape {
  param([Parameter(Mandatory)]$Task, [Parameter(Mandatory)][string]$Root)
  if ([string]$Task.State -eq 'Disabled') { return $false }
  # A conta e identificada pelo SID: o nome e localizado (pt-BR: SISTEMA, AUTORIDADE NT\SISTEMA) e nunca e comparado.
  if ((ConvertTo-NextecAccountSid -Account ([string]$Task.Principal.UserId)) -cne 'S-1-5-18') { return $false }
  if ([string]$Task.Principal.RunLevel -ine 'Highest') { return $false }
  $actions = @($Task.Actions)
  if ($actions.Count -ne 1) { return $false }
  $action = $actions[0]
  $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  if (([string]$action.Execute).Trim('"') -ine $powershell) { return $false }
  $script = Join-Path $Root 'Agente-Senha-Nextec.ps1'
  $limit = [TimeSpan]::FromMinutes([int](Get-NextecConfiguredAgentIntervals -AgentScript $script).PasswordMinutes)
  $arguments = [string]$action.Arguments
  if ($arguments -notmatch ('(?i)(^|\s)-File\s+"' + [regex]::Escape($script) + '"(\s|$)')) { return $false }
  if ($arguments -notmatch '(?i)(^|\s)-Executar(\s|$)') { return $false }
  $triggers = @($Task.Triggers)
  if ($triggers.Count -lt 1) { return $false }
  foreach ($trigger in $triggers) {
    if ($trigger.PSObject.Properties['Enabled'] -and $trigger.Enabled -eq $false) { return $false }
    $interval = ''
    if ($trigger.Repetition) { $interval = [string]$trigger.Repetition.Interval }
    if (-not $interval) { return $false }
    try { $span = [Xml.XmlConvert]::ToTimeSpan($interval) } catch { return $false }
    if ($span -le [TimeSpan]::Zero -or $span -gt $limit) { return $false }
  }
  return $true
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
  # 'painel' (host normalizado em que o estado foi criado) e opcional: estados gravados antes dele continuam validos.
  $painelGravado = ''
  if ($actual -contains 'painel') { $painelGravado = [string]$raw.painel; $actual = @($actual | Where-Object { $_ -cne 'painel' }) }
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
    painel = $painelGravado
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
    painel = [string]$State.painel
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
    if ($uri.Scheme -cne 'https' -or $uri.Host -cne ([Uri]$script:NextecPainelFixo).Host -or $uri.UserInfo -or $uri.Query -or $uri.Fragment) { throw 'invalid_panel' }
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
  # Estado de inscricao criado contra outro painel (troca de dominio): descarta e recomeca no painel atual.
  # Sem 'painel' gravado (estado antigo) vale o limite de tempo abaixo, nunca uma espera sem fim.
  $enrollPanel = ConvertTo-NextecPainelUrl ([string]$enroll.painel)
  if ($state -and $state.painel) {
    if ((ConvertTo-NextecPainelUrl $state.painel) -cne $enrollPanel) { Write-NextecProvisionLog 'pending_other_panel' -Root $Root; $state = $null }
  }

  if ($state -and $state.state -eq 'manual' -and $utc.Ticks -lt $state.next_try_utc) {
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
    $state = [pscustomobject]@{ state='self'; chave_sha256=$keyHash; proposed_token=$proposed; attempts=0; next_try_utc=0L; blocked_until_utc=0L; painel=$enrollPanel }
  } else {
    $state.state = 'self'
    $state.painel = $enrollPanel
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
    # chave girada, maquina removida ou pendencia antiga: resolvido no painel, a maquina tenta sozinha de novo em 6 h
    $state.state = 'manual'
    $state.next_try_utc = $utc.AddHours(6).Ticks
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

function Invoke-NextecInvitePost {
  # Retorna o status HTTP (0 em falha de rede); nunca lanca por status. TestOrigin so aceita http://127.0.0.1:porta.
  param([Parameter(Mandatory)][string]$Panel, [Parameter(Mandatory)]$Body, [string]$TestOrigin)
  if ($TestOrigin) {
    if ($TestOrigin -notmatch '^http://127\.0\.0\.1:\d{2,5}$') { throw 'invalid_panel' }
    $target = $TestOrigin + '/api/nextec/agent/invite'
  } else {
    $uri = [Uri]::new($Panel.TrimEnd('/') + '/api/nextec/agent/invite')
    if ($uri.Scheme -cne 'https' -or $uri.Host -cne ([Uri]$script:NextecPainelFixo).Host -or $uri.UserInfo -or $uri.Query -or $uri.Fragment) { throw 'invalid_panel' }
    $target = $uri.AbsoluteUri
  }
  try {
    Invoke-RestMethod -Uri $target -Method Post -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Compress) -TimeoutSec 30 -MaximumRedirection 0 -UserAgent 'Nextec-Connect-Agent/1' | Out-Null
    return 200
  } catch {
    if ($_.Exception.Response -and $_.Exception.Response.StatusCode) { return [int]$_.Exception.Response.StatusCode }
    return 0
  }
}

# Convite de instalacao (convite.json, gravado pelo coordenador quando o MSI veio de um link do painel): depois da inscricao
# a maquina apresenta o codigo com a propria credencial e o painel a atribui ao cliente do convite. Nunca derruba o fluxo:
# resposta definitiva (aceito, invalido, vencido, conflito) apaga o arquivo; falha temporaria tenta de novo no proximo ciclo,
# ate 3 dias, depois a maquina fica como Pendente.
function Invoke-NextecInviteClaim {
  param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][scriptblock]$PostInvite,
    [DateTime]$Now = [DateTime]::UtcNow
  )
  $paths = Get-NextecProvisionPaths -Root $Root
  try {
    if (-not (Test-Path -LiteralPath $paths.Invite -PathType Leaf)) { return 'none' }
    $invite = Read-NextecProvisionJson -Path $paths.Invite
    $code = [string]$invite.codigo
    $created = [DateTime]::MinValue
    $valid = $code -cmatch '^[A-HJ-NP-Z2-9]{20}$' -and [DateTime]::TryParse([string]$invite.criado_utc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$created)
    $age = ($Now.ToUniversalTime() - $created.ToUniversalTime()).TotalHours
    if (-not $valid -or $age -ge 72 -or $age -lt -1) {
      Remove-Item -LiteralPath $paths.Invite -Force -ErrorAction SilentlyContinue
      Write-NextecProvisionLog 'invite_discarded' -Root $Root
      return 'discarded'
    }
    if (-not (Test-Path -LiteralPath $paths.AgentConfig -PathType Leaf)) { return 'waiting' }
    $config = Read-NextecAgentTokenConfig -Path $paths.AgentConfig
    if (-not $config) { return 'waiting' }
    $status = [int](& $PostInvite $config.painel @{ id=$config.id; token=$config.token; code=$code })
    if ($status -eq 200) {
      Remove-Item -LiteralPath $paths.Invite -Force -ErrorAction SilentlyContinue
      Write-NextecProvisionLog 'invite_claimed' -Root $Root
      return 'claimed'
    }
    if ($status -in @(403, 409)) {
      Remove-Item -LiteralPath $paths.Invite -Force -ErrorAction SilentlyContinue
      Write-NextecProvisionLog 'invite_discarded' -Root $Root
      return 'discarded'
    }
    Write-NextecProvisionLog 'invite_retry' -Root $Root
    return 'retry'
  } catch {
    try { Write-NextecProvisionLog 'invite_retry' -Root $Root } catch { }
    return 'retry'
  }
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
    [scriptblock]$GetUuid = { Get-NextecMachineUuid },
    [scriptblock]$AgentTaskReady = { param($root) Test-NextecAgentTaskReady -Root $root },
    [scriptblock]$PostInvite = { param($panel,$body) Invoke-NextecInvitePost -Panel $panel -Body $body }
  )
  $paths = Get-NextecProvisionPaths -Root $Root
  Initialize-NextecProvisionDirectory -Root $Root
  foreach ($path in @($paths.Input,$paths.Journal,$paths.AgentConfig,$paths.Log)) { Assert-NextecProvisionPath -Path $path }

  $localId = [string](& $DiscoverId)
  if ($localId -notmatch '^\d{6,64}$') { Write-NextecProvisionLog 'identity_conflict' -Root $Root; throw 'identity_conflict' }

  $journal = Read-NextecProvisionJournal -Path $paths.Journal
  if ($journal -and $journal.state -notin @('pending','manual')) { throw 'protocol_error' }
  # Pendente de OUTRO painel (troca de dominio) nunca bloqueia a inscricao no painel atual: o journal e descartado
  # (so o codigo vai ao log, sem segredos) e o fluxo segue como maquina sem pendencia.
  if ($journal) {
    $journalPanel = ConvertTo-NextecPainelUrl $journal.painel
    if (-not $journalPanel -or $journalPanel -cne (ConvertTo-NextecPainelUrl ([string]$script:NextecPainelFixo))) {
      Remove-Item -LiteralPath $paths.Journal -Force -ErrorAction SilentlyContinue
      Write-NextecProvisionLog 'pending_other_panel' -Root $Root
      $journal = $null
    }
  }
  # Pendente do mesmo painel espera ate expirar (autorizacao: 15 min; recusa manual: 24 h) e depois reinscreve.
  if ($journal -and -not (Test-Path -LiteralPath $paths.Input -PathType Leaf)) {
    $pendingAge = ($Now.ToUniversalTime() - $journal.created_utc).TotalSeconds
    $pendingLimit = 900
    if ($journal.state -eq 'manual') { $pendingLimit = 86400 }
    if ($pendingAge -ge $pendingLimit -or $pendingAge -lt -60) {
      Remove-Item -LiteralPath $paths.Journal -Force -ErrorAction SilentlyContinue
      Write-NextecProvisionLog 'pending_expired' -Root $Root
      $journal = $null
    }
  }
  $input = $null
  if (Test-Path -LiteralPath $paths.Input -PathType Leaf) {
    $raw = Get-Content -LiteralPath $paths.Input -Raw -Encoding UTF8
    try { $input = ConvertFrom-NextecStrictBootstrapJson -Json $raw }
    catch {
      # autorizacao ilegivel ou de outro painel: descarta para nao bloquear as proximas
      Remove-Item -LiteralPath $paths.Input -Force -ErrorAction SilentlyContinue
      Write-NextecProvisionLog 'bootstrap_discarded' -Root $Root
      throw
    }
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
    if ($input.id -cne $localId) {
      Remove-Item -LiteralPath $paths.Input -Force -ErrorAction SilentlyContinue
      Write-NextecProvisionLog 'identity_conflict' -Root $Root; throw 'identity_conflict'
    }
    # Uma credencial local existente (ex.: agente antigo com 401) so e aposentada DEPOIS de o servidor confirmar o cadastro novo:
    # autorizacao vencida, recusada ou falha de rede nao pode deixar a maquina sem a configuracao que ja tinha.
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
      # credencial ilegivel (formato antigo, permissao adulterada) ou de outro ID: sai do caminho e a inscricao recomeca
      $existing = $null
      try { $existing = Read-NextecAgentTokenConfig -Path $paths.AgentConfig } catch { $existing = $null }
      if (-not $existing) { Move-NextecAgentConfigAside -Root $Root -Reason 'agent_config_unreadable' }
      elseif ($existing.id -cne $localId) { Move-NextecAgentConfigAside -Root $Root -Reason 'identity_changed' }
      elseif (-not (Test-NextecCredentialPanelCompatible -StoredPanel $existing.painel_gravado)) { Move-NextecAgentConfigAside -Root $Root -Reason 'panel_changed' }
    }
    if (Test-Path -LiteralPath $paths.AgentConfig -PathType Leaf) {
      if (-not (& $AgentTaskReady $Root)) { & $RegisterAgent $paths.AgentScript }
      if (Test-Path -LiteralPath $paths.SelfState -PathType Leaf) {
        # Inscricao propria concluida mas interrompida antes de limpar o token proposto.
        $selfState = Read-NextecSelfState -Path $paths.SelfState
        if ($selfState -and $selfState.proposed_token -and $selfState.proposed_token -ceq $existing.token) {
          $selfState.proposed_token = ''; $selfState.attempts = 0; $selfState.next_try_utc = 0L; $selfState.blocked_until_utc = 0L
          Save-NextecSelfState -Path $paths.SelfState -State $selfState
        }
      }
      Write-NextecProvisionLog 'already_configured' -Root $Root
      Invoke-NextecInviteClaim -Root $Root -PostInvite $PostInvite -Now $Now | Out-Null
      return 'already_configured'
    }
    # Sem bootstrap.json e sem agente-senha.json: inscricao global (inscricao.json do MSI).
    $enrollResult = Invoke-NextecSelfEnrollment -Root $Root -LocalId $localId -Now $Now -PostSelfEnroll $PostSelfEnroll -NewToken $NewToken -RegisterAgent $RegisterAgent -GetUuid $GetUuid
    if ($enrollResult -eq 'complete') { Invoke-NextecInviteClaim -Root $Root -PostInvite $PostInvite -Now $Now | Out-Null }
    return $enrollResult
  }

  if ($journal.painel -cne $script:NextecPainelFixo -or $journal.id -cne $localId) { Write-NextecProvisionLog 'identity_conflict' -Root $Root; throw 'identity_conflict' }
  $age = ($Now.ToUniversalTime() - $journal.created_utc).TotalSeconds
  if ($age -ge 900 -or $age -lt -60) {
    Remove-Item -LiteralPath $paths.Journal -Force
    Write-NextecProvisionLog 'manual_authorization_required' -Root $Root
    return 'manual_authorization_required'
  }

  if (Test-Path -LiteralPath $paths.AgentConfig -PathType Leaf) {
    $existing = $null
    try { $existing = Read-NextecAgentTokenConfig -Path $paths.AgentConfig } catch { $existing = $null }
    # Repeticao depois de gravar o token proposto: so falta registrar a tarefa. Qualquer outra credencial (antiga, morta
    # ou ilegivel) fica onde esta ate o servidor aceitar o cadastro novo, logo abaixo.
    if ($existing -and $existing.id -ceq $journal.id -and $existing.token -ceq $journal.proposed_token) {
      & $RegisterAgent $paths.AgentScript
      Remove-Item -LiteralPath $paths.Journal -Force
      Write-NextecProvisionLog 'complete' -Root $Root
      return 'complete'
    }
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

  # O servidor aceitou: agora sim a credencial antiga (se havia) vai para .anterior e a nova passa a valer.
  if (Test-Path -LiteralPath $paths.AgentConfig -PathType Leaf) { Move-NextecAgentConfigAside -Root $Root -Reason 'agent_config_replaced' }
  Save-NextecAgentTokenConfig -Path $paths.AgentConfig -Panel $journal.painel -Id $journal.id -Token $journal.proposed_token
  try { & $RegisterAgent $paths.AgentScript }
  catch { Write-NextecProvisionLog 'registration_retry' -Root $Root; return 'registration_retry' }
  Remove-Item -LiteralPath $paths.Journal -Force
  Write-NextecProvisionLog 'complete' -Root $Root
  return 'complete'
}

function Invoke-NextecAgentTokenProbe {
  # Pergunta ao painel se ele ainda reconhece o token local: /agent/sync com probe:true, que so confere o token e NAO
  # conta como consulta (nao grava last_sync_at nem last_seen_at). Assim a sondagem nunca faz um agente parado parecer
  # ativo e o painel continua aceitando a autorizacao de reinstalacao. Devolve status HTTP (0 = sem resposta) e o
  # agent_state calculado pelo painel ('' em painel anterior). Nunca lanca e nunca devolve nem registra o token.
  param([Parameter(Mandatory)][string]$Panel, [Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][string]$Token)
  try {
    # So o painel configurado, em HTTPS na raiz (ConvertTo-NextecPainelUrl), recebe o token.
    $base = ConvertTo-NextecPainelUrl $Panel
    if (-not $base -or ([Uri]$base).Host -cne ([Uri]$script:NextecPainelFixo).Host) { return [pscustomobject]@{ status = 0; agent_state = '' } }
    $uri = [Uri]::new($base.TrimEnd('/') + '/api/nextec/agent/sync')
    $r = Invoke-RestMethod -Uri $uri.AbsoluteUri -Method Post -ContentType 'application/json' -Body (@{ id = $Id; token = $Token; probe = $true } | ConvertTo-Json -Compress) -TimeoutSec 30 -MaximumRedirection 0 -UserAgent 'Nextec-Connect-Agent/1'
    $state = ''
    if ($r -and $r.PSObject.Properties['agent_state']) { $state = [string]$r.agent_state }
    return [pscustomobject]@{ status = 200; agent_state = $state }
  } catch {
    $status = 0
    try { if ($_.Exception.Response -and $_.Exception.Response.StatusCode) { $status = [int]$_.Exception.Response.StatusCode } } catch { $status = 0 }
    return [pscustomobject]@{ status = $status; agent_state = '' }
  }
}

# Instalacao local do agente: script presente e tarefa de senha no formato esperado.
function Test-NextecAgentInstallHealthy {
  param([Parameter(Mandatory)][string]$Root, [scriptblock]$AgentTaskReady = { param($root) Test-NextecAgentTaskReady -Root $root })
  $paths = Get-NextecProvisionPaths -Root $Root
  if (-not (Test-Path -LiteralPath $paths.AgentScript -PathType Leaf)) { return $false }
  try { return [bool](& $AgentTaskReady $Root) } catch { return $false }
}

function Move-NextecProvisionFileAside {
  # Backup protegido (CreateNew + ACL SYSTEM/Administradores) e so entao sai do lugar. O conteudo nunca e apagado:
  # se ja existe uma copia identica (<nome>.antigo-*), o original so deixa o caminho.
  param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Stamp)
  Assert-NextecProvisionPath -Path $Path
  $bytes = [IO.File]::ReadAllBytes($Path)
  $folder = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path))
  $leaf = [IO.Path]::GetFileName($Path)
  foreach ($candidate in @(Get-ChildItem -LiteralPath $folder -Filter ($leaf + '.antigo-*') -File -ErrorAction SilentlyContinue)) {
    if ($candidate.Length -ne $bytes.Length) { continue }
    $same = [IO.File]::ReadAllBytes($candidate.FullName)
    $equal = $true
    for ($i = 0; $i -lt $bytes.Length; $i++) { if ($same[$i] -ne $bytes[$i]) { $equal = $false; break } }
    if ($equal) { Remove-Item -LiteralPath $Path -Force; return $candidate.FullName }
  }
  $dest = $Path + '.antigo-' + $Stamp
  $n = 1
  while (Test-Path -LiteralPath $dest) { $n++; $dest = $Path + '.antigo-' + $Stamp + '-' + $n }
  Assert-NextecProvisionPath -Path $dest
  $stream = [IO.File]::Open($dest, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  $stream.Dispose()
  Set-Acl -LiteralPath $dest -AclObject (New-NextecProvisionAcl)
  [IO.File]::WriteAllBytes($dest, $bytes)
  Remove-Item -LiteralPath $Path -Force
  return $dest
}

# Agente antigo ou quebrado (so com -SubstituirAgenteAntigo, passado pelo Ativar-Nextec-<ID>.cmd baixado do painel por um
# administrador autenticado). Decide entre reparar a instalacao local e pedir a substituicao do cadastro:
#   - credencial valida (sondagem 200) e instalacao local quebrada (tarefa ausente ou invalida, script faltando): REPARA,
#     registrando a tarefa com a credencial que ja existe. Sem cadastro novo e sem recusar ('repaired').
#   - credencial ilegivel, de outro ID, recusada (401) ou painel dizendo "parado": substituicao pelo bootstrap.
#   - credencial valida, instalacao boa e agente ativo (ou painel sem agent_state): mantem, already_enrolled.
#   - painel sem resposta: panel_unreachable, nada muda.
# A credencial antiga NUNCA sai do lugar aqui: Invoke-NextecProvisioning so a troca (com backup em .anterior) depois de
# o painel aceitar o token novo. Recusa, autorizacao vencida ou falha de rede deixam a maquina com o que ja tinha.
function Resolve-NextecOldAgent {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$LocalId,
    [scriptblock]$Probe = { param($panel, $id, $token) Invoke-NextecAgentTokenProbe -Panel $panel -Id $id -Token $token },
    [scriptblock]$AgentTaskReady = { param($root) Test-NextecAgentTaskReady -Root $root },
    [scriptblock]$RegisterAgent = { param($path) Invoke-NextecAgentRegistration -ScriptPath $path },
    [DateTime]$Now = [DateTime]::UtcNow
  )
  $paths = Get-NextecProvisionPaths -Root $Root
  if (-not (Test-Path -LiteralPath $paths.AgentConfig -PathType Leaf)) { return 'none' }
  $reason = ''
  $config = $null
  try { $config = Read-NextecAgentTokenConfig -Path $paths.AgentConfig } catch { $reason = 'formato_antigo' }
  if (-not $reason) {
    if ($config.id -cne $LocalId) { $reason = 'outro_id' }
    else {
      $status = 0; $state = ''
      try {
        $answer = & $Probe $config.painel $config.id $config.token
        if ($answer -and $answer.PSObject.Properties['status']) { $status = [int]$answer.status; $state = [string]$answer.agent_state }
        else { $status = [int]$answer }
      } catch { $status = 0 }
      if ($status -eq 401) { $reason = 'token_recusado' }
      elseif ($status -eq 0) { Write-NextecProvisionLog 'panel_unreachable' -Root $Root; throw 'panel_unreachable' }
      elseif ($status -eq 200 -and -not (Test-NextecAgentInstallHealthy -Root $Root -AgentTaskReady $AgentTaskReady)) {
        try { & $RegisterAgent $paths.AgentScript }
        catch { Write-NextecProvisionLog 'registration_retry' -Root $Root; throw 'registration_retry' }
        Write-NextecProvisionLog 'agent_repaired' -Root $Root
        return 'repaired'
      }
      elseif ($status -eq 200 -and $state -ceq 'parado') { $reason = 'agente_parado' }
      else { Write-NextecProvisionLog 'old_agent_kept' -Root $Root; throw 'already_enrolled' }
    }
  }
  # Pendencia antiga (journal) sairia na frente da autorizacao nova: vai para backup protegido. A credencial fica.
  if (Test-Path -LiteralPath $paths.Journal -PathType Leaf) {
    [void](Move-NextecProvisionFileAside -Path $paths.Journal -Stamp ($Now.ToUniversalTime().ToString('yyyyMMdd-HHmmss', [Globalization.CultureInfo]::InvariantCulture)))
  }
  Write-NextecProvisionLog ('old_agent_replace_' + $reason) -Root $Root
  return $reason
}

function Receive-NextecBootstrapAuthorization {
  param(
    [string]$Root = (Join-Path $env:ProgramData 'Nextec\Acesso'),
    [scriptblock]$ReadInput = { Read-NextecSecureInput },
    [scriptblock]$DiscoverId = { Get-NextecProvisionLocalId },
    [switch]$SubstituirAgenteAntigo,
    [scriptblock]$ProbeToken,
    [scriptblock]$AgentTaskReady,
    [scriptblock]$RegisterAgent
  )
  Initialize-NextecProvisionDirectory -Root $Root
  $paths = Get-NextecProvisionPaths -Root $Root
  if (Test-Path -LiteralPath $paths.Input) { throw 'pending_authorization' }
  $payload = ConvertFrom-NextecStrictBootstrapJson -Json ([string](& $ReadInput))
  $localId = [string](& $DiscoverId)
  if ($payload.id -cne $localId) { throw 'identity_conflict' }
  if ($SubstituirAgenteAntigo) {
    # Depois de validar formato, painel e ID: um arquivo invalido nunca mexe no cadastro existente.
    $resolveArgs = @{ Root = $Root; LocalId = $localId }
    if ($ProbeToken) { $resolveArgs.Probe = $ProbeToken }
    if ($AgentTaskReady) { $resolveArgs.AgentTaskReady = $AgentTaskReady }
    if ($RegisterAgent) { $resolveArgs.RegisterAgent = $RegisterAgent }
    if ((Resolve-NextecOldAgent @resolveArgs) -eq 'repaired') {
      # Credencial valida: a instalacao local foi refeita com ela. A autorizacao nao e usada (nenhum cadastro novo).
      return 'Agente reparado com o cadastro existente; nenhuma autorização nova foi necessária.'
    }
  }
  Write-NextecProtectedJson -Path $paths.Input -Value $payload
  Assert-NextecProvisionPath -Path $paths.Input
  Set-Acl -LiteralPath $paths.Input -AclObject (New-NextecProvisionAcl)
  'Autorização temporária gravada em local protegido; o coordenador tentará o cadastro por até 15 minutos.'
}

# O host do painel vem de inscricao.json (ou do marcador); sem arquivo, cai no padrao antigo com aviso.
$script:NextecPainelFixo = Get-NextecPainelConfigurado -Root $PastaDados -Padrao $script:NextecPainelFixo
if ($Receber) { Receive-NextecBootstrapAuthorization -Root $PastaDados -SubstituirAgenteAntigo:$SubstituirAgenteAntigo; return }
if ($Executar) {
  try {
    if ($script:NextecPainelOrigem -ceq 'padrao') { Write-NextecProvisionLog 'painel_padrao' -Root $PastaDados }
    Assert-NextecProvisionFileAcl -Path $PSCommandPath
    Invoke-NextecProvisioning -Root $PastaDados | Out-Null
  }
  catch { Write-NextecProvisionLog ([string]$_.Exception.Message) -Root $PastaDados; exit 1 }
  return
}
Write-Host 'Use -Receber para inserir a autorização temporária pela sessão remota ou -Executar (coordenador SYSTEM).'
