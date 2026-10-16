#requires -version 5.1
[CmdletBinding()]
param(
  [switch]$Registrar,
  [switch]$Executar,
  [switch]$Receber,
  [switch]$Remover,
  [switch]$SubstituirAgenteAntigo,
  [string]$ArquivoAutorizacao,
  [string]$Origem,
  [string]$PastaDados = (Join-Path $env:ProgramData 'Nextec\Acesso')
)

$ErrorActionPreference = 'Stop'
$script:TaskName = 'Nextec Acesso - Cadastro de agente'

function New-NextecCoordinatorAcl {
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

# Convite de instalacao: o MSI baixado do painel leva o codigo no nome (<app>-<CODIGO>.msi). O instalador entrega o caminho
# do proprio arquivo em -Origem; so o codigo (20 caracteres do alfabeto do painel) sai do nome e fica em convite.json, que o
# provisionador apresenta ao painel depois da inscricao. Nome sem codigo (ou renomeado) nao grava nada: a maquina entra como Pendente.
function Get-NextecInviteCode {
  param([string]$Origem)
  if (-not $Origem) { return '' }
  $name = [IO.Path]::GetFileName($Origem.Trim())
  $m = [regex]::Match($name, '-([A-HJ-NP-Z2-9]{20})(?: \(\d+\))?\.msi$', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
  if (-not $m.Success) { return '' }
  return $m.Groups[1].Value.ToUpperInvariant()
}

function Save-NextecInvite {
  param([Parameter(Mandatory)][string]$Root, [string]$Origem)
  $code = Get-NextecInviteCode -Origem $Origem
  $path = Join-Path $Root 'convite.json'
  Assert-NextecCoordinatorPath -Path $path
  if (-not $code) { return $false }
  $temp = Join-Path $Root ('.convite-' + [Guid]::NewGuid().ToString('N') + '.tmp')
  try {
    $stream = [IO.File]::Open($temp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $stream.Dispose()
    Set-Acl -LiteralPath $temp -AclObject (New-NextecCoordinatorAcl)
    $json = [pscustomobject]@{ codigo = $code; criado_utc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture) } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($temp, $json, [Text.UTF8Encoding]::new($false))
    if (Test-Path -LiteralPath $path) { [IO.File]::Replace($temp, $path, [NullString]::Value) } else { [IO.File]::Move($temp, $path) }
    Set-Acl -LiteralPath $path -AclObject (New-NextecCoordinatorAcl)
  } finally { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
  return $true
}

function Assert-NextecCoordinatorPath {
  param([Parameter(Mandatory)][string]$Path)
  $current = [IO.Path]::GetFullPath($Path)
  while ($current) {
    if (Test-Path -LiteralPath $current) {
      if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'unsafe_path' }
    }
    $parent = [IO.Path]::GetDirectoryName($current.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar))
    if (-not $parent -or $parent -eq $current) { break }
    $current = $parent
  }
}

function Assert-NextecCoordinatorFileAcl {
  param([Parameter(Mandatory)][string]$Path)
  Assert-NextecCoordinatorPath -Path $Path
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

# Host normalizado (minusculo, https, porta padrao, sem credencial) do campo "painel" de um JSON local; $null se nao der para ler.
function ConvertTo-NextecCoordinatorPanelHost {
  param([string]$Url)
  if ([string]::IsNullOrWhiteSpace($Url) -or $Url.Length -gt 253) { return $null }
  $uri = $null
  if (-not [Uri]::TryCreate($Url.Trim(), [UriKind]::Absolute, [ref]$uri)) { return $null }
  if ($uri.Scheme -cne 'https' -or $uri.UserInfo -or -not $uri.IsDefaultPort -or $uri.HostNameType -ne [UriHostNameType]::Dns) { return $null }
  return $uri.Host.ToLowerInvariant()
}

function Get-NextecCoordinatorFilePanel {
  param([Parameter(Mandatory)][string]$Path)
  try {
    if ((Get-Item -LiteralPath $Path -Force).Length -gt 4096) { return $null }
    $value = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8).TrimStart([char]0xFEFF) | ConvertFrom-Json
    return (ConvertTo-NextecCoordinatorPanelHost ([string]$value.painel))
  } catch { return $null }
}

# Intervalo do coordenador: FONTE UNICA em Get-NextecAgentIntervals (Agente-Senha-Nextec.ps1), lido sem executar nada.
# Sem a funcao (agente de versao anterior) ou com valor invalido, vale o legado de 5 minutos.
function Get-NextecCoordinatorMinutes {
  param([Parameter(Mandatory)][string]$AgentScript)
  try {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($AgentScript, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { return 5 }
    $function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-NextecAgentIntervals' }, $true)
    if (-not $function) { return 5 }
    $table = $function.Body.Find({ param($node) $node -is [Management.Automation.Language.HashtableAst] }, $true)
    if (-not $table) { return 5 }
    $minutes = [int]($table.SafeGetValue())['CoordinatorMinutes']
    if ($minutes -lt 1 -or $minutes -gt 60) { return 5 }
    return $minutes
  } catch { return 5 }
}

function Register-NextecCoordinatorTask {
  param([string]$Root = (Join-Path $env:ProgramData 'Nextec\Acesso'), [string]$SourceRoot = $PSScriptRoot)
  Assert-NextecCoordinatorPath -Path $Root

  $coordinatorSource = Join-Path $SourceRoot 'Coordenar-Agente-Nextec.ps1'
  $workerSource = Join-Path $SourceRoot 'Provisionar-Agente-Nextec.ps1'
  $agentSource = Join-Path $SourceRoot 'Agente-Senha-Nextec.ps1'
  $coordinatorPath = Join-Path $Root 'Coordenar-Agente-Nextec.ps1'
  $workerPath = Join-Path $Root 'Provisionar-Agente-Nextec.ps1'
  $agentPath = Join-Path $Root 'Agente-Senha-Nextec.ps1'
  $pairs = @(
    [pscustomobject]@{ Source=$coordinatorSource; Destination=$coordinatorPath }
    [pscustomobject]@{ Source=$workerSource; Destination=$workerPath }
    [pscustomobject]@{ Source=$agentSource; Destination=$agentPath }
  )
  # inscricao.json (MSI global) e opcional: so entra na copia quando existe na origem.
  $enrollSource = Join-Path $SourceRoot 'inscricao.json'
  $enrollPath = Join-Path $Root 'inscricao.json'
  $hasEnrollment = Test-Path -LiteralPath $enrollSource -PathType Leaf
  if ($hasEnrollment) {
    Assert-NextecCoordinatorPath -Path $enrollSource
    if ((Get-Item -LiteralPath $enrollSource -Force).Length -gt 4096) { throw 'invalid_input' }
    $pairs = @($pairs) + @([pscustomobject]@{ Source=$enrollSource; Destination=$enrollPath })
  }
  # nextec-marker.json (opcional): leva o painel do build ({v,app,upgrade_code,painel}) para a pasta de dados, de onde os
  # scripts leem o endereco mesmo quando o instalador saiu sem chave de inscricao.
  $markerSource = Join-Path $SourceRoot 'nextec-marker.json'
  $markerPath = Join-Path $Root 'nextec-marker.json'
  if (Test-Path -LiteralPath $markerSource -PathType Leaf) {
    Assert-NextecCoordinatorPath -Path $markerSource
    if ((Get-Item -LiteralPath $markerSource -Force).Length -gt 4096) { throw 'invalid_input' }
    $pairs = @($pairs) + @([pscustomobject]@{ Source=$markerSource; Destination=$markerPath })
  }
  # Politica da inscricao e da credencial anteriores (comparacao pelo host normalizado do painel, nunca pelo texto):
  #  - instalador COM inscricao.json: substitui a anterior; se o painel mudou, o estado da inscricao e a credencial do painel antigo saem;
  #  - instalador SEM inscricao.json: a anterior e a credencial so ficam se forem do MESMO painel do novo instalador (marcador);
  #    se o painel e outro, saem; se o instalador nao diz qual e o painel, ficam (nada a comparar) e isso e anotado no log.
  # O log leva so decisoes e nomes de arquivo, nunca chave nem token.
  $script:NextecDecisions = @()
  $newPanel = $null
  if ($hasEnrollment) { $newPanel = Get-NextecCoordinatorFilePanel -Path $enrollSource }
  if (-not $newPanel -and (Test-Path -LiteralPath $markerSource -PathType Leaf)) { $newPanel = Get-NextecCoordinatorFilePanel -Path $markerSource }
  $oldEnrollPanel = $null
  if (Test-Path -LiteralPath $enrollPath -PathType Leaf) { $oldEnrollPanel = Get-NextecCoordinatorFilePanel -Path $enrollPath }
  $script:NextecStaleEnrollment = $false
  $script:NextecStaleEnrollmentState = $false
  $script:NextecStaleCredential = $false
  $oldEnrollExists = Test-Path -LiteralPath $enrollPath -PathType Leaf
  if ($hasEnrollment) {
    if ($oldEnrollExists -and $oldEnrollPanel -and $newPanel -and $oldEnrollPanel -cne $newPanel) {
      $script:NextecStaleEnrollmentState = $true
      $script:NextecDecisions += 'inscricao: substituida por outra de painel diferente; estado anterior removido'
    } elseif ($oldEnrollExists) { $script:NextecDecisions += 'inscricao: substituida pela do instalador (mesmo painel)' }
    else { $script:NextecDecisions += 'inscricao: nova, trazida pelo instalador' }
  } elseif ($oldEnrollExists) {
    if ($newPanel -and $oldEnrollPanel -and $oldEnrollPanel -cne $newPanel) {
      $script:NextecStaleEnrollment = $true
      $script:NextecDecisions += 'inscricao: removida (instalador sem inscricao e de outro painel)'
    } elseif ($newPanel -and $oldEnrollPanel) { $script:NextecDecisions += 'inscricao: mantida (mesmo painel do instalador)' }
    else { $script:NextecDecisions += 'inscricao: mantida (instalador nao informa o painel ou arquivo anterior sem painel legivel)' }
  } else { $script:NextecDecisions += 'inscricao: nenhuma' }
  $credentialPath = Join-Path $Root 'agente-senha.json'
  if ($newPanel -and (Test-Path -LiteralPath $credentialPath -PathType Leaf)) {
    $credentialPanel = Get-NextecCoordinatorFilePanel -Path $credentialPath
    if ($credentialPanel -and $credentialPanel -cne $newPanel) {
      $script:NextecStaleCredential = $true
      $script:NextecDecisions += 'credencial: guardada em .anterior (cadastrada em outro painel)'
    } elseif ($credentialPanel) { $script:NextecDecisions += 'credencial: mantida (mesmo painel)' }
  }
  foreach ($pair in $pairs) {
    $source = $pair.Source
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'component_missing' }
    Assert-NextecCoordinatorPath -Path $source
    Assert-NextecCoordinatorPath -Path $pair.Destination
    if (Test-Path -LiteralPath $pair.Destination) {
      if (-not (Test-Path -LiteralPath $pair.Destination -PathType Leaf)) { throw 'unsafe_path' }
      # Arquivo de instalacao anterior com permissao fora do padrao (agente antigo, antivirus, restauracao):
      # nao e reaproveitado, e apagado e copiado de novo. Apagar remove so o link, nunca o alvo de um hardlink.
      try { Assert-NextecCoordinatorFileAcl -Path $pair.Destination }
      catch { Remove-Item -LiteralPath $pair.Destination -Force; $script:NextecReplacedFiles += [IO.Path]::GetFileName($pair.Destination) }
    }
  }

  New-Item -ItemType Directory -Path $Root -Force | Out-Null
  Set-Acl -LiteralPath $Root -AclObject (New-NextecCoordinatorAcl -Directory)
  if ($script:NextecStaleEnrollment) {
    Remove-Item -LiteralPath $enrollPath -Force -ErrorAction SilentlyContinue
    $script:NextecReplacedFiles += 'inscricao.json (de outro painel)'
  }
  if ($script:NextecStaleEnrollment -or $script:NextecStaleEnrollmentState -or $script:NextecStaleCredential) {
    Remove-Item -LiteralPath (Join-Path $Root 'inscricao-estado.json') -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath (Join-Path $Root 'agente-senha.falhas') -Force -ErrorAction SilentlyContinue
  }
  if ($script:NextecStaleCredential) {
    Assert-NextecCoordinatorPath -Path ($credentialPath + '.anterior')
    Remove-Item -LiteralPath ($credentialPath + '.anterior') -Force -ErrorAction SilentlyContinue
    Move-Item -LiteralPath $credentialPath -Destination ($credentialPath + '.anterior') -Force
    $script:NextecReplacedFiles += 'agente-senha.json (de outro painel)'
  }
  foreach ($pair in $pairs) {
    $source = [IO.Path]::GetFullPath($pair.Source)
    $destination = [IO.Path]::GetFullPath($pair.Destination)
    if ($source -ine $destination) {
      Assert-NextecCoordinatorPath -Path $destination
      Copy-Item -LiteralPath $source -Destination $destination -Force
    }
    Assert-NextecCoordinatorPath -Path $destination
    Set-Acl -LiteralPath $destination -AclObject (New-NextecCoordinatorAcl)
  }

  $powershellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $argument = '-NoProfile -ExecutionPolicy Bypass -File "' + $coordinatorPath + '" -Executar'
  $action = New-ScheduledTaskAction -Execute $powershellExe -Argument $argument
  $coordinatorMinutes = Get-NextecCoordinatorMinutes -AgentScript $agentSource
  $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $coordinatorMinutes) -RepetitionDuration (New-TimeSpan -Days 3650)
  $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 4) -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName 'Nextec Acesso - Cadastro de agente' -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
  ('Coordenador registrado para verificar autorizações pendentes a cada {0} min.' -f $coordinatorMinutes)
}

# Log do coordenador (sem segredos: so codigos e nomes de arquivo). A instalacao e o ciclo periodico
# nunca falham em silencio.
function Write-NextecCoordinatorLog {
  param([string]$Root, [string]$Message)
  try {
    if (-not $Root -or -not (Test-Path -LiteralPath $Root -PathType Container)) { return }
    $log = Join-Path $Root 'coordenador.log'
    Assert-NextecCoordinatorPath -Path $log
    if ((Test-Path -LiteralPath $log -PathType Leaf) -and (Get-Item -LiteralPath $log -Force).Length -gt 262144) {
      Move-Item -LiteralPath $log -Destination ($log + '.antigo') -Force
    }
    $line = '{0} {1}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture), ([string]$Message -replace '[\r\n]+', ' ')
    [IO.File]::AppendAllText($log, $line + "`r`n", [Text.UTF8Encoding]::new($false))
  } catch { }
}

function Remove-NextecCoordinatorTasks {
  # Remove only Nextec's two scheduled tasks. Config, identity, and token files
  # intentionally remain available for recovery or an explicit later install.
  foreach ($taskName in @('Nextec Acesso - Cadastro de agente', 'Nextec Acesso - Senha')) {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
  }
  'Tarefas de cadastro e senha removidas; configuração e identidade preservadas.'
}

function Select-NextecBootstrapFilePath {
  param([Parameter(Mandatory)][scriptblock]$PickFile)
  $selected = [string](& $PickFile)
  if ([string]::IsNullOrWhiteSpace($selected)) { return $null }
  $selected = [IO.Path]::GetFullPath($selected)
  if ([IO.Path]::GetFileName($selected) -cne 'bootstrap.json' -or -not (Test-Path -LiteralPath $selected -PathType Leaf)) {
    throw 'invalid_authorization_file'
  }
  if ((Get-Item -LiteralPath $selected -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'unsafe_path' }
  return $selected
}

function Show-NextecBootstrapFileDialog {
  if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne [Threading.ApartmentState]::STA) { throw 'interactive_sta_required' }
  Add-Type -AssemblyName System.Windows.Forms
  $dialog = New-Object System.Windows.Forms.OpenFileDialog
  $dialog.Title = 'Selecione o arquivo bootstrap.json enviado pelo administrador'
  $dialog.Filter = 'Autorização Nextec (bootstrap.json)|bootstrap.json|Arquivos JSON (*.json)|*.json'
  $dialog.FileName = 'bootstrap.json'
  $dialog.InitialDirectory = $env:USERPROFILE
  $dialog.Multiselect = $false
  $dialog.CheckFileExists = $true
  try {
    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return $dialog.FileName }
    return $null
  } finally { $dialog.Dispose() }
}

# Sem -ArquivoAutorizacao abre o seletor de arquivo (uso manual). Com ele, usa exatamente aquele bootstrap.json,
# sem nenhum diálogo (usado pelo Ativar-Nextec-<ID>.cmd baixado do painel). As mesmas checagens de nome e de link
# simbólico valem nos dois caminhos.
function Get-NextecBootstrapSelection {
  param([string]$Path)
  if ($Path) {
    $fixed = $Path
    return Select-NextecBootstrapFilePath -PickFile { $fixed }.GetNewClosure()
  }
  return Select-NextecBootstrapFilePath -PickFile { Show-NextecBootstrapFileDialog }
}

function Assert-NextecInteractiveAdministrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'administrator_required' }
}

function Invoke-NextecCoordinator {
  param([string]$Root = (Join-Path $env:ProgramData 'Nextec\Acesso'), [Parameter(Mandatory)][string]$CoordinatorPath)
  Assert-NextecCoordinatorFileAcl -Path $CoordinatorPath
  $worker = Join-Path $Root 'Provisionar-Agente-Nextec.ps1'
  if (-not (Test-Path -LiteralPath $worker -PathType Leaf)) { throw 'component_missing' }
  Assert-NextecCoordinatorPath -Path $worker
  Assert-NextecCoordinatorFileAcl -Path $worker
  & $worker -Executar
}

# -SubstituirAgenteAntigo so existe junto de -Receber: e o Ativar-Nextec-<ID>.cmd (arquivo baixado do painel por um
# administrador autenticado, valido por 15 minutos e amarrado ao ID/uuid) que autoriza trocar um agente antigo ou quebrado.
if ($SubstituirAgenteAntigo -and -not $Receber) { throw 'Use -SubstituirAgenteAntigo somente com -Receber.' }
if ($Remover) {
  if ($Registrar -or $Executar -or $Receber) { throw 'Escolha somente -Remover.' }
  Remove-NextecCoordinatorTasks
  return
}
if ($Registrar) {
  $script:NextecReplacedFiles = @()
  try {
    Register-NextecCoordinatorTask -Root $PastaDados -SourceRoot $PSScriptRoot
    if ($Origem -and (Save-NextecInvite -Root $PastaDados -Origem $Origem)) { Write-NextecCoordinatorLog -Root $PastaDados -Message 'registrar: convite de instalacao registrado' }
    if ($script:NextecReplacedFiles.Count) { Write-NextecCoordinatorLog -Root $PastaDados -Message ('registrar: arquivos antigos substituidos: ' + ($script:NextecReplacedFiles -join ', ')) }
    foreach ($decision in @($script:NextecDecisions)) { Write-NextecCoordinatorLog -Root $PastaDados -Message ('registrar: ' + $decision) }
    Write-NextecCoordinatorLog -Root $PastaDados -Message 'registrar: ok'
  } catch {
    Write-NextecCoordinatorLog -Root $PastaDados -Message ('registrar: ERRO ' + $_.Exception.Message)
    throw
  }
  return
}
if ($Receber) {
  if ($Registrar -or $Executar) { throw 'Escolha somente -Receber.' }
  Assert-NextecInteractiveAdministrator
  Assert-NextecCoordinatorFileAcl -Path $PSCommandPath
  $worker = Join-Path $PastaDados 'Provisionar-Agente-Nextec.ps1'
  if (-not (Test-Path -LiteralPath $worker -PathType Leaf)) { throw 'component_missing' }
  Assert-NextecCoordinatorFileAcl -Path $worker
  $selectedPath = Get-NextecBootstrapSelection -Path $ArquivoAutorizacao
  if (-not $selectedPath) { return }

  # Load the provisioner's tested functions at script scope so the shared
  # strict parser, DPAPI storage, ACLs, and real ID discovery remain canonical.
  $script:NextecPainelFixo = 'https://painel-remoto.nex.tec.br'
  $script:NextecProvisionScriptRoot = Split-Path -Parent $worker
  Add-Type -AssemblyName System.Security
  $tokens = $null; $errors = $null
  $workerAst = [Management.Automation.Language.Parser]::ParseFile($worker, [ref]$tokens, [ref]$errors)
  if ($errors.Count) { throw 'component_missing' }
  foreach ($definition in $workerAst.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
    . ([scriptblock]::Create($definition.Extent.Text))
  }
  # host do painel: inscricao.json/marcador instalado; sem arquivo, o padrao antigo (compat)
  $script:NextecPainelFixo = Get-NextecPainelConfigurado -Root $PastaDados -Padrao $script:NextecPainelFixo
  $readSelectedFile = { Get-Content -LiteralPath $selectedPath -Raw -Encoding UTF8 }
  try { Receive-NextecBootstrapAuthorization -Root $PastaDados -ReadInput $readSelectedFile -SubstituirAgenteAntigo:$SubstituirAgenteAntigo }
  finally {
    # o arquivo entregue ao coordenador é de uso único: sai do disco mesmo se a ativação falhar
    if ($ArquivoAutorizacao) { Remove-Item -LiteralPath $selectedPath -Force -ErrorAction SilentlyContinue }
  }
  # cadastra agora, sem esperar o próximo ciclo do coordenador
  try { Start-ScheduledTask -TaskName $script:TaskName -ErrorAction Stop } catch { Write-NextecCoordinatorLog -Root $PastaDados -Message ('receber: tarefa nao iniciada ' + $_.Exception.Message) }
  return
}
if ($Executar) {
  try { Invoke-NextecCoordinator -Root $PastaDados -CoordinatorPath $PSCommandPath | Out-Null }
  catch { Write-NextecCoordinatorLog -Root $PastaDados -Message ('executar: ERRO ' + $_.Exception.Message); exit 1 }
  return
}
Write-Host 'Use -Registrar na instalação, -Receber para selecionar o bootstrap.json como administrador, -Executar (tarefa SYSTEM) ou -Remover no uninstall.'
