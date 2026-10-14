#requires -version 5.1
[CmdletBinding()]
param(
  [switch]$Registrar,
  [switch]$Executar,
  [switch]$Receber,
  [switch]$Remover,
  [string]$ArquivoAutorizacao,
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
  # Politica da inscricao anterior: instalador sem inscricao.json nao herda a de uma instalacao anterior que aponte para
  # OUTRO painel (migracao de painel ou de cliente); se o painel e o mesmo, ou o instalador nao diz qual e, ela e mantida.
  $script:NextecStaleEnrollment = $false
  if (-not $hasEnrollment -and (Test-Path -LiteralPath $enrollPath -PathType Leaf)) {
    try {
      $newPanel = ''
      if (Test-Path -LiteralPath $markerSource -PathType Leaf) {
        $newPanel = [string]([IO.File]::ReadAllText($markerSource, [Text.Encoding]::UTF8).TrimStart([char]0xFEFF) | ConvertFrom-Json).painel
      }
      $oldPanel = [string]([IO.File]::ReadAllText($enrollPath, [Text.Encoding]::UTF8).TrimStart([char]0xFEFF) | ConvertFrom-Json).painel
      if ($newPanel -and $oldPanel -and ($newPanel.TrimEnd('/') -ine $oldPanel.TrimEnd('/'))) { $script:NextecStaleEnrollment = $true }
    } catch { $script:NextecStaleEnrollment = $false }
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
    Remove-Item -LiteralPath (Join-Path $Root 'inscricao-estado.json') -Force -ErrorAction SilentlyContinue
    $script:NextecReplacedFiles += 'inscricao.json (de outro painel)'
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
  $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)
  $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 4) -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName 'Nextec Acesso - Cadastro de agente' -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
  'Coordenador registrado para verificar autorizações pendentes a cada 5 minutos.'
}

# Log do coordenador (sem segredos: so codigos e nomes de arquivo). A instalacao e o ciclo de 5 minutos
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
    $line = '{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), ([string]$Message -replace '[\r\n]+', ' ')
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

if ($Remover) {
  if ($Registrar -or $Executar -or $Receber) { throw 'Escolha somente -Remover.' }
  Remove-NextecCoordinatorTasks
  return
}
if ($Registrar) {
  $script:NextecReplacedFiles = @()
  try {
    Register-NextecCoordinatorTask -Root $PastaDados -SourceRoot $PSScriptRoot
    if ($script:NextecReplacedFiles.Count) { Write-NextecCoordinatorLog -Root $PastaDados -Message ('registrar: arquivos antigos substituidos: ' + ($script:NextecReplacedFiles -join ', ')) }
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
  try { Receive-NextecBootstrapAuthorization -Root $PastaDados -ReadInput $readSelectedFile }
  finally {
    # o arquivo entregue ao coordenador é de uso único: sai do disco mesmo se a ativação falhar
    if ($ArquivoAutorizacao) { Remove-Item -LiteralPath $selectedPath -Force -ErrorAction SilentlyContinue }
  }
  # cadastra agora, sem esperar o próximo ciclo de 5 minutos
  try { Start-ScheduledTask -TaskName $script:TaskName -ErrorAction Stop } catch { Write-NextecCoordinatorLog -Root $PastaDados -Message ('receber: tarefa nao iniciada ' + $_.Exception.Message) }
  return
}
if ($Executar) {
  try { Invoke-NextecCoordinator -Root $PastaDados -CoordinatorPath $PSCommandPath | Out-Null }
  catch { Write-NextecCoordinatorLog -Root $PastaDados -Message ('executar: ERRO ' + $_.Exception.Message); exit 1 }
  return
}
Write-Host 'Use -Registrar na instalação, -Receber para selecionar o bootstrap.json como administrador, -Executar (tarefa SYSTEM) ou -Remover no uninstall.'
