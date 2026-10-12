#requires -version 5.1
[CmdletBinding()]
param(
  [switch]$Registrar,
  [switch]$Executar,
  [switch]$Receber,
  [switch]$Remover,
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
  foreach ($pair in $pairs) {
    $source = $pair.Source
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'component_missing' }
    Assert-NextecCoordinatorPath -Path $source
    Assert-NextecCoordinatorPath -Path $pair.Destination
    if (Test-Path -LiteralPath $pair.Destination) {
      if (-not (Test-Path -LiteralPath $pair.Destination -PathType Leaf)) { throw 'unsafe_path' }
      Assert-NextecCoordinatorFileAcl -Path $pair.Destination
    }
  }

  New-Item -ItemType Directory -Path $Root -Force | Out-Null
  Set-Acl -LiteralPath $Root -AclObject (New-NextecCoordinatorAcl -Directory)
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
if ($Registrar) { Register-NextecCoordinatorTask -Root $PastaDados -SourceRoot $PSScriptRoot; return }
if ($Receber) {
  if ($Registrar -or $Executar) { throw 'Escolha somente -Receber.' }
  Assert-NextecInteractiveAdministrator
  Assert-NextecCoordinatorFileAcl -Path $PSCommandPath
  $worker = Join-Path $PastaDados 'Provisionar-Agente-Nextec.ps1'
  if (-not (Test-Path -LiteralPath $worker -PathType Leaf)) { throw 'component_missing' }
  Assert-NextecCoordinatorFileAcl -Path $worker
  $selectedPath = Select-NextecBootstrapFilePath -PickFile { Show-NextecBootstrapFileDialog }
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
  $readSelectedFile = { Get-Content -LiteralPath $selectedPath -Raw -Encoding UTF8 }
  Receive-NextecBootstrapAuthorization -Root $PastaDados -ReadInput $readSelectedFile
  return
}
if ($Executar) {
  try { Invoke-NextecCoordinator -Root $PastaDados -CoordinatorPath $PSCommandPath | Out-Null }
  catch { exit 1 }
  return
}
Write-Host 'Use -Registrar na instalação, -Receber para selecionar o bootstrap.json como administrador, -Executar (tarefa SYSTEM) ou -Remover no uninstall.'
