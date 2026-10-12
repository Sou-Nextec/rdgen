<#
.SYNOPSIS
  Agente de senha automática do acesso remoto Nextec (RustDesk), para servidores e máquinas marcadas no painel.

.DESCRIPTION
  -Instalar: cadastra a máquina no painel (usa a chave de cadastro que o admin gera em Segurança > Senhas dos servidores),
             guarda o token protegido e cria a tarefa agendada (SYSTEM, a cada 5 minutos).
  -Executar: uma verificação (o que a tarefa roda). Pergunta ao painel se a máquina é gerenciada e se é hora de trocar a
             senha. Se for, gera uma senha forte, envia ao painel como pendente, aplica no RustDesk (--password) e só então
             confirma. Se aplicar falhar, não confirma e a senha anterior continua valendo no painel.

  A senha é permanente do RustDesk: serve só para liberar a conexão pelo RustDesk. Não é a senha do Windows.

.PARAMETER Painel
  Endereço do painel (ex.: https://painel-remoto.nex.tec.br).
.PARAMETER ChaveAgente
  Chave de cadastro gerada no painel (só no -Instalar).
.PARAMETER Simular
  Teste: não mexe no RustDesk nem cria tarefa; usa -Id e -PastaDados.
#>
[CmdletBinding()]
param(
  [switch]$Instalar,
  [switch]$Registrar,
  [switch]$Executar,
  [string]$Painel,
  [string]$ChaveAgente,
  [string]$Exe,
  [switch]$Simular,
  [string]$Id,
  [string]$PastaDados = (Join-Path $env:ProgramData 'Nextec\Acesso')
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Config = Join-Path $PastaDados 'agente-senha.json'
$Log    = Join-Path $PastaDados 'agente-senha.log'
$Tarefa = 'Nextec Acesso - Senha'
Add-Type -AssemblyName System.Security

function Get-NextecServiceExecutablePath {
  param([Parameter(Mandatory)]$Service)

  $commandLine = [string]$Service.PathName
  if ($commandLine -notmatch '(?i)(?:^|\s)--service(?:\s|$)') { return $null }
  if ($commandLine -match '^\s*"([^"]+\.exe)"(?=\s|$)') { return $Matches[1] }
  if ($commandLine -match '^\s*(.+?\.exe)(?=\s|$)') { return $Matches[1].Trim('"') }
  return $null
}

function Get-NextecServiceProfileRoot {
  param(
    [Parameter(Mandatory)][string]$ServiceAccount,
    [string]$WindowsDirectory = $env:WinDir,
    [string]$ProfileRootBase
  )

  $account = $ServiceAccount.Trim().ToLowerInvariant()
  if ($account -match '^(localservice|nt authority\\localservice)$') {
    if ($ProfileRootBase) { return (Join-Path $ProfileRootBase 'LocalService\AppData\Roaming') }
    return (Join-Path $WindowsDirectory 'ServiceProfiles\LocalService\AppData\Roaming')
  }
  if ($account -match '^(localsystem|nt authority\\system|system)$') {
    if ($ProfileRootBase) { return (Join-Path $ProfileRootBase 'SystemProfile\AppData\Roaming') }
    return (Join-Path $WindowsDirectory 'System32\config\systemprofile\AppData\Roaming')
  }
  if ($account -match '^(networkservice|nt authority\\networkservice)$') {
    if ($ProfileRootBase) { return (Join-Path $ProfileRootBase 'NetworkService\AppData\Roaming') }
    return (Join-Path $WindowsDirectory 'ServiceProfiles\NetworkService\AppData\Roaming')
  }
  throw "identity_conflict: conta de serviço não reconhecida ('$ServiceAccount')."
}

function Get-NextecPeerId {
  param([Parameter(Mandatory)][string]$ExePath)

  # No Windows, o CLI consulta o IPC do cliente instalado; APPDATA não escolhe o serviço ativo.
  $output = (& $ExePath --get-id 2>&1 | Out-String).Trim()
  if ($LASTEXITCODE -ne 0) {
    throw "identity_conflict: o cliente não conseguiu consultar o ID via IPC (código $LASTEXITCODE)."
  }
  $lines = @($output -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  if ($lines.Count -eq 0 -or $lines[-1] -notmatch '^\d{6,}$') {
    throw 'identity_conflict: o cliente não retornou um PeerId válido via IPC.'
  }
  return $lines[-1]
}

function Assert-NextecPasswordApplied {
  param([Parameter(Mandatory)]$Result)

  # Contrato confirmado no upstream RustDesk 1.5.0: sucesso IPC imprime Done!;
  # builds sem esse contrato precisam ser verificados antes de serem declarados compatíveis.
  if ($Result.ExitCode -ne 0) { throw 'password_apply_failed: o cliente recusou a aplicação da senha.' }
  $lines = @(([string]$Result.Output -split "`r?`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  if ($lines.Count -eq 0 -or $lines[-1] -cne 'Done!') {
    throw 'password_apply_failed: o cliente não confirmou a aplicação via IPC.'
  }
}

function Get-NextecInstalledClient {
  [CmdletBinding()]
  param(
    [object[]]$Services,
    [string]$WindowsDirectory = $env:WinDir,
    [string]$ProfileRootBase,
    [scriptblock]$PeerIdReader
  )

  if ($null -eq $Services) {
    $Services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)
  }

  $candidates = @(
    foreach ($service in $Services) {
      $exePath = Get-NextecServiceExecutablePath -Service $service
      if (-not $exePath) { continue }
      $exeName = [IO.Path]::GetFileNameWithoutExtension($exePath)
      if ([string]$service.Name -ine $exeName) { continue }
      if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) { continue }
      $profile = Get-NextecServiceProfileRoot -ServiceAccount ([string]$service.StartName) -WindowsDirectory $WindowsDirectory -ProfileRootBase $ProfileRootBase
      $configPath = Join-Path (Join-Path $profile $exeName) 'config'
      if (-not (Test-Path -LiteralPath $configPath -PathType Container)) { continue }
      if (@(Get-ChildItem -LiteralPath $configPath -File -Filter '*.toml' -ErrorAction SilentlyContinue).Count -eq 0) { continue }
      [pscustomobject]@{ Service = $service; ExePath = [IO.Path]::GetFullPath($exePath); ConfigRoot = $configPath }
    }
  )

  if ($candidates.Count -eq 0) {
    throw 'identity_conflict: nenhum serviço instalado do RustDesk/Nextec foi encontrado.'
  }
  if ($candidates.Count -gt 1) {
    $names = ($candidates | ForEach-Object { [string]$_.Service.Name }) -join ', '
    throw "identity_conflict: múltiplos serviços/instalações encontrados ($names). Corrija a instalação antes de continuar."
  }

  $candidate = $candidates[0]
  $service = $candidate.Service
  $configRoot = $candidate.ConfigRoot

  if ($PeerIdReader) { $peerId = [string](& $PeerIdReader $service $candidate.ExePath) }
  else { $peerId = [string](Get-NextecPeerId -ExePath $candidate.ExePath) }
  if ($peerId -notmatch '^\d{6,}$') { throw 'identity_conflict: PeerId vazio ou inválido.' }

  $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($candidate.ExePath).FileVersion
  [pscustomobject]@{
    ExePath = $candidate.ExePath
    ServiceName = [string]$service.Name
    ServiceAccount = [string]$service.StartName
    ConfigRoot = [IO.Path]::GetFullPath($configRoot)
    PeerId = $peerId
    ComponentVersion = [string]$version
  }
}

function Escrever([string]$msg) {
  if (-not (Test-Path $PastaDados)) { New-Item -ItemType Directory -Path $PastaDados -Force | Out-Null }
  if ((Test-Path $Log) -and (Get-Item $Log).Length -gt 1MB) { Move-Item $Log "$Log.antigo" -Force }
  Add-Content -Path $Log -Value ('{0:yyyy-MM-dd HH:mm:ss}  {1}' -f (Get-Date), $msg) -Encoding UTF8
  if ($Instalar -or $VerbosePreference -ne 'SilentlyContinue' -or $Simular) { Write-Host $msg }
}

function Chamar([string]$caminho, [hashtable]$corpo) {
  $r = Invoke-WebRequest -Uri ($script:PainelUrl + $caminho) -Method Post -ContentType 'application/json' `
        -Body ($corpo | ConvertTo-Json -Compress) -UseBasicParsing -MaximumRedirection 0 -TimeoutSec 30
  return ([Text.Encoding]::UTF8.GetString($r.RawContentStream.ToArray()).TrimStart([char]0xFEFF) | ConvertFrom-Json)
}

function Proteger([string]$texto) {
  $b = [Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($texto), $null, 'LocalMachine')
  return [Convert]::ToBase64String($b)
}
function Revelar([string]$b64) {
  $b = [Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($b64), $null, 'LocalMachine')
  return [Text.Encoding]::UTF8.GetString($b)
}

function Assert-NextecNoReparsePoints {
  param([Parameter(Mandatory)][string]$Path)

  $current = [IO.Path]::GetFullPath($Path)
  while ($current) {
    if (Test-Path -LiteralPath $current) {
      $item = Get-Item -LiteralPath $current -Force
      if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Pasta ou arquivo do agente redirecionado; operação interrompida.'
      }
    }
    $parent = [IO.Path]::GetDirectoryName($current.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar))
    if (-not $parent -or $parent -eq $current) { break }
    $current = $parent
  }
}

function New-NextecSecureAcl {
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

function ProtegerPastaAgente {
  Assert-NextecNoReparsePoints -Path $PastaDados
  New-Item -ItemType Directory -Path $PastaDados -Force | Out-Null
  Assert-NextecNoReparsePoints -Path $PastaDados

  $managedFiles = @(
    $Config,
    $Log,
    "$Log.antigo",
    (Join-Path $PastaDados 'Agente-Senha-Nextec.ps1')
  )
  foreach ($path in $managedFiles) {
    Assert-NextecNoReparsePoints -Path $path
    if (Test-Path -LiteralPath $path) {
      if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "identity_conflict: arquivo esperado do agente não é arquivo regular ('$path')." }
    }
  }
  Set-Acl -LiteralPath $PastaDados -AclObject (New-NextecSecureAcl -Directory)
  foreach ($path in $managedFiles) {
    Assert-NextecNoReparsePoints -Path $path
    if (Test-Path -LiteralPath $path) { Set-Acl -LiteralPath $path -AclObject (New-NextecSecureAcl) }
  }
}

function ClienteInstalado {
  if ($Simular) {
    if (-not $Exe) { return $null }
    return [pscustomobject]@{ ExePath = [IO.Path]::GetFullPath($Exe); PeerId = (Get-NextecPeerId -ExePath $Exe) }
  }
  $cliente = Get-NextecInstalledClient
  if ($Exe -and [IO.Path]::GetFullPath($Exe) -ine $cliente.ExePath) {
    throw 'identity_conflict: -Exe não corresponde ao executável do único serviço instalado.'
  }
  return $cliente
}

function InvocarRustDesk([string[]]$Argumentos) {
  $cliente = ClienteInstalado
  if (-not $cliente) { throw 'identity_conflict: descoberta indisponível no modo de simulação.' }
  $saida = & $cliente.ExePath @Argumentos 2>&1
  $codigo = $LASTEXITCODE
  return [pscustomobject]@{ ExitCode = $codigo; Output = (@($saida) -join "`n").Trim() }
}

function MeuId {
  if ($Simular -and -not $Exe) { if (-not $Id) { throw 'No modo -Simular informe -Id.' }; return $Id }
  return (ClienteInstalado).PeerId
}

function SenhaForte {
  $letras = [char[]]('abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789')
  $bytes = New-Object byte[] 24
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  -join ($bytes | ForEach-Object { $letras[$_ % $letras.Length] })
}

function Opcao([string]$chave, [string]$valor) {
  if ($Simular) { Escrever "[simulação] --option $chave $valor"; return }
  $consulta = InvocarRustDesk -Argumentos @('--option', $chave)
  if ($consulta.ExitCode -ne 0) { throw "O RustDesk não conseguiu consultar '$chave' (código $($consulta.ExitCode)): $($consulta.Output)" }
  if ($consulta.Output -ne $valor) {
    $alteracao = InvocarRustDesk -Argumentos @('--option', $chave, $valor)
    if ($alteracao.ExitCode -ne 0) { throw "O RustDesk não conseguiu aplicar '$chave' (código $($alteracao.ExitCode)): $($alteracao.Output)" }
    Escrever "Opção $chave = $valor"
  }
}

function Save-NextecAgentState([psobject]$State) {
  Assert-NextecNoReparsePoints -Path $Config
  $temp = Join-Path $PastaDados ('agente-state-' + [Guid]::NewGuid().ToString('N') + '.tmp')
  try {
    [IO.File]::WriteAllText($temp, ($State | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($true))
    if (Test-Path -LiteralPath $Config) { [IO.File]::Replace($temp, $Config, $null) }
    else { [IO.File]::Move($temp, $Config) }
  } finally {
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
  }
}

function Set-NextecStateValue([psobject]$State, [string]$Name, $Value) {
  $State | Add-Member -MemberType NoteProperty -Name $Name -Value $Value -Force
}

function Confirm-NextecOperation([psobject]$Cfg, [psobject]$Operation, [string]$Token) {
  $result = Chamar '/api/nextec/agent/confirm' @{
    id = $Cfg.id; token = $Token; operation_id = $Operation.operation_id; pending_version = [int]$Operation.pending_version
  }
  if (-not $result.ok -or [int]$result.active_version -ne [int]$Operation.pending_version) {
    throw 'confirmation_failed: o painel nao confirmou a versao esperada.'
  }
  foreach ($name in @('pending_operation_id','pending_version','pending_password','applied_operation_id','applied_pending_version')) {
    Set-NextecStateValue $Cfg $name $null
  }
  Save-NextecAgentState $Cfg
}

function Invoke-NextecPasswordCycle([psobject]$Cfg) {
  $token = Revelar $Cfg.token
  $state = Chamar '/api/nextec/agent/sync' @{id=$Cfg.id;token=$token;capabilities=@('transaction_v1')}
  if (-not $state.transaction_v1 -and $Cfg.protocol_version -eq 1) {
    throw 'protocol_downgrade: o painel nao suporta o protocolo de senha ja negociado.'
  }
  if ($state.transaction_v1) {
    Set-NextecStateValue $Cfg 'protocol_version' 1
    Save-NextecAgentState $Cfg
    $operation = $state.operation
    if ($operation) {
      if (-not $operation.operation_id -or [int]$operation.pending_version -lt 1) {
        throw 'invalid_operation: operacao de senha incompleta.'
      }
    }
    if (-not $operation -and ($Cfg.pending_password -or $Cfg.applied_operation_id)) {
      foreach ($name in @('pending_operation_id','pending_version','pending_password','applied_operation_id','applied_pending_version')) {
        Set-NextecStateValue $Cfg $name $null
      }
      Save-NextecAgentState $Cfg
    }
    if (-not $state.managed) {
      # Uma politica desligada nunca aplica outra senha. Reconciliar apenas o que o journal prova aplicado.
      if ($operation -and $Cfg.applied_operation_id -eq $operation.operation_id -and
          $Cfg.applied_pending_version -eq $operation.pending_version) {
        Confirm-NextecOperation $Cfg $operation $token
        Escrever 'Operacao previamente aplicada reconciliada com o painel.'
      } else { Escrever 'Sem regra ativa; nenhuma senha foi aplicada.' }
      return
    }
    Opcao 'approve-mode' $state.approve_mode
    Opcao 'verification-method' $state.verification_method
    if (-not $state.rotate) { Escrever 'Sincronizacao concluida; nenhuma troca necessaria.'; return }
    if (-not $operation) { throw 'invalid_operation: rotacao sem identificador de operacao.' }

    $password = [string]$operation.pending_password
    if (-not $password) {
      if ($Cfg.pending_operation_id -eq $operation.operation_id -and $Cfg.pending_version -eq $operation.pending_version -and $Cfg.pending_password) {
        $password = Revelar $Cfg.pending_password
      } else { $password = SenhaForte }
    }
    Set-NextecStateValue $Cfg 'pending_operation_id' $operation.operation_id
    Set-NextecStateValue $Cfg 'pending_version' ([int]$operation.pending_version)
    Set-NextecStateValue $Cfg 'pending_password' (Proteger $password)
    Save-NextecAgentState $Cfg
    if (-not $operation.pending_password) {
      $proposed = Chamar '/api/nextec/agent/password' @{
        id=$Cfg.id;token=$token;operation_id=$operation.operation_id;pending_version=[int]$operation.pending_version;password=$password
      }
      if (-not $proposed.ok -or $proposed.operation_id -ne $operation.operation_id -or [int]$proposed.pending_version -ne [int]$operation.pending_version) { throw 'proposal_failed: o painel nao confirmou a proposta.' }
    }
    if ($Simular -and -not $Exe) { Escrever '[simulacao] senha aplicada' }
    else { Assert-NextecPasswordApplied -Result (InvocarRustDesk -Argumentos @('--password',$password)) }
    Set-NextecStateValue $Cfg 'applied_operation_id' $operation.operation_id
    Set-NextecStateValue $Cfg 'applied_pending_version' ([int]$operation.pending_version)
    Save-NextecAgentState $Cfg
    Confirm-NextecOperation $Cfg $operation $token
    Escrever 'Senha aplicada e operacao confirmada.'
    return
  }
  # API anterior: manter a compatibilidade somente enquanto este dispositivo nao negociou v1.
  if (-not $state.managed) { Escrever 'Sem regra ativa; aguardando politica.'; return }
  Opcao 'approve-mode' $state.approve_mode
  Opcao 'verification-method' $state.verification_method
  if (-not $state.rotate) { return }
  $password = SenhaForte
  Chamar '/api/nextec/agent/password' @{id=$Cfg.id;token=$token;password=$password} | Out-Null
  if ($Simular -and -not $Exe) { Escrever '[simulacao] senha aplicada' }
  else { Assert-NextecPasswordApplied -Result (InvocarRustDesk -Argumentos @('--password',$password)) }
  Chamar '/api/nextec/agent/confirm' @{id=$Cfg.id;token=$token} | Out-Null
  Escrever 'Senha aplicada e confirmada no protocolo anterior.'
}

function Register-NextecPasswordTask {
  param([Parameter(Mandatory)][string]$Source)
  $destination = Join-Path $PastaDados 'Agente-Senha-Nextec.ps1'
  Assert-NextecNoReparsePoints -Path $Source
  Assert-NextecNoReparsePoints -Path $destination
  if ([IO.Path]::GetFullPath($Source) -ine [IO.Path]::GetFullPath($destination)) {
    Copy-Item -LiteralPath $Source -Destination $destination -Force
  }
  Set-Acl -LiteralPath $destination -AclObject (New-NextecSecureAcl)
  $powershellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $argument = "-NoProfile -ExecutionPolicy Bypass -File `"$destination`" -Executar"
  $action = New-ScheduledTaskAction -Execute $powershellExe -Argument $argument
  $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)
  $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 4) -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName $Tarefa -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
}

if ($Registrar) {
  if ($Instalar -or $Executar -or $Simular) { throw 'Escolha somente -Registrar para ativar um cadastro existente.' }
  $admin = (New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $admin) { throw 'Execute como administrador.' }
  ProtegerPastaAgente
  $cfg = Get-Content -LiteralPath $Config -Raw -Encoding UTF8 | ConvertFrom-Json
  if ($cfg.painel -cne 'https://painel-remoto.nex.tec.br' -or -not $cfg.token) { throw 'invalid_agent_config' }
  if ((MeuId) -ne $cfg.id) { throw 'identity_conflict' }
  Revelar $cfg.token | Out-Null
  Register-NextecPasswordTask -Source $PSCommandPath
  Start-ScheduledTask -TaskName $Tarefa
  Escrever 'Tarefa de senha registrada; primeira sincronizacao iniciada.'
  return
}

if ($Instalar) {
  if (-not $Painel -or -not $ChaveAgente) { throw 'Informe -Painel e -ChaveAgente.' }
  if (-not $Simular) {
    $admin = (New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) { throw 'Execute como administrador.' }
    ProtegerPastaAgente
  }
  $script:PainelUrl = $Painel.TrimEnd('/')
  $meuId = MeuId
  Escrever "ID do RustDesk: $meuId"
  try {
    $r = Chamar '/api/nextec/agent/enroll' @{ key = $ChaveAgente; id = $meuId }
  } catch {
    $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
    if ($code -eq 409) { throw 'Esta máquina já está cadastrada. Peça ao administrador para usar "Remover agente" no painel e rode de novo.' }
    if ($code -eq 401) { throw 'Chave de cadastro recusada. Gere uma nova no painel.' }
    throw
  }
  New-Item -ItemType Directory -Path $PastaDados -Force | Out-Null
  @{ painel = $script:PainelUrl; id = $meuId; token = (Proteger $r.token) } | ConvertTo-Json | Set-Content -Path $Config -Encoding UTF8
  if (-not $Simular) {
    $copia = Join-Path $PastaDados 'Agente-Senha-Nextec.ps1'
    if ([IO.Path]::GetFullPath($MyInvocation.MyCommand.Path) -ne [IO.Path]::GetFullPath($copia)) {
      Copy-Item -LiteralPath $MyInvocation.MyCommand.Path -Destination $copia -Force
    }
    $powershellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$copia`" -Executar"
    if ($Exe) { $arg += " -Exe `"$Exe`"" }
    $acao = New-ScheduledTaskAction -Execute $powershellExe -Argument $arg
    $gatilho = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)
    $conf = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 4) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $Tarefa -Action $acao -Trigger $gatilho -Settings $conf -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
    Escrever "Tarefa agendada criada: $Tarefa (a cada 5 minutos)"
    $inicioExecucao = (Get-Date).AddSeconds(-2)
    Start-ScheduledTask -TaskName $Tarefa
    $limiteExecucao = (Get-Date).AddSeconds(45)
    do {
      Start-Sleep -Seconds 1
      $infoExecucao = Get-ScheduledTaskInfo -TaskName $Tarefa
      $estadoExecucao = (Get-ScheduledTask -TaskName $Tarefa).State
    } while (($infoExecucao.LastRunTime -lt $inicioExecucao -or $estadoExecucao -eq 'Running') -and (Get-Date) -lt $limiteExecucao)
    if ($infoExecucao.LastRunTime -lt $inicioExecucao -or $estadoExecucao -eq 'Running') {
      Escrever 'A primeira sincronização continua em andamento; a tarefa seguirá verificando a cada 5 minutos.'
    } elseif ($infoExecucao.LastTaskResult -ne 0) {
      $erroExecucao = Get-Content $Log -Tail 5 -ErrorAction SilentlyContinue | Where-Object { $_ -match 'ERRO:' } | Select-Object -Last 1
      throw "A primeira sincronização falhou (código $($infoExecucao.LastTaskResult)). $erroExecucao Consulte '$Log'."
    } else {
      Escrever 'Primeira sincronização concluída.'
    }
  }
  Escrever 'Cadastro concluído. Ligue a senha automática desta máquina (ou do grupo) no painel.'
  return
}

if ($Executar) {
  ProtegerPastaAgente
  try {
    $cfg = Get-Content $Config -Raw | ConvertFrom-Json
    $script:PainelUrl = $cfg.painel
    $token = Revelar $cfg.token
    $meuId = $cfg.id
    $idServico = MeuId
    if ($idServico -ne $meuId) {
      throw "O agente está vinculado ao ID $meuId, mas o serviço RustDesk atende o ID $idServico. A execução foi interrompida para não trocar a senha da máquina errada. Remova o agente antigo no painel e cadastre novamente para vincular o ID do serviço."
    }
    Invoke-NextecPasswordCycle $cfg
  } catch {
    Escrever "ERRO: $($_.Exception.Message)"
    exit 1
  }
  return
}

Write-Host 'Use -Instalar -Painel <url> -ChaveAgente <chave>  (como administrador)  ou -Executar.'
