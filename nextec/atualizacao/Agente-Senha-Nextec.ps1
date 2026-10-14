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

  # Devolve as pastas Roaming onde o serviço pode guardar a config, na ordem de preferência.
  # O RustDesk roda como LocalSystem, mas grava em ServiceProfiles\LocalService: o hbb_common troca
  # 'system32\config\systemprofile' por 'ServiceProfiles\LocalService' (config.rs, função patch).
  $localService = if ($ProfileRootBase) { Join-Path $ProfileRootBase 'LocalService\AppData\Roaming' } else { Join-Path $WindowsDirectory 'ServiceProfiles\LocalService\AppData\Roaming' }
  $systemProfile = if ($ProfileRootBase) { Join-Path $ProfileRootBase 'SystemProfile\AppData\Roaming' } else { Join-Path $WindowsDirectory 'System32\config\systemprofile\AppData\Roaming' }
  $networkService = if ($ProfileRootBase) { Join-Path $ProfileRootBase 'NetworkService\AppData\Roaming' } else { Join-Path $WindowsDirectory 'ServiceProfiles\NetworkService\AppData\Roaming' }

  $account = $ServiceAccount.Trim().ToLowerInvariant()
  if ($account -match '^(localservice|nt authority\\localservice)$') { return @($localService) }
  if (-not $account -or $account -match '^(localsystem|nt authority\\system|system|\.\\localsystem)$') { return @($localService, $systemProfile) }
  if ($account -match '^(networkservice|nt authority\\networkservice)$') { return @($networkService) }
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
    [scriptblock]$PeerIdReader,
    [object]$Marker,
    [string]$MarkerFile
  )

  if ($null -eq $Services) {
    $Services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)
  }

  # Marcador gravado pelo MSI (HKLM\SOFTWARE\Nextec\Agente {InstallDir, AppName}) ou nextec-marker.json.
  # Quando existe, decide sozinho qual serviço é o nosso; nenhum nome de app é fixo aqui.
  $markerApp = ''
  $markerDir = ''
  $markerSource = ''
  if ($null -ne $Marker) {
    $markerApp = [string]$Marker.AppName
    $markerDir = [string]$Marker.InstallDir
    $markerSource = 'marcador informado'
  } else {
    try {
      $reg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Nextec\Agente' -ErrorAction Stop
      $markerApp = [string]$reg.AppName
      $markerDir = [string]$reg.InstallDir
      $markerSource = 'HKLM\SOFTWARE\Nextec\Agente'
    } catch { $markerApp = ''; $markerDir = '' }
    if (-not $markerApp -and -not $markerDir) {
      $markerPath = $MarkerFile
      if (-not $markerPath -and $env:ProgramData) { $markerPath = Join-Path $env:ProgramData 'Nextec\Acesso\nextec-marker.json' }
      try {
        if ($markerPath -and (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
          $mj = Get-Content -Raw -LiteralPath $markerPath -ErrorAction Stop | ConvertFrom-Json
          if ($mj.AppName) { $markerApp = [string]$mj.AppName } elseif ($mj.app_name) { $markerApp = [string]$mj.app_name } elseif ($mj.app) { $markerApp = [string]$mj.app }
          if ($mj.InstallDir) { $markerDir = [string]$mj.InstallDir } elseif ($mj.install_dir) { $markerDir = [string]$mj.install_dir }
          $markerSource = $markerPath
        }
      } catch { $markerApp = ''; $markerDir = '' }
    }
  }
  if ($markerApp -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$') { $markerApp = '' }
  $markerDir = ([string]$markerDir).Trim().Trim('"').Trim().TrimEnd('\')
  if ($markerDir -notmatch '^[A-Za-z]:\\') { $markerDir = '' }

  $all = @(
    foreach ($service in $Services) {
      try {
        $exePath = Get-NextecServiceExecutablePath -Service $service
        if (-not $exePath) { continue }
        if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) { continue }
        $exePath = [IO.Path]::GetFullPath($exePath)
        $exeName = [IO.Path]::GetFileNameWithoutExtension($exePath)
        $exeDir = [IO.Path]::GetDirectoryName($exePath).TrimEnd('\')
        $roots = @(Get-NextecServiceProfileRoot -ServiceAccount ([string]$service.StartName) -WindowsDirectory $WindowsDirectory -ProfileRootBase $ProfileRootBase)
        $configPath = ''
        foreach ($root in $roots) {
          $path = Join-Path (Join-Path $root $exeName) 'config'
          if ((Test-Path -LiteralPath $path -PathType Container) -and
              @(Get-ChildItem -LiteralPath $path -File -Filter '*.toml' -ErrorAction SilentlyContinue).Count -gt 0) { $configPath = $path; break }
        }
        $expectedConfig = Join-Path (Join-Path $roots[0] $exeName) 'config'
        $byMarker = ($markerDir -and ($exeDir -ieq $markerDir)) -or
          ($markerApp -and ([string]$service.Name -ieq $markerApp) -and ($exeName -ieq $markerApp))
        $isRustDesk = ([string]$service.Name -ieq $exeName) -and [bool]$configPath
        if (-not $byMarker -and -not $isRustDesk) { continue }
        if (-not $configPath) { $configPath = $expectedConfig }
        [pscustomobject]@{ Service = $service; ExePath = $exePath; ConfigRoot = $configPath; ByMarker = [bool]$byMarker }
      } catch { continue }
    }
  )

  # O marcador do instalador vence a heurística; sem marcador, vale serviço com config do RustDesk.
  $candidates = @($all | Where-Object { $_.ByMarker })
  if ($candidates.Count -eq 0) { $candidates = @($all) }

  if ($candidates.Count -eq 0) {
    $seen = @($Services | Where-Object { $_ }).Count
    if ($markerApp -or $markerDir) { $how = "marcador: app '$markerApp', pasta '$markerDir' ($markerSource)" } else { $how = 'sem marcador (HKLM\SOFTWARE\Nextec\Agente ou nextec-marker.json)' }
    throw ('identity_conflict: nenhum serviço instalado do RustDesk/Nextec foi encontrado. Procurado: serviço com --service apontando para a pasta do marcador, ou serviço com o nome do executável e config .toml em ServiceProfiles\LocalService ({0} serviços vistos; {1}).' -f $seen, $how)
  }
  if ($candidates.Count -gt 1 -and $markerApp) {
    $byName = @($candidates | Where-Object { [string]$_.Service.Name -ieq $markerApp })
    if ($byName.Count -eq 1) { $candidates = $byName }
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
    [string]$Padrao = 'https://painel-remoto.nex.tec.br'
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
  $script:NextecPainelOrigem = 'padrao'
  return $Padrao
}

function Escrever([string]$msg) {
  if (-not (Test-Path $PastaDados)) { New-Item -ItemType Directory -Path $PastaDados -Force | Out-Null }
  if ((Test-Path $Log) -and (Get-Item $Log).Length -gt 1MB) { Move-Item $Log "$Log.antigo" -Force }
  Add-Content -Path $Log -Value ('{0:yyyy-MM-dd HH:mm:ss}  {1}' -f (Get-Date), $msg) -Encoding UTF8
  if ($Instalar -or $VerbosePreference -ne 'SilentlyContinue' -or $Simular) { Write-Host $msg }
}

# Credencial que o painel recusa (401) em 3 ciclos seguidos nao volta a valer: vai para agente-senha.json.anterior
# e o coordenador refaz o cadastro sozinho (inscricao.json ou autorizacao do painel). Um 401 isolado nao derruba nada.
function Get-NextecHttpStatus {
  param($Exception)
  $ex = $Exception
  while ($ex) {
    if ($ex -is [Net.WebException] -and $ex.Response) { return [int]$ex.Response.StatusCode }
    $ex = $ex.InnerException
  }
  return 0
}

function Register-NextecAuthFailure {
  param(
    [Parameter(Mandatory)][string]$CounterPath,
    [Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][string]$DataRoot,
    [int]$Limit = 3
  )
  $count = 0
  try { if (Test-Path -LiteralPath $CounterPath -PathType Leaf) { $count = [int]([IO.File]::ReadAllText($CounterPath).Trim()) } } catch { $count = 0 }
  $count++
  if ($count -lt $Limit) {
    [IO.File]::WriteAllText($CounterPath, [string]$count)
    return $false
  }
  $aside = $ConfigPath + '.anterior'
  Remove-Item -LiteralPath $aside -Force -ErrorAction SilentlyContinue
  if (Test-Path -LiteralPath $ConfigPath -PathType Leaf) { Move-Item -LiteralPath $ConfigPath -Destination $aside -Force }
  Remove-Item -LiteralPath (Join-Path $DataRoot 'inscricao-estado.json') -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $CounterPath -Force -ErrorAction SilentlyContinue
  return $true
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
    if (Test-Path -LiteralPath $Config) { [IO.File]::Replace($temp, $Config, [NullString]::Value) }
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
  if ($state.pending_approval -and -not $state.managed) {
    # Inscricao global: a maquina ja esta no painel, mas ainda sem atribuicao. Nunca rotaciona.
    if ($Cfg.enrollment_state -ne 'pending_approval') {
      Set-NextecStateValue $Cfg 'enrollment_state' 'pending_approval'
      Save-NextecAgentState $Cfg
    }
    Escrever 'Aguardando atribuicao no painel; nenhuma senha foi aplicada.'
    return
  }
  if ($Cfg.enrollment_state) {
    Set-NextecStateValue $Cfg 'enrollment_state' $null
    Save-NextecAgentState $Cfg
  }
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
  if (-not (ConvertTo-NextecPainelUrl ([string]$cfg.painel)) -or -not $cfg.token) { throw 'invalid_agent_config' }
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
  # o painel configurado no instalador (inscricao.json) vence o argumento; sem arquivo, vale o argumento validado
  $painelCfg = Get-NextecPainelConfigurado -Root $PastaDados -Padrao ''
  if ($painelCfg) { $script:PainelUrl = $painelCfg }
  else {
    $script:PainelUrl = ConvertTo-NextecPainelUrl $Painel
    if (-not $script:PainelUrl) { throw 'Endereco do painel invalido (precisa ser https://dominio, sem IP nem credenciais).' }
    Escrever 'Aviso: inscricao.json ausente; usando o painel informado (compat com instalacao antiga).'
  }
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
  # Sem credencial: o coordenador ainda vai cadastrar (ou acabou de aposentar a antiga). Nada a fazer, sem erro.
  if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) { return }
  $falhas = Join-Path $PastaDados 'agente-senha.falhas'
  try {
    $cfg = Get-Content $Config -Raw | ConvertFrom-Json
    # troca de dominio: vale o painel configurado hoje; sem arquivo, o gravado no cadastro (validado)
    $script:PainelUrl = Get-NextecPainelConfigurado -Root $PastaDados -Padrao ''
    if (-not $script:PainelUrl) {
      $script:PainelUrl = ConvertTo-NextecPainelUrl ([string]$cfg.painel)
      if (-not $script:PainelUrl) { throw 'invalid_agent_config' }
      Escrever 'Aviso: inscricao.json ausente; usando o painel do cadastro (compat).'
    }
    $token = Revelar $cfg.token
    $meuId = $cfg.id
    $idServico = MeuId
    if ($idServico -ne $meuId) {
      throw "O agente está vinculado ao ID $meuId, mas o serviço RustDesk atende o ID $idServico. A execução foi interrompida para não trocar a senha da máquina errada. Remova o agente antigo no painel e cadastre novamente para vincular o ID do serviço."
    }
    Invoke-NextecPasswordCycle $cfg
    Remove-Item -LiteralPath $falhas -Force -ErrorAction SilentlyContinue
  } catch {
    Escrever "ERRO: $($_.Exception.Message)"
    if ((Get-NextecHttpStatus $_.Exception) -eq 401) {
      if (Register-NextecAuthFailure -CounterPath $falhas -ConfigPath $Config -DataRoot $PastaDados) {
        Escrever 'O painel recusou a credencial deste agente 3 vezes seguidas (401). Ela foi guardada em agente-senha.json.anterior e o cadastro sera refeito automaticamente.'
      }
    }
    exit 1
  }
  return
}

Write-Host 'Use -Instalar -Painel <url> -ChaveAgente <chave>  (como administrador)  ou -Executar.'
