<#
.SYNOPSIS
  Agente de senha automática do acesso remoto Nextec (RustDesk), para servidores e máquinas marcadas no painel.

.DESCRIPTION
  -Instalar: cadastra a máquina no painel (usa a chave de cadastro que o admin gera em Segurança > Senhas dos servidores),
             guarda o token protegido e cria a tarefa agendada (SYSTEM, a cada minuto; ver Get-NextecAgentIntervals).
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

# FONTE UNICA dos intervalos (em minutos) das tarefas agendadas do agente. Provisionar-Agente-Nextec.ps1 e
# Coordenar-Agente-Nextec.ps1 leem estes valores DESTE arquivo (so os literais do hashtable abaixo, sem executar nada);
# nao existe outro numero de intervalo nos tres scripts. Valor valido: inteiro de 1 a 60. Para mudar o ritmo, altere aqui.
#   PasswordMinutes:    tarefa 'Nextec Acesso - Senha' (uma consulta leve ao painel por execucao).
#   CoordinatorMinutes: tarefa 'Nextec Acesso - Cadastro de agente' (cadastro, reparo e autorizacoes pendentes).
function Get-NextecAgentIntervals {
  return @{
    PasswordMinutes    = 1
    CoordinatorMinutes = 2
  }
}

function Get-NextecPasswordTaskInterval {
  $minutes = [int](Get-NextecAgentIntervals).PasswordMinutes
  if ($minutes -lt 1 -or $minutes -gt 60) { throw 'invalid_interval: PasswordMinutes precisa estar entre 1 e 60.' }
  return (New-TimeSpan -Minutes $minutes)
}

# Intervalo real de consulta (segundos) informado ao painel no sync; 0 se o valor configurado for invalido.
function Get-NextecSyncIntervalSeconds {
  try { return [int](Get-NextecPasswordTaskInterval).TotalSeconds } catch { return 0 }
}

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

# Cliente gerado com "Bloquear configurações" (disable-settings=Y): no RustDesk 1.5.0, `--password` e `--option`
# imprimem "Settings are disabled!" e saem com código 0 (src/core_main.rs, is_cli_setting_change_disabled). Nenhuma
# nova tentativa resolve: só um instalador gerado de novo. Código estável: client_settings_locked.
function Test-NextecSettingsLockedOutput([string]$Output) {
  return [bool](@(([string]$Output -split "`r?`n") | Where-Object { $_.Trim() -ceq 'Settings are disabled!' }).Count)
}

function Assert-NextecClientSettingsUnlocked([string]$Output, [string]$Comando) {
  if (Test-NextecSettingsLockedOutput $Output) {
    throw "client_settings_locked: o cliente recusou $Comando (resposta: Settings are disabled!)."
  }
}

# Ultimo erro do agente (codigo estavel, sem texto livre e sem segredos) para o painel mostrar "A troca de senha esta
# falhando". So mensagens com prefixo de codigo ("client_settings_locked: ...") sao registradas; falha de rede ou HTTP
# (o painel nem recebeu a rodada) nao muda o registro. Rodada sem erro apaga o arquivo.
function Get-NextecErrorCode([string]$Message) {
  if ([string]$Message -cmatch '^([a-z][a-z0-9_]{0,47}):') { return $Matches[1] }
  return ''
}

function Set-NextecLastErrorCode {
  param([Parameter(Mandatory)][string]$Path, [string]$Message)
  $code = Get-NextecErrorCode $Message
  if (-not $code) { return }
  [IO.File]::WriteAllText($Path, $code, [Text.UTF8Encoding]::new($false))
}

function Get-NextecLastErrorCode {
  param([Parameter(Mandatory)][string]$Path)
  try {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    $code = ([IO.File]::ReadAllText($Path)).Trim()
    if ($code -cmatch '^[a-z][a-z0-9_]{0,47}$') { return $code }
  } catch { }
  return ''
}

# Espera longa depois de client_settings_locked: até $Hours horas, ou até o executável do cliente mudar (reinstalação).
function Test-NextecSettingsLockedWait {
  param([Parameter(Mandatory)][string]$Path, [string]$Fingerprint, [DateTime]$Now = [DateTime]::UtcNow)
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
  try {
    $wait = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
    $until = [DateTime]::Parse([string]$wait.until, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
  } catch { Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue; return $false }
  if ($Now -ge $until -or [string]$wait.client -cne [string]$Fingerprint) {
    Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    return $false
  }
  return $true
}

function Set-NextecSettingsLockedWait {
  param([Parameter(Mandatory)][string]$Path, [string]$Fingerprint, [DateTime]$Now = [DateTime]::UtcNow, [int]$Hours = 6)
  $value = @{ code = 'client_settings_locked'; until = $Now.AddHours($Hours).ToString('o'); client = [string]$Fingerprint } | ConvertTo-Json -Compress
  [IO.File]::WriteAllText($Path, $value, [Text.UTF8Encoding]::new($false))
}

# Identifica o executável instalado (caminho, tamanho, data): instalar por cima muda e encerra a espera na hora.
function Get-NextecClientFingerprint {
  try { $cliente = ClienteInstalado } catch { return '' }
  if (-not $cliente -or -not $cliente.ExePath) { return '' }
  try {
    $item = Get-Item -LiteralPath $cliente.ExePath -ErrorAction Stop
    return ('{0}|{1}|{2}' -f $item.FullName.ToLowerInvariant(), $item.Length, $item.LastWriteTimeUtc.Ticks)
  } catch { return '' }
}

function Assert-NextecPasswordApplied {
  param([Parameter(Mandatory)]$Result)
  Assert-NextecClientSettingsUnlocked -Output ([string]$Result.Output) -Comando '--password'

  # Contrato confirmado no upstream RustDesk 1.5.0: sucesso IPC imprime Done!;
  # builds sem esse contrato precisam ser verificados antes de serem declarados compatíveis.
  $lines = @(([string]$Result.Output -split "`r?`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  # A resposta do cliente (uma linha curta, sem a senha) acompanha o erro: "Installation and administrative privileges
  # required!" quer dizer app nao instalado ou sem privilegio, e "Done!" so vem depois do IPC aceitar a troca.
  $resposta = if ($lines.Count) { ([string]$lines[-1]) -replace '[^ -~]', '?' } else { '(vazia)' }
  if ($resposta.Length -gt 120) { $resposta = $resposta.Substring(0, 120) }
  if ($Result.ExitCode -ne 0) { throw "password_apply_failed: o cliente recusou a aplicação da senha (código $($Result.ExitCode); resposta: $resposta)." }
  if ($lines.Count -eq 0 -or $lines[-1] -cne 'Done!') {
    throw "password_apply_failed: o cliente não confirmou a aplicação via IPC (resposta: $resposta)."
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

# Nome do app instalado (AppName do marcador: valor AppName em HKLM\SOFTWARE\Nextec\Agente ou nextec-marker.json).
# O painel monta o link de conexao desta maquina com ele (o RustDesk registra o protocolo com o nome do app em
# minusculas). Nenhum nome e fixo aqui: sem marcador valido devolve '' e o painel usa o protocolo global.
function Get-NextecAppName {
  [CmdletBinding()]
  param(
    [string]$Root = (Join-Path $env:ProgramData 'Nextec\Acesso'),
    [string]$RegistryKey = 'HKLM:\SOFTWARE\Nextec\Agente'
  )
  try {
    $reg = Get-ItemProperty -LiteralPath $RegistryKey -ErrorAction Stop
    $nome = ([string]$reg.AppName).Trim()
    if ($nome -cmatch '^[A-Za-z0-9-]{1,64}$') { return $nome }
  } catch { }
  try {
    if ([string]::IsNullOrWhiteSpace($Root)) { return '' }
    $arquivo = Join-Path $Root 'nextec-marker.json'
    if ((Test-Path -LiteralPath $arquivo -PathType Leaf) -and (Get-Item -LiteralPath $arquivo).Length -le 4096) {
      $valor = [IO.File]::ReadAllText($arquivo, [Text.Encoding]::UTF8).TrimStart([char]0xFEFF) | ConvertFrom-Json
      foreach ($campo in 'AppName', 'app_name', 'app') {
        $nome = ([string]$valor.$campo).Trim()
        if ($nome -cmatch '^[A-Za-z0-9-]{1,64}$') { return $nome }
      }
    }
  } catch { }
  return ''
}

function Escrever([string]$msg) {
  if (-not (Test-Path $PastaDados)) { New-Item -ItemType Directory -Path $PastaDados -Force | Out-Null }
  if ((Test-Path $Log) -and (Get-Item $Log).Length -gt 1MB) { Move-Item $Log "$Log.antigo" -Force }
  Add-Content -Path $Log -Value ('{0}  {1}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture), $msg) -Encoding UTF8
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

# Resultado de um ciclo que falhou: so 401 conta, e so se for seguido de outros 401. Qualquer outra falha (503, rede,
# timeout) interrompe a sequencia e zera a contagem. 429 nao diz nada sobre a credencial (o painel so segurou a consulta,
# por falhas do IP ou por excesso de chamadas): a contagem fica como esta, sem somar nem zerar, para a aposentadoria de uma
# credencial morta nao ficar adiada para sempre quando varias maquinas do mesmo IP estao na mesma situacao.
# Devolve $true quando a credencial foi aposentada.
function Update-NextecAuthFailures {
  param(
    [int]$Status,
    [Parameter(Mandatory)][string]$CounterPath,
    [Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][string]$DataRoot
  )
  if ($Status -eq 401) { return (Register-NextecAuthFailure -CounterPath $CounterPath -ConfigPath $ConfigPath -DataRoot $DataRoot) }
  if ($Status -eq 429) { return $false }
  Remove-Item -LiteralPath $CounterPath -Force -ErrorAction SilentlyContinue
  return $false
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
    (Join-Path $PastaDados 'agente-senha.bloqueio.json'),
    (Join-Path $PastaDados 'agente-senha.ultimo-erro'),
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

# Um argumento da linha de comando do Windows: sem aspas quando e simples, senao entre aspas com barras e aspas escapadas.
function ConvertTo-NextecArgument([string]$Valor) {
  if ($Valor -ne '' -and $Valor -match '^[A-Za-z0-9_.:=/@+-]+$') { return $Valor }
  $escapado = [regex]::Replace($Valor, '(\\*)"', '$1$1\"')
  $escapado = [regex]::Replace($escapado, '(\\+)$', '$1$1')
  return '"' + $escapado + '"'
}

# O rustdesk.exe e um programa de janela (subsistema GUI): `$x = & exe args` NAO espera o processo nem captura a saida
# (o PowerShell o trata como aplicativo grafico), entao o --password rodava sem ninguem conferir o "Done!". Aqui o processo
# e iniciado com a saida redirecionada, esperado com limite de tempo e o codigo de saida e real.
function InvocarRustDesk([string[]]$Argumentos) {
  $cliente = ClienteInstalado
  if (-not $cliente) { throw 'identity_conflict: descoberta indisponível no modo de simulação.' }
  $psi = New-Object Diagnostics.ProcessStartInfo
  $psi.FileName = $cliente.ExePath
  $psi.Arguments = (@($Argumentos | ForEach-Object { ConvertTo-NextecArgument $_ }) -join ' ')
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $processo = [Diagnostics.Process]::Start($psi)
  try {
    $saidaPadrao = $processo.StandardOutput.ReadToEndAsync()
    $saidaErro = $processo.StandardError.ReadToEndAsync()
    if (-not $processo.WaitForExit(60000)) {
      try { $processo.Kill() } catch { }
      throw 'rustdesk_cli_timeout: o cliente não respondeu ao comando em 60 segundos.'
    }
    $processo.WaitForExit()
    $texto = (([string]$saidaPadrao.Result + "`n" + [string]$saidaErro.Result)).Trim()
    return [pscustomobject]@{ ExitCode = [int]$processo.ExitCode; Output = $texto }
  } finally { $processo.Dispose() }
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
  Assert-NextecClientSettingsUnlocked -Output ([string]$consulta.Output) -Comando "--option $chave"
  if ($consulta.ExitCode -ne 0) { throw "O RustDesk não conseguiu consultar '$chave' (código $($consulta.ExitCode)): $($consulta.Output)" }
  if ($consulta.Output -ne $valor) {
    $alteracao = InvocarRustDesk -Argumentos @('--option', $chave, $valor)
    Assert-NextecClientSettingsUnlocked -Output ([string]$alteracao.Output) -Comando "--option $chave"
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
  # A confirmacao e idempotente no painel (mesmo operation_id e versao): repetir na mesma execucao, depois de uma falha de
  # rede, resolve inclusive o caso em que o painel gravou e a resposta se perdeu.
  $result = Invoke-NextecTransientRetry {
    Chamar '/api/nextec/agent/confirm' @{
      id = $Cfg.id; token = $Token; operation_id = $Operation.operation_id; pending_version = [int]$Operation.pending_version
    }
  }
  if (-not $result.ok -or [int]$result.active_version -ne [int]$Operation.pending_version) {
    throw 'confirmation_failed: o painel nao confirmou a versao esperada.'
  }
  foreach ($name in @('pending_operation_id','pending_version','pending_password','applied_operation_id','applied_pending_version')) {
    Set-NextecStateValue $Cfg $name $null
  }
  Save-NextecAgentState $Cfg
}

# Aplica a senha no cliente. Repete na mesma execucao quando o cliente recusa (servico ainda subindo logo apos a
# instalacao); so e chamada depois de o painel aceitar a proposta, e aplicar duas vezes a mesma senha e inofensivo.
# Timeout do cliente (60 s) nao e repetido.
function Invoke-NextecApplyPassword([string]$Password) {
  Invoke-NextecTransientRetry -Retryable { param($e) ([string]$e.Message) -like 'password_apply_failed*' } -Action {
    Assert-NextecPasswordApplied -Result (InvocarRustDesk -Argumentos @('--password', $Password))
  }
}

# -SemCliente: o sync com o painel continua (presença), mas nada é pedido ao cliente (espera de client_settings_locked).
function Invoke-NextecPasswordCycle([psobject]$Cfg, [switch]$SemCliente) {
  $script:NextecClienteAdiado = $false
  $token = Revelar $Cfg.token
  # Campos aditivos (painel antigo ignora): interval_seconds, para o painel calcular a janela de "ativo" com o ritmo real
  # deste agente; app_name, so com marcador valido (sem ele o painel usa o protocolo global).
  $corpoSync = @{id=$Cfg.id;token=$token;capabilities=@('transaction_v1');interval_seconds=(Get-NextecSyncIntervalSeconds)}
  $nomeApp = Get-NextecAppName -Root $PastaDados
  if ($nomeApp) { $corpoSync.app_name = $nomeApp }
  # last_error (0035): codigo estavel da ultima rodada que falhou (ex.: client_settings_locked). Sem o campo, o painel
  # entende que a ultima rodada nao falhou e limpa o aviso.
  if ($PastaDados) {
    $ultimoErro = Get-NextecLastErrorCode -Path (Join-Path $PastaDados 'agente-senha.ultimo-erro')
    if ($ultimoErro) { $corpoSync.last_error = $ultimoErro }
  }
  $state = Chamar '/api/nextec/agent/sync' $corpoSync
  if ($state.pending_approval -and -not $state.managed) {
    # Inscricao global: a maquina ja esta no painel, mas ainda sem atribuicao. Nunca rotaciona.
    if ($Cfg.enrollment_state -ne 'pending_approval') {
      Set-NextecStateValue $Cfg 'enrollment_state' 'pending_approval'
      Save-NextecAgentState $Cfg
    }
    Write-NextecIdleLog 'Aguardando atribuicao no painel; nenhuma senha foi aplicada.'
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
      } else { Write-NextecIdleLog 'Sem regra ativa; nenhuma senha foi aplicada.' }
      return
    }
    if ($SemCliente) { $script:NextecClienteAdiado = $true; return }
    Opcao 'approve-mode' $state.approve_mode
    Opcao 'verification-method' $state.verification_method
    if (-not $state.rotate) { Write-NextecIdleLog 'Sincronizacao concluida; nenhuma troca necessaria.'; return }
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
      # Idempotente no painel (mesma operacao, versao e senha): falha transitoria repete na mesma execucao.
      $proposed = Invoke-NextecTransientRetry {
        Chamar '/api/nextec/agent/password' @{
          id=$Cfg.id;token=$token;operation_id=$operation.operation_id;pending_version=[int]$operation.pending_version;password=$password
        }
      }
      if (-not $proposed.ok -or $proposed.operation_id -ne $operation.operation_id -or [int]$proposed.pending_version -ne [int]$operation.pending_version) { throw 'proposal_failed: o painel nao confirmou a proposta.' }
    }
    if ($Simular -and -not $Exe) { Escrever '[simulacao] senha aplicada' }
    else { Invoke-NextecApplyPassword $password }
    Set-NextecStateValue $Cfg 'applied_operation_id' $operation.operation_id
    Set-NextecStateValue $Cfg 'applied_pending_version' ([int]$operation.pending_version)
    Save-NextecAgentState $Cfg
    Confirm-NextecOperation $Cfg $operation $token
    Escrever 'Senha aplicada e operacao confirmada.'
    return
  }
  # API anterior: manter a compatibilidade somente enquanto este dispositivo nao negociou v1.
  if (-not $state.managed) { Escrever 'Sem regra ativa; aguardando politica.'; return }
  if ($SemCliente) { $script:NextecClienteAdiado = $true; return }
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
  $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (Get-NextecPasswordTaskInterval) -RepetitionDuration (New-TimeSpan -Days 3650)
  $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 4) -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName $Tarefa -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
}

# Dispara a tarefa de senha agora (sem esperar a repeticao): usado depois de cadastrar, registrar ou reparar a tarefa.
# Nao duplica: se a tarefa ja esta em execucao, nada e feito (o Agendador tambem usa IgnoreNew). Nunca lanca: uma tarefa
# que nao pode ser iniciada agora roda na proxima repeticao. Devolve $true somente quando pediu a execucao.
function Start-NextecPasswordTaskNow {
  try {
    $task = Get-ScheduledTask -TaskName $Tarefa -ErrorAction Stop
    if ([string]$task.State -in @('Running', 'Disabled')) { return $false }
    Start-ScheduledTask -TaskName $Tarefa -ErrorAction Stop
    return $true
  } catch {
    Escrever "Aviso: a tarefa de senha nao foi iniciada agora ($($_.Exception.Message)); ela roda na proxima repeticao."
    return $false
  }
}

# Registra (ou repara) a tarefa de senha e ja a executa. E o unico caminho de registro do coordenador e do cadastro por
# autorizacao/inscricao: toda maquina cadastrada sincroniza na hora, sem esperar o proximo minuto.
function Register-NextecPasswordTaskAndStart {
  param([Parameter(Mandatory)][string]$Source)
  Register-NextecPasswordTask -Source $Source
  [void](Start-NextecPasswordTaskNow)
}

# Trava de execucao unica: duas execucoes (tarefa + manual, ou o disparo imediato junto da repeticao) nunca trocam a
# senha ao mesmo tempo. Arquivo aberto sem compartilhamento; o sistema o libera sozinho se o processo morrer.
function Enter-NextecAgentLock {
  param([Parameter(Mandatory)][string]$Path)
  Assert-NextecNoReparsePoints -Path $Path
  try {
    return [IO.File]::Open($Path, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
  } catch [IO.IOException] { return $null }
}

# Linha repetida a cada ciclo (nada a trocar, aguardando atribuicao, a mesma falha de rede): com uma execucao por minuto
# a mesma frase nao pode inundar o log. A mensagem e gravada quando muda e, igual, no maximo uma vez por hora.
# O marcador guarda so a ultima mensagem (sem segredos: o log nunca recebe senha nem token).
function Write-NextecIdleLog {
  param([Parameter(Mandatory)][string]$Message)
  if (-not $PastaDados) { Escrever $Message; return }
  $marker = Join-Path $PastaDados 'agente-senha.ocioso'
  try {
    if (Test-Path -LiteralPath $marker -PathType Leaf) {
      $age = [DateTime]::UtcNow - (Get-Item -LiteralPath $marker -Force).LastWriteTimeUtc
      $last = [IO.File]::ReadAllText($marker, [Text.Encoding]::UTF8)
      if ($last -ceq $Message -and $age -ge [TimeSpan]::Zero -and $age -lt [TimeSpan]::FromHours(1)) { return }
    }
  } catch { }
  Escrever $Message
  try { [IO.File]::WriteAllText($marker, $Message, [Text.UTF8Encoding]::new($false)) } catch { }
}

# Falha de rede ou do servidor no meio da transacao (propor, aplicar, confirmar): tenta de novo na MESMA execucao, em vez
# de esperar a proxima rodada. 401, 403 e 409 nunca sao repetidos (credencial, aprovacao e conflito pedem decisao).
function Get-NextecRetryDelays { return @(2, 5) }
function Wait-NextecRetry([int]$Seconds) { if ($Seconds -gt 0) { Start-Sleep -Seconds $Seconds } }
function Test-NextecTransientFailure($Exception) {
  $status = Get-NextecHttpStatus $Exception
  return ($status -eq 0 -or $status -eq 408 -or $status -eq 429 -or $status -ge 500)
}
function Invoke-NextecTransientRetry {
  param([Parameter(Mandatory)][scriptblock]$Action, [scriptblock]$Retryable = { param($e) Test-NextecTransientFailure $e })
  $delays = @(Get-NextecRetryDelays)
  for ($attempt = 0; ; $attempt++) {
    try { return (& $Action) }
    catch {
      if ($attempt -ge $delays.Count -or -not (& $Retryable $_.Exception)) { throw }
      Wait-NextecRetry ([int]$delays[$attempt])
    }
  }
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
  Register-NextecPasswordTaskAndStart -Source $PSCommandPath
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
    $gatilho = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (Get-NextecPasswordTaskInterval) -RepetitionDuration (New-TimeSpan -Days 3650)
    $conf = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 4) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $Tarefa -Action $acao -Trigger $gatilho -Settings $conf -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
    Escrever "Tarefa agendada criada: $Tarefa (a cada $([int](Get-NextecPasswordTaskInterval).TotalMinutes) min)"
    $inicioExecucao = (Get-Date).AddSeconds(-2)
    Start-ScheduledTask -TaskName $Tarefa
    $limiteExecucao = (Get-Date).AddSeconds(45)
    do {
      Start-Sleep -Seconds 1
      $infoExecucao = Get-ScheduledTaskInfo -TaskName $Tarefa
      $estadoExecucao = (Get-ScheduledTask -TaskName $Tarefa).State
    } while (($infoExecucao.LastRunTime -lt $inicioExecucao -or $estadoExecucao -eq 'Running') -and (Get-Date) -lt $limiteExecucao)
    if ($infoExecucao.LastRunTime -lt $inicioExecucao -or $estadoExecucao -eq 'Running') {
      Escrever "A primeira sincronização continua em andamento; a tarefa seguirá verificando a cada $([int](Get-NextecPasswordTaskInterval).TotalMinutes) min."
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

# Uma verificacao (o que a tarefa agendada roda). Devolve $true quando o ciclo terminou sem erro; qualquer falha e anotada
# no log e, se for 401, conta para a aposentadoria da credencial (3 seguidos).
function Invoke-NextecAgentExecute {
  $falhas = Join-Path $PastaDados 'agente-senha.falhas'
  $espera = Join-Path $PastaDados 'agente-senha.bloqueio.json'
  $ultimoErro = Join-Path $PastaDados 'agente-senha.ultimo-erro'
  $impressao = ''
  try {
    $cfg = Get-Content $Config -Raw | ConvertFrom-Json
    # troca de dominio: vale o painel configurado hoje; sem arquivo, o gravado no cadastro (validado)
    $script:PainelUrl = Get-NextecPainelConfigurado -Root $PastaDados -Padrao ''
    if (-not $script:PainelUrl) {
      $script:PainelUrl = ConvertTo-NextecPainelUrl ([string]$cfg.painel)
      if (-not $script:PainelUrl) { throw 'invalid_agent_config' }
      Escrever 'Aviso: inscricao.json ausente; usando o painel do cadastro (compat).'
    } else {
      # credencial de OUTRO painel nunca e enviada ao painel configurado: o coordenador a aposenta e refaz o cadastro
      $gravado = ConvertTo-NextecPainelUrl ([string]$cfg.painel)
      if (-not $gravado -or $gravado -cne $script:PainelUrl) { throw 'panel_changed: a credencial foi cadastrada em outro painel; o coordenador vai refazer o cadastro.' }
    }
    $token = Revelar $cfg.token
    $meuId = $cfg.id
    $idServico = MeuId
    if ($idServico -ne $meuId) {
      throw "O agente está vinculado ao ID $meuId, mas o serviço RustDesk atende o ID $idServico. A execução foi interrompida para não trocar a senha da máquina errada. Remova o agente antigo no painel e cadastre novamente para vincular o ID do serviço."
    }
    $impressao = Get-NextecClientFingerprint
    $emEspera = Test-NextecSettingsLockedWait -Path $espera -Fingerprint $impressao
    Invoke-NextecPasswordCycle $cfg -SemCliente:$emEspera | Out-Null
    Remove-Item -LiteralPath $falhas -Force -ErrorAction SilentlyContinue
    # Em espera: o painel recebeu o sync, mas o cliente continua bloqueado; sem nova linha no log a cada rodada.
    if ($emEspera -and $script:NextecClienteAdiado) { return $false }
    Remove-Item -LiteralPath $ultimoErro -Force -ErrorAction SilentlyContinue
    return $true
  } catch {
    Write-NextecIdleLog "ERRO: $($_.Exception.Message)"
    try { Set-NextecLastErrorCode -Path $ultimoErro -Message ([string]$_.Exception.Message) } catch { }
    if ($_.Exception.Message -like 'client_settings_locked:*') {
      try { Set-NextecSettingsLockedWait -Path $espera -Fingerprint $impressao } catch { }
      Escrever "O app foi gerado com 'Bloquear configurações'; gere o instalador de novo com a versão atual do gerador e instale por cima. Nova tentativa em 6 h ou logo após a reinstalação."
    }
    if (Update-NextecAuthFailures -Status (Get-NextecHttpStatus $_.Exception) -CounterPath $falhas -ConfigPath $Config -DataRoot $PastaDados) {
      Escrever 'O painel recusou a credencial deste agente 3 vezes seguidas (401). Ela foi guardada em agente-senha.json.anterior e o cadastro sera refeito automaticamente.'
    }
    return $false
  }
}

# Uma execucao por vez: se outra (repeticao, disparo imediato ou execucao manual) esta em andamento, esta devolve 'busy'
# sem fazer nada e sem erro. 'ok' = ciclo concluido; 'failed' = ciclo com erro (o chamador sai com codigo 1).
function Invoke-NextecAgentExecuteExclusive {
  $trava = Enter-NextecAgentLock -Path (Join-Path $PastaDados 'agente-senha.lock')
  if (-not $trava) { return 'busy' }
  try {
    if (Invoke-NextecAgentExecute) { return 'ok' }
    return 'failed'
  } finally { $trava.Dispose() }
}

if ($Executar) {
  ProtegerPastaAgente
  # Sem credencial: o coordenador ainda vai cadastrar (ou acabou de aposentar a antiga). Nada a fazer, sem erro.
  if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) { return }
  if ((Invoke-NextecAgentExecuteExclusive) -eq 'failed') { exit 1 }
  return
}

Write-Host 'Use -Instalar -Painel <url> -ChaveAgente <chave>  (como administrador)  ou -Executar.'
