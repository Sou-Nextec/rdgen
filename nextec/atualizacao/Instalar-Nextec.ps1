<#
.SYNOPSIS
  Instala e mantém atualizado o app de acesso remoto da Nextec (RustDesk personalizado).

.DESCRIPTION
  Pergunta ao painel qual versão esta máquina deve ter, valida o manifesto RSA assinado, confere o hash SHA-256 e instala o MSI
  em modo silencioso e cria uma tarefa agendada que repete a checagem todo dia. O mesmo script serve
  para a primeira instalação e para as atualizações. O administrador escolhe no painel
  (Dispositivos > Atualizações do app) a versão e quem a recebe (todos ou um grupo piloto).

.PARAMETER UrlBase
  Endereço da atualização (padrão: o painel, https://painel-remoto.nex.tec.br/api/nextec/update).
  Serve também qualquer site com versao.json e o MSI lado a lado.

.PARAMETER GrupoId
  ID do cliente no painel. Junto com -ChaveCliente (ambos vêm do comando gerado em Dispositivos > Clientes > Comando de instalação),
  coloca esta máquina no cliente certo. Só vale para máquina que ainda não tem cliente.

.PARAMETER Forcar
  Reinstala mesmo que a versão instalada já seja a atual.

.PARAMETER SoVerificar
  Baixa e confere o hash, mas não instala nada nem cria tarefa (teste).

.PARAMETER Silencioso
  Usado pela tarefa agendada: sem mensagens na tela.

.PARAMETER Registrar
  Registra o atualizador incluído no instalador, sem baixar manifesto ou MSI.
  Exige administrador. Funciona offline e mantém o estado de versão e sequência.
#>
[CmdletBinding()]
param(
  [string]$UrlBase = 'https://painel-remoto.nex.tec.br/api/nextec/update',
  [int]$GrupoId = 0,
  [string]$ChaveCliente = '',
  [switch]$Forcar,
  [switch]$SoVerificar,
  [switch]$Registrar,
  [switch]$Silencioso
)

$ErrorActionPreference = 'Stop'
$Pasta   = Join-Path $env:ProgramData 'Nextec\Acesso'
$Log     = Join-Path $Pasta 'atualizacao.log'
$Tarefa  = 'Nextec Acesso - Atualizacao'
$ChaveReg = 'HKLM:\SOFTWARE\Nextec\Acesso'
$script:PastaSegura = $false
$script:ReleaseVerificada = $false
$script:OrigemAtualizador = $PSCommandPath

function RegistrarAtualizador {
  if ($SoVerificar) { throw 'Registrar e SoVerificar não podem ser usados juntos.' }
  $meu = $script:OrigemAtualizador
  $fixo = Join-Path $Pasta 'Instalar-Nextec.ps1'
  if (-not $meu) { throw 'O registro exige executar o arquivo do atualizador.' }
  if ([IO.Path]::GetFullPath($meu) -ne [IO.Path]::GetFullPath($fixo)) {
    Copy-Item -LiteralPath $meu -Destination $fixo -Force
  }
  ProtegerPastaAtualizador
  $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$fixo`" -UrlBase `"$UrlBase`" -Silencioso"
  $acao = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument $arg
  $gatilho = New-ScheduledTaskTrigger -Daily -At '12:30'
  $gatilho.RandomDelay = [TimeSpan]::FromHours(2)
  $conf = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 1) -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName $Tarefa -Action $acao -Trigger $gatilho -Settings $conf -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
  Escrever "Tarefa agendada: $Tarefa (todo dia, perto das 12:30)"
}

function Get-DownloadConnect([string]$Url, [long]$Limite, [string]$Destino = '') {
  $uri = [Uri]$Url
  if ($uri.Scheme -ne 'https') { throw 'Download sem HTTPS recusado.' }
  $request = [Net.HttpWebRequest]::Create($uri)
  $request.AllowAutoRedirect = $false
  $request.Timeout = 30000
  $request.ReadWriteTimeout = 30000
  $response = $null; $inputStream = $null; $outputStream = $null
  try {
    $response = $request.GetResponse()
    if ([int]$response.StatusCode -ne 200 -or $response.ContentLength -gt $Limite) { throw 'Resposta ou tamanho de download inválido.' }
    $inputStream = $response.GetResponseStream()
    $outputStream = if ($Destino) { [IO.File]::Open($Destino, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None) } else { New-Object IO.MemoryStream }
    $buffer = New-Object byte[] 65536
    $total = 0L
    $deadline = [DateTime]::UtcNow.AddMinutes(15)
    while (($count = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
      $total += $count
      if ($total -gt $Limite -or [DateTime]::UtcNow -gt $deadline) { throw 'Download excedeu o limite de tamanho ou tempo.' }
      $outputStream.Write($buffer, 0, $count)
    }
    if (-not $Destino) { return ,$outputStream.ToArray() }
  } finally {
    if ($outputStream) { $outputStream.Dispose() }
    if ($inputStream) { $inputStream.Dispose() }
    if ($response) { $response.Dispose() }
  }
}

function ProtegerPastaAtualizador {
  # A SYSTEM task must never execute a script writable by standard users.
  foreach ($path in @((Split-Path $Pasta -Parent), $Pasta, (Join-Path $Pasta 'download'))) {
    if ((Test-Path -LiteralPath $path) -and ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      throw 'Link ou redirecionamento encontrado na pasta do atualizador.'
    }
  }
  foreach ($path in @((Split-Path $Pasta -Parent), $Pasta, (Join-Path $Pasta 'download'))) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
      $identity = New-Object Security.Principal.SecurityIdentifier($sid)
      $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
      $acl.AddAccessRule($rule)
    }
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    Set-Acl -LiteralPath $path -AclObject $acl
  }
  foreach ($file in @('Instalar-Nextec.ps1', 'atualizacao.log', 'msi.log')) {
    $path = Join-Path $Pasta $file
    if (Test-Path -LiteralPath $path) {
      if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Arquivo do atualizador redirecionado.' }
      $acl = Get-Acl -LiteralPath $path
      $acl.SetAccessRuleProtection($false, $false)
      foreach ($rule in @($acl.Access | Where-Object { -not $_.IsInherited })) { $acl.RemoveAccessRuleSpecific($rule) }
      Set-Acl -LiteralPath $path -AclObject $acl
    }
  }
}

function Escrever([string]$msg) {
  $linha = '{0:yyyy-MM-dd HH:mm:ss}  {1}' -f (Get-Date), $msg
  if ($script:PastaSegura) { Add-Content -LiteralPath $Log -Value $linha -Encoding UTF8 }
  if (-not $Silencioso) { Write-Host $linha }
}

function IdDoRustDesk {
  try {
    $svc = Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.PathName -match '--service' -and $_.PathName -match 'Program Files' } | Select-Object -First 1
    if ($svc -and $svc.PathName -match '^"([^"]+)"') {
      $saida = & $Matches[1] --get-id 2>&1 | Out-String
      if ($saida -match '(\d{6,})') { return $Matches[1] }
    }
  } catch { }
  return ''
}

# coloca a máquina no cliente do comando (depois de instalar, o ID demora alguns segundos para existir)
function Atribuir {
  if ($GrupoId -le 0 -or -not $ChaveCliente) { return }
  $painel = $UrlBase -replace '/api/nextec/update$', ''
  for ($i = 0; $i -lt 12; $i++) {
    $meuId = IdDoRustDesk
    if ($meuId) { break }
    Start-Sleep -Seconds 5
  }
  if (-not $meuId) { Escrever 'Não consegui ler o ID do RustDesk para colocar a máquina no cliente. Rode o comando de novo depois que o app abrir.'; return }
  try {
    $corpo = @{ id = $meuId; group = $GrupoId; token = $ChaveCliente } | ConvertTo-Json -Compress
    $r = Invoke-WebRequest -Uri "$painel/api/nextec/install/assign" -Method Post -ContentType 'application/json' -Body $corpo -UseBasicParsing -TimeoutSec 30
    $estado = ([Text.Encoding]::UTF8.GetString($r.RawContentStream.ToArray()) | ConvertFrom-Json).state
    switch ($estado) {
      'assigned' { Escrever "Máquina colocada no cliente (ID $meuId)." }
      'pending'  { Escrever "Máquina ainda não registrada no painel: será colocada no cliente assim que aparecer (ID $meuId)." }
      'kept'     { Escrever 'Esta máquina já tem cliente no painel; nada foi alterado.' }
      default    { Escrever "Resposta inesperada do painel: $estado" }
    }
  } catch {
    $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
    if ($code -eq 401) { Escrever 'Chave do cliente recusada (comando antigo ou invalidado). Gere o comando de novo no painel.' }
    else { Escrever "Não foi possível colocar a máquina no cliente: $($_.Exception.Message)" }
  }
}

#requires -version 5.1
# Imported by the installed updater, never downloaded/executed from the manifest.
# RSA PKCS#1 v1.5 / SHA-256: same trust key and primitive as Nextec monitoring.
function Test-ManifestoConnect {
    param(
        [Parameter(Mandatory)][byte[]]$Dados,
        [Parameter(Mandatory)][string]$Assinatura,
        [long]$UltimaSequencia = 0,
        [string]$UltimoHash = '',
        [DateTime]$Agora = [DateTime]::UtcNow
    )
    if ($Dados.Length -eq 0 -or $Dados.Length -gt 65536 -or $Assinatura.Length -gt 4096) {
        throw 'Manifesto ou assinatura acima do limite.'
    }
    $keys = '[
  {
    "id": "8cb5b1d7f80d20cb",
    "e": 65537,
    "n": "d87a26b54c0a3ca1d1780b5d72b9f81b7bcfcaa37c2b6ac57619e95aed2d6441da58de1133acb8cf7ada60a9d2e5506662b78aac1e8b77e5d170cb4066ae799cddb20dbbfe14919e92a350cbc01b2045d52058bd4975a880d65b8cb9aff4932e7ce1aedb64fe049f2c889105c6086f023d9a30788d523d1b551936a413db547bd53e391ef1a81fa80664f17516addf8ae23ab609b9f4e802baebf8777f6138ec4ff61c951dbbaabaa15fb85469642ff531b49c1a588b6b4870da9f6034c0aeb005a9fe8fa67d9efa7cad26e0057c272c4d6a7cebefc3f5c58bbd8d8c6553ab113c882ebe8d5b68b2a35c4b224b8dc7aa7a920b1b34a332d4763c5e51c4918b19d4894793b8be26ad4ae4d84afee77196692d6a26b44ccb6001e133d43755c5bf2b46e51b3f0b39c5ba4ce4eafbf4967d01b3776bdb8c5b4bc113a3c4ce0d5b12108b2c63225085eed92254b377c53baca735574b50af0a1a1a1cdd3f825b6e74d0a3461d7d4f45c4bb5b29b79631536d2af39ce02bc20b24e72054de5b38678389db8fee83fd48a3e0c6d7bd4caf33f6756c5a7a57293ef1694d8589e0a396b12881438b7933fbf41a7724ad96ebacc65fbd43f80bbe9c9d56a4637552e9cd5b73b7e8cf9be0db09701b5c26d1427dd92b508496e3fddd27013f080d015e712f7139cfd22ec3adcfc0776693a0649e3b1d4de08cd47340502c19b8d77460738b"
  }
]' | ConvertFrom-Json
    $signature = [Convert]::FromBase64String($Assinatura.Trim())
    $signer = $null
    foreach ($key in $keys) {
        if ($key.n -notmatch '^[a-f0-9]{768,1024}$' -or $key.n.Length % 2 -ne 0 -or $key.e -ne 65537) { continue }
        $modulus = New-Object byte[] ($key.n.Length / 2)
        for ($i = 0; $i -lt $modulus.Length; $i++) { $modulus[$i] = [Convert]::ToByte($key.n.Substring($i * 2, 2), 16) }
        if ($signature.Length -ne $modulus.Length) { continue }
        $rsa = [Security.Cryptography.RSA]::Create()
        try {
            $parameters = New-Object Security.Cryptography.RSAParameters
            $parameters.Modulus = $modulus
            $parameters.Exponent = [byte[]]@(1, 0, 1)
            $rsa.ImportParameters($parameters)
            if ($rsa.VerifyData($Dados, $signature, [Security.Cryptography.HashAlgorithmName]::SHA256,
                               [Security.Cryptography.RSASignaturePadding]::Pkcs1)) { $signer = $key.id; break }
        } finally { $rsa.Dispose() }
    }
    if (-not $signer) { throw 'Assinatura não confere com a chave Nextec.' }
    $m = [Text.Encoding]::UTF8.GetString($Dados) | ConvertFrom-Json
    if ($m.produto -cne 'nextec-connect' -or $m.formato -ne 1) { throw 'Manifesto de outro produto ou formato.' }
    if ($m.sequencia -isnot [long] -and $m.sequencia -isnot [int]) { throw 'Sequência inválida.' }
    if ($m.sequencia -lt 1 -or $m.sequencia -gt 9007199254740991) { throw 'Sequência inválida.' }
    if ($m.versao -cnotmatch '^\d{1,4}\.\d{1,4}\.\d{1,4}(\.\d{1,4})?$') { throw 'Versão inválida.' }
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    # PowerShell 7 can convert ISO dates to DateTime; Windows PowerShell 5.1 keeps strings.
    $issued = if ($m.publicado_em -is [DateTime]) { $m.publicado_em.ToUniversalTime() } else {
        [DateTime]::ParseExact($m.publicado_em, 'yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture, $styles)
    }
    $expires = if ($m.valido_ate -is [DateTime]) { $m.valido_ate.ToUniversalTime() } else {
        [DateTime]::ParseExact($m.valido_ate, 'yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture, $styles)
    }
    if ($issued -gt $Agora.AddMinutes(5) -or $expires -le $issued -or $expires -gt $issued.AddDays(30) -or $expires -le $Agora) {
        throw 'Manifesto vencido ou validade inválida.'
    }
    if ($m.windows.arquivo -cne "files/nextec-acesso-$($m.versao).msi" -or $m.windows.sha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'Caminho do MSI ou hash inválido.'
    }
    if (($m.windows.tamanho -isnot [long] -and $m.windows.tamanho -isnot [int]) -or
        $m.windows.tamanho -lt 8 -or $m.windows.tamanho -gt 314572800) { throw 'Tamanho do MSI inválido.' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = ([BitConverter]::ToString($sha.ComputeHash($Dados))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
    if ($m.sequencia -lt $UltimaSequencia -or ($m.sequencia -eq $UltimaSequencia -and $hash -cne $UltimoHash)) {
        throw 'Manifesto antigo ou divergente.'
    }
    return [pscustomobject]@{ Manifesto = $m; Hash = $hash; Assinante = $signer }
}


try {
  # precisa de administrador para instalar o serviço
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $admin = (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $admin -and -not $SoVerificar) { throw 'Execute como administrador (botão direito > Executar como administrador).' }
  if (-not $SoVerificar) { ProtegerPastaAtualizador; $script:PastaSegura = $true }

  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $UrlBase = $UrlBase.TrimEnd('/')
  $baseUri = [Uri]$UrlBase
  if (-not $baseUri.IsAbsoluteUri -or $baseUri.Scheme -ne 'https' -or $baseUri.Query -or $baseUri.Fragment -or $baseUri.UserInfo -or $UrlBase.Contains('"')) { throw 'Endereço de atualização inválido; use HTTPS.' }
  $UrlBase = $baseUri.AbsoluteUri.TrimEnd('/')
  # Called by EXE/MSI after installing their trusted, bundled updater.
  # Registration must work offline and never download or install another package.
  if ($Registrar) { RegistrarAtualizador; return }

  # 1. versão instalada (marca gravada por este script) e ID do RustDesk (o painel usa para piloto e acompanhamento)
  $instalada = $null
  if (Test-Path $ChaveReg) { $instalada = (Get-ItemProperty $ChaveReg -ErrorAction SilentlyContinue).Versao }
  if ($instalada) { Escrever "Versão instalada: $instalada" } else { Escrever 'Nada instalado por este script ainda.' }
  $meuId = IdDoRustDesk

  # 2. versão publicada para esta máquina
  $consulta = "t=$([DateTime]::UtcNow.Ticks)"
  if ($meuId) { $consulta += "&id=$meuId" }
  if ($instalada) { $consulta += "&v=$instalada" }
  $resp = Get-DownloadConnect "$UrlBase/versao.json?$consulta" 100000
  # decodifica como UTF-8 e ignora a marca BOM, que o Windows PowerShell 5.1 coloca ao gravar arquivos
  $texto = [Text.Encoding]::UTF8.GetString($resp).TrimStart([char]0xFEFF)
  $json = $texto | ConvertFrom-Json
  if (-not $json.windows) { Escrever 'Nenhuma versão publicada para esta máquina. Nada a fazer.'; return }
  if (-not $json.windows.manifesto -or -not $json.windows.assinatura -or $json.windows.manifesto.Length -gt 88000) {
    throw 'Atualização sem manifesto assinado. Gere a autorização com a chave do monitoramento antes de publicar.'
  }
  $lastSequence = 0; $lastHash = ''
  if (Test-Path $ChaveReg) {
    $state = Get-ItemProperty $ChaveReg
    if ($state.PSObject.Properties['Sequencia']) { $lastSequence = [long]$state.Sequencia }
    if ($state.PSObject.Properties['ManifestoHash']) { $lastHash = [string]$state.ManifestoHash }
  }
  $verified = Test-ManifestoConnect -Dados ([Convert]::FromBase64String($json.windows.manifesto)) -Assinatura $json.windows.assinatura -UltimaSequencia $lastSequence -UltimoHash $lastHash
  $script:ReleaseVerificada = $true
  $alvo = $verified.Manifesto.windows
  $alvo | Add-Member -NotePropertyName versao -NotePropertyValue $verified.Manifesto.versao
  if (-not $SoVerificar) {
    New-Item -Path $ChaveReg -Force | Out-Null
    New-ItemProperty -Path $ChaveReg -Name Sequencia -Value $verified.Manifesto.sequencia -PropertyType QWord -Force | Out-Null
    Set-ItemProperty -Path $ChaveReg -Name ManifestoHash -Value $verified.Hash
  }
  if (-not $alvo) { Escrever 'Nenhuma versão publicada para esta máquina. Nada a fazer.'; return }
  if (-not $alvo.versao -or -not $alvo.arquivo -or -not $alvo.sha256) { throw 'versao.json com a seção windows incompleta.' }
  Escrever "Versão publicada: $($alvo.versao)"

  $precisa = $Forcar -or (-not $instalada) -or ([version]$alvo.versao -ne [version]$instalada)
  if (-not $precisa) { Escrever 'Já está na versão publicada. Nada a fazer.'; return }

  # 3. baixar e conferir
  $tmp = Join-Path (Join-Path $Pasta 'download') ([Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tmp -Force | Out-Null
  $msi = Join-Path $tmp ([IO.Path]::GetFileName($alvo.arquivo))
  Escrever "Baixando $($alvo.arquivo)"
  Get-DownloadConnect "$UrlBase/$($alvo.arquivo)" $alvo.tamanho $msi
  $hash = (Get-FileHash -Path $msi -Algorithm SHA256).Hash
  if ($hash -ne $alvo.sha256.ToUpper()) {
    Remove-Item $msi -Force -ErrorAction SilentlyContinue
    throw "Hash diferente do publicado (esperado $($alvo.sha256), recebido $hash). Instalação cancelada."
  }
  if ((Get-Item -LiteralPath $msi).Length -ne $alvo.tamanho) { throw 'Tamanho diferente do manifesto assinado.' }
  Escrever 'Assinatura, hash e tamanho conferidos.'
  if ($SoVerificar) { Escrever 'Modo SoVerificar: nada foi instalado.'; Remove-Item $msi -Force -ErrorAction SilentlyContinue; return }

  # 4. instalar (MSI faz atualização por cima)
  Escrever 'Instalando...'
  $logMsi = Join-Path $Pasta 'msi.log'
  $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList @('/i', "`"$msi`"", '/qn', '/norestart', '/L*v', "`"$logMsi`"") -Wait -PassThru
  if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { throw "msiexec terminou com código $($p.ExitCode). Veja $logMsi" }
  if (-not (Test-Path $ChaveReg)) { New-Item -Path $ChaveReg -Force | Out-Null }
  Set-ItemProperty -Path $ChaveReg -Name Versao -Value $alvo.versao
  Escrever "Instalado: $($alvo.versao)"
  Remove-Item $msi -Force -ErrorAction SilentlyContinue

  # 5. tarefa diária de atualização (copia o script para um lugar fixo)
  RegistrarAtualizador
}
catch {
  Escrever "ERRO: $($_.Exception.Message)"
  if (-not $Silencioso) { Write-Host "ERRO: $($_.Exception.Message)" -ForegroundColor Red }
  exit 1
}
finally {
  if (-not $SoVerificar -and $script:ReleaseVerificada) { Atribuir }
}

