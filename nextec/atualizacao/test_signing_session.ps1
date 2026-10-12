$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Connect-SigningSession.ps1')

$tokens = $null
$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot 'assinar-pedido-connect.ps1'), [ref]$tokens, [ref]$parseErrors
) | Out-Null
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }

function Assert-Equal($Actual, $Expected, [string]$Message) {
    if ($Actual -ne $Expected) { throw "$Message (obtido: $Actual; esperado: $Expected)" }
}

$signerSource = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'assinar-pedido-connect.ps1')
Assert-Equal ($signerSource.IndexOf('--validar-chave') -lt $signerSource.IndexOf('Read-Host')) $true 'O assistente pediu a senha antes de validar se a chave é cifrada'

$start = [DateTimeOffset]::Parse('2026-10-12T12:00:00Z')
Assert-Equal (Test-ConnectSigningSessionActive -StartedAt $start -Now $start.AddMinutes(14).AddSeconds(59)) $true 'A sessão expirou antes de 15 minutos'
Assert-Equal (Test-ConnectSigningSessionActive -StartedAt $start -Now $start.AddMinutes(15)) $false 'A sessão permaneceu desbloqueada após 15 minutos'
Assert-Equal (Test-ConnectSigningSessionActive -StartedAt $start -Now $start.AddMinutes(-1)) $false 'A sessão aceitou relógio regressivo'
Assert-Equal (Test-ConnectSigningSessionActive -Elapsed ([TimeSpan]::FromMinutes(14).Add([TimeSpan]::FromSeconds(59))) ) $true 'O relógio monotônico expirou cedo'
Assert-Equal (Test-ConnectSigningSessionActive -Elapsed ([TimeSpan]::FromMinutes(15))) $false 'O relógio monotônico não expirou no limite'

Add-Type -TypeDefinition @'
using System;
public sealed class FakeConnectTimer {
    public event EventHandler Tick;
    public int Interval { get; set; }
    public bool Started { get; private set; }
    public bool Disposed { get; private set; }
    public void Start() { Started = true; }
    public void Stop() { Started = false; }
    public void Dispose() { Disposed = true; }
    public void Fire() { if (Tick != null) Tick(this, EventArgs.Empty); }
}
'@
$timerSecret = ConvertTo-SecureString ([guid]::NewGuid().ToString('N')) -AsPlainText -Force
$script:testElapsed = [TimeSpan]::Zero
$script:expiredCallback = $false
$timer = New-ConnectSigningSessionTimer -TimerFactory { [FakeConnectTimer]::new() } -OnTick {
    [void](Invoke-ConnectSigningSessionTick -Elapsed $script:testElapsed -Passphrase $timerSecret -OnExpired { $script:expiredCallback = $true })
}
Assert-Equal $timer.Interval 1000 'O timer não está configurado para checar a sessão a cada segundo'
Assert-Equal $timer.Started $true 'O timer não iniciou'
$script:testElapsed = [TimeSpan]::FromMinutes(15)
$timer.Fire()
Assert-Equal $script:expiredCallback $true 'O tick de expiração não chamou o callback'
$disposedSecret = $false
try { [void][Runtime.InteropServices.Marshal]::SecureStringToBSTR($timerSecret) } catch { $disposedSecret = $true }
Assert-Equal $disposedSecret $true 'O tick de expiração não descartou o segredo'
$timer.Stop(); $timer.Dispose()
Assert-Equal $timer.Disposed $true 'O timer fake não foi descartado'

$secretText = 'Nextec-çã漢字-' + [guid]::NewGuid().ToString('N')
$secure = ConvertTo-SecureString $secretText -AsPlainText -Force
$child = New-Object System.Diagnostics.Process
$startInfo = New-Object System.Diagnostics.ProcessStartInfo
$startInfo.FileName = (Get-Command powershell.exe).Source
$childScript = '$bytes=New-Object byte[] 512; $count=[Console]::OpenStandardInput().Read($bytes,0,$bytes.Length); $value=[Text.Encoding]::UTF8.GetString($bytes,0,$count).TrimEnd([char]10,[char]13); $sha=[Security.Cryptography.SHA256]::Create(); $digest=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($value))).Replace(''-'',''''); [Console]::Out.WriteLine($digest)'
$startInfo.Arguments = '-NoProfile -Command "' + $childScript + '"'
$startInfo.UseShellExecute = $false
$startInfo.RedirectStandardInput = $true
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true
$child.StartInfo = $startInfo
try {
    [void]$child.Start()
    $argsForSigner = Get-ConnectSignerArguments -Helper 'helper.py' -Pedido 'pedido.json' -Msi 'release.msi' -Chave 'encrypted-key.pem' -SaidaRoot 'releases'
    if (($argsForSigner -join ' ') -match [regex]::Escape($secretText)) { throw 'Senha apareceu nos argumentos' }
    Write-ConnectSigningPassphrase -Process $child -Passphrase $secure
    $child.StandardInput.Close()
    $child.WaitForExit()
    Assert-Equal $child.ExitCode 0 'O processo de teste de stdin falhou'
    $output = $child.StandardOutput.ReadToEnd().Trim()
    $childError = $child.StandardError.ReadToEnd()
    $expectedHash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($secretText))).Replace('-', '')
    Assert-Equal $output $expectedHash 'O processo não recebeu a senha Unicode em UTF-8 pelo stdin'
    if (($output + $childError) -match [regex]::Escape($secretText)) { throw 'Senha apareceu em stdout/stderr' }
    if ($startInfo.Arguments -match [regex]::Escape($secretText)) { throw 'Senha apareceu na linha de comando' }
    Write-Output 'OK: PowerShell 5.1, expiração, timer, descarte e senha Unicode somente em SecureString/stdin UTF-8'
} finally {
    if ($null -ne $secure) { $secure.Dispose() }
    $child.Dispose()
}

