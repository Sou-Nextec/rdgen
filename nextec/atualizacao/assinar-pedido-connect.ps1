param(
    [string]$Pedido,
    [string]$Msi,
    [string]$DebAmd64,
    [string]$DebArm64
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Connect-SigningSession.ps1')

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

function Select-LocalFile([string]$Title, [string]$Filter) {
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title = $Title
    $dialog.Filter = $Filter
    $dialog.Multiselect = $false
    if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { throw 'Operação cancelada.' }
    return $dialog.FileName
}

function Quote-ProcessArgument([string]$Value) {
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Invoke-ConnectSigner([string]$RequestPath, [string]$MsiPath, [string]$Amd64Path, [string]$Arm64Path) {
    if (-not (Test-ConnectSigningSessionActive -Elapsed $sessionClock.Elapsed)) {
        throw 'A sessão de assinatura de 15 minutos venceu. Abra novamente para desbloquear.'
    }
    $remaining = [int][Math]::Floor(([TimeSpan]::FromMinutes(15) - $sessionClock.Elapsed).TotalMilliseconds)
    if ($remaining -le 0) { throw 'A sessão de assinatura de 15 minutos venceu. Abra novamente para desbloquear.' }
    $argsForPython = Get-ConnectSignerArguments -Helper $helper -Pedido $RequestPath -Msi $MsiPath -DebAmd64 $Amd64Path -DebArm64 $Arm64Path -Chave $keyPath -SaidaRoot $releaseRoot
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $pythonCommand
    $startInfo.Arguments = (($pythonArgs + $argsForPython) | ForEach-Object { Quote-ProcessArgument ([string]$_) }) -join ' '
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardInput = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    $script:signerProcess = $process
    $originalInputEncoding = [Console]::InputEncoding
    try {
        # Process.Start creates the redirected StandardInput StreamWriter using
        # Console.InputEncoding on Windows PowerShell 5.1. Pin it before Start
        # so its preamble is UTF-8 without a BOM, independent of the console page.
        [Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
        if (-not $process.Start()) { throw 'Não foi possível iniciar o assinador local.' }
        Write-ConnectSigningPassphrase -Process $process -Passphrase $securePassphrase
        $process.StandardInput.BaseStream.Close()
        $remaining = [int][Math]::Floor(([TimeSpan]::FromMinutes(15) - $sessionClock.Elapsed).TotalMilliseconds)
        if ($remaining -le 0 -or -not $process.WaitForExit($remaining)) {
            Stop-ConnectProcessTree -Process $process
            throw 'A sessão venceu durante a assinatura. Nenhuma nova assinatura pode continuar.'
        }
        if ($process.ExitCode -ne 0) { throw "O assinador recusou o pedido ou falhou (código $($process.ExitCode))." }
    } finally {
        try { $process.StandardInput.BaseStream.Close() } catch {}
        try { if (-not $process.HasExited) { Stop-ConnectProcessTree -Process $process } } catch {}
        $script:signerProcess = $null
        try { $process.Dispose() } finally { [Console]::InputEncoding = $originalInputEncoding }
    }
}

try {
    if (-not $env:LOCALAPPDATA -or -not $env:APPDATA) { throw 'Execute o assinador no perfil Windows do operador.' }
    $configDir = Join-Path $env:APPDATA 'Nextec\Connect'
    New-Item -ItemType Directory -Force -Path $configDir | Out-Null
    $configPath = Join-Path $configDir 'publisher-config.json'
    $keyPath = $null
    if (Test-Path -LiteralPath $configPath) {
        try { $keyPath = (Get-Content -Raw -LiteralPath $configPath | ConvertFrom-Json).keyPath } catch {}
    }
    if (-not $keyPath -or -not (Test-Path -LiteralPath $keyPath -PathType Leaf)) {
        $keyPath = Select-LocalFile 'Selecione a chave RSA cifrada do monitoramento' 'Chave privada (*.pem;*.key)|*.pem;*.key|Todos os arquivos (*.*)|*.*'
        @{ keyPath = $keyPath } | ConvertTo-Json | Set-Content -LiteralPath $configPath -Encoding UTF8
    }

    $openssl = Get-Command openssl -ErrorAction SilentlyContinue
    if (-not $openssl) {
        $gitOpenSsl = Join-Path $env:ProgramFiles 'Git\usr\bin\openssl.exe'
        if (Test-Path -LiteralPath $gitOpenSsl) { $env:PATH = "$(Split-Path -Parent $gitOpenSsl);$env:PATH" }
        else { throw 'OpenSSL não encontrado. Instale o Git for Windows ou coloque OpenSSL no PATH.' }
    }
    $python = Get-Command py -ErrorAction SilentlyContinue
    if ($python) { $pythonCommand = $python.Source; $pythonArgs = @('-3') }
    else {
        $python = Get-Command python -ErrorAction SilentlyContinue
        if (-not $python) { throw 'Python 3 não encontrado.' }
        $pythonCommand = $python.Source; $pythonArgs = @()
    }
    $helper = Join-Path $PSScriptRoot 'assinar-pedido-connect.py'
    $releaseRoot = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'Nextec\Connect\Releases'
    & $pythonCommand @pythonArgs $helper --validar-chave --chave $keyPath
    if ($LASTEXITCODE -ne 0) { throw 'A chave selecionada não está cifrada em um formato RSA PEM suportado.' }
    $securePassphrase = Read-Host 'Senha da chave RSA cifrada (sessão local de até 15 minutos)' -AsSecureString
    if ($securePassphrase.Length -eq 0) { throw 'A senha da chave não pode ficar vazia.' }
    $sessionClock = [System.Diagnostics.Stopwatch]::StartNew()
    $script:securePassphrase = $securePassphrase
    $script:sessionClock = $sessionClock
    Write-Host 'A senha fica apenas em memória nesta janela por até 15 minutos. Fechar a janela encerra a sessão.'

    $sessionTimer = New-ConnectSigningSessionTimer -OnTick {
        if (Invoke-ConnectSigningSessionTick -Elapsed $script:sessionClock.Elapsed -Passphrase $script:securePassphrase -OnExpired {
            try { $script:sessionTimer.Stop() } catch {}
            try { $script:sessionTimer.Dispose() } catch {}
            try { if ($script:signerProcess -and -not $script:signerProcess.HasExited) { Stop-ConnectProcessTree -Process $script:signerProcess } } catch {}
            [System.Windows.Forms.MessageBox]::Show(
                'A sessão de assinatura venceu após 15 minutos. Abra novamente para desbloquear a chave.',
                'Sessão encerrada',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
            [Environment]::Exit(0)
        }) { return }
    }
    $script:sessionTimer = $sessionTimer

    while (Test-ConnectSigningSessionActive -Elapsed $sessionClock.Elapsed) {
        if (-not $Pedido) { $Pedido = Select-LocalFile 'Selecione o pedido JSON baixado do painel' 'Pedido de release (*.json)|*.json|Todos os arquivos (*.*)|*.*' }
        $requestShape = Get-Content -Raw -LiteralPath $Pedido | ConvertFrom-Json
        if ($requestShape.windows -and -not $Msi) { $Msi = Select-LocalFile 'Selecione o MSI Nextec-Connect salvo localmente' 'Instalador MSI (*.msi)|*.msi|Todos os arquivos (*.*)|*.*' }
        if ($requestShape.linux.amd64 -and -not $DebAmd64) { $DebAmd64 = Select-LocalFile 'Selecione o pacote DEB amd64 salvo localmente' 'Pacote Debian (*.deb)|*.deb|Todos os arquivos (*.*)|*.*' }
        if ($requestShape.linux.arm64 -and -not $DebArm64) { $DebArm64 = Select-LocalFile 'Selecione o pacote DEB arm64 salvo localmente' 'Pacote Debian (*.deb)|*.deb|Todos os arquivos (*.*)|*.*' }
        Invoke-ConnectSigner -RequestPath $Pedido -MsiPath $Msi -Amd64Path $DebAmd64 -Arm64Path $DebArm64
        $Pedido = $null
        $Msi = $null
        $DebAmd64 = $null
        $DebArm64 = $null
        if (-not (Test-ConnectSigningSessionActive -Elapsed $sessionClock.Elapsed)) { break }
        $choice = [System.Windows.Forms.MessageBox]::Show(
            'Pedido assinado. Deseja selecionar outro pedido e MSI nesta mesma sessão?',
            'Nextec Connect — sessão local de assinatura',
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
        if ($choice -ne [System.Windows.Forms.DialogResult]::Yes) { break }
    }
} catch {
    [System.Windows.Forms.MessageBox]::Show(
        $_.Exception.Message,
        'Falha ao assinar o pedido Connect',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    exit 1
} finally {
    try { if ($sessionTimer) { $sessionTimer.Stop(); $sessionTimer.Dispose() } } catch {}
    if ($null -ne $securePassphrase) { $securePassphrase.Dispose(); $securePassphrase = $null }
    $script:securePassphrase = $null
    if ($sessionClock) { $sessionClock.Stop() }
}
