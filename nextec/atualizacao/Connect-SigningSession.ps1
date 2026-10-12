function Test-ConnectSigningSessionActive {
    param(
        [TimeSpan]$Elapsed,
        [DateTimeOffset]$StartedAt,
        [DateTimeOffset]$Now
    )
    if ($PSBoundParameters.ContainsKey('Elapsed')) { $duration = $Elapsed }
    else {
        if ($Now -lt $StartedAt) { return $false }
        $duration = $Now - $StartedAt
    }
    return ($duration -ge [TimeSpan]::Zero -and $duration -lt [TimeSpan]::FromMinutes(15))
}

function Invoke-ConnectSigningSessionTick {
    param(
        [Parameter(Mandatory)][TimeSpan]$Elapsed,
        [Parameter(Mandatory)][Security.SecureString]$Passphrase,
        [Parameter(Mandatory)][scriptblock]$OnExpired
    )
    if (Test-ConnectSigningSessionActive -Elapsed $Elapsed) { return $false }
    $Passphrase.Dispose()
    & $OnExpired
    return $true
}

function New-ConnectSigningSessionTimer {
    param(
        [Parameter(Mandatory)][scriptblock]$OnTick,
        [scriptblock]$TimerFactory
    )
    if ($TimerFactory) { $timer = & $TimerFactory }
    else { $timer = New-Object System.Windows.Forms.Timer }
    $timer.Interval = 1000
    $timer.add_Tick($OnTick)
    $timer.Start()
    return $timer
}

function Stop-ConnectProcessTree {
    param([Parameter(Mandatory)][System.Diagnostics.Process]$Process)
    if ($Process.HasExited) { return }
    try {
        $taskkill = Join-Path $env:WINDIR 'System32\taskkill.exe'
        if (Test-Path -LiteralPath $taskkill) {
            $killer = Start-Process -FilePath $taskkill -ArgumentList @('/PID', "$($Process.Id)", '/T', '/F') -WindowStyle Hidden -PassThru -Wait
            if ($killer.ExitCode -ne 0 -and -not $Process.HasExited) { $Process.Kill() }
        } else { $Process.Kill() }
    } catch {
        try { if (-not $Process.HasExited) { $Process.Kill() } } catch {}
    }
}

function Get-ConnectSignerArguments {
    param(
        [Parameter(Mandatory)][string]$Helper,
        [Parameter(Mandatory)][string]$Pedido,
        [string]$Msi,
        [string]$DebAmd64,
        [string]$DebArm64,
        [Parameter(Mandatory)][string]$Chave,
        [Parameter(Mandatory)][string]$SaidaRoot
    )
    $result = [System.Collections.Generic.List[string]]::new()
    $result.AddRange([string[]]@($Helper, '--pedido', $Pedido))
    if ($Msi) { $result.AddRange([string[]]@('--msi', $Msi)) }
    if ($DebAmd64) { $result.AddRange([string[]]@('--deb-amd64', $DebAmd64)) }
    if ($DebArm64) { $result.AddRange([string[]]@('--deb-arm64', $DebArm64)) }
    $result.AddRange([string[]]@('--chave', $Chave, '--saida-root', $SaidaRoot, '--passphrase-stdin'))
    return $result.ToArray()
}

function Write-ConnectSigningPassphrase {
    param(
        [Parameter(Mandatory)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory)][Security.SecureString]$Passphrase
    )
    $bstr = [IntPtr]::Zero
    $chars = New-Object char[] $Passphrase.Length
    $utf8 = $null
    try {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Passphrase)
        [Runtime.InteropServices.Marshal]::Copy($bstr, $chars, 0, $chars.Length)
        # ProcessStartInfo.StandardInputEncoding is unavailable in Windows PowerShell 5.1/.NET Framework.
        # Write UTF-8 bytes directly so Python/OpenSSL receive Unicode passphrases consistently.
        $utf8 = [System.Text.Encoding]::UTF8.GetBytes($chars)
        $stream = $Process.StandardInput.BaseStream
        $stream.Write($utf8, 0, $utf8.Length)
        [byte[]]$newline = @(10)
        $stream.Write($newline, 0, 1)
        $stream.Flush()
    } finally {
        if ($chars.Length -gt 0) { [Array]::Clear($chars, 0, $chars.Length) }
        if ($null -ne $utf8 -and $utf8.Length -gt 0) { [Array]::Clear($utf8, 0, $utf8.Length) }
        if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($bstr) }
    }
}
