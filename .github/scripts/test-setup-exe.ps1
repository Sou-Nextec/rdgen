$ErrorActionPreference = 'Stop'
$fixture = Join-Path $env:RUNNER_TEMP ('nextec-setup-test-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $fixture | Out-Null
try {
    $msi = Join-Path $fixture 'client payload.msi'
    $exe = Join-Path $fixture 'client setup.exe'
    $portable = Join-Path $fixture 'client portable.exe'
    [IO.File]::WriteAllBytes($portable, [Text.Encoding]::UTF8.GetBytes('unique portable client fixture'))
    [IO.File]::WriteAllBytes($msi, [Text.Encoding]::UTF8.GetBytes('unique embedded MSI fixture'))
    & "$PSScriptRoot/build-setup-exe.ps1" -MsiPath $msi -PortablePath $portable -OutputPath $exe -DisplayName 'Nextec "Support" <teste>'
    $bytes = [IO.File]::ReadAllBytes($exe)
    if ($bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) { throw 'Windows executable header missing' }
    $assembly = [Reflection.Assembly]::LoadFile($exe)
    $stream = $assembly.GetManifestResourceStream('Nextec.Client.msi')
    if (!$stream) { throw 'Embedded MSI resource missing' }
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $embeddedHash = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '') }
        finally { $sha.Dispose() }
    } finally { $stream.Dispose() }
    if ($embeddedHash -ne (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash) { throw 'Embedded MSI differs from supplied payload' }
    $stream = $assembly.GetManifestResourceStream('Nextec.Client.portable.exe')
    if (!$stream) { throw 'Portable resource missing' }
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $embeddedHash = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '') }
        finally { $sha.Dispose() }
    } finally { $stream.Dispose() }
    if ($embeddedHash -ne (Get-FileHash -LiteralPath $portable -Algorithm SHA256).Hash) { throw 'Portable payload changed' }
    $manifest = Get-Content (Join-Path $env:RUNNER_TEMP 'nextec-setup-wrapper.manifest') -Raw
    if (!$manifest.Contains('level="asInvoker"') -or $manifest.Contains('requireAdministrator')) { throw 'Portable mode must not require elevation' }
    $source = Get-Content (Join-Path $env:RUNNER_TEMP 'nextec-setup-wrapper.cs') -Raw
    if (!$source.Contains('Nextec Support teste Setup') -or $source.Contains('__HASH__') -or $source.Contains('__PORTABLE_HASH__') -or $source.Contains('__DISPLAY__')) { throw 'Installer substitutions failed' }
    Write-Output 'OK: real EXE compiles, sanitizes display name, and embeds the exact MSI payload'
} finally {
    # Loaded assemblies lock the EXE until PowerShell exits; runner temp is ephemeral.
    Remove-Item -LiteralPath $msi -Force -ErrorAction SilentlyContinue
}
