param(
    [Parameter(Mandatory)][string]$AppName,
    [string]$SourceRoot = (Get-Location).Path,
    [string]$BinaryDirectory
)
$ErrorActionPreference = 'Stop'
if ($AppName -notmatch '^[A-Za-z0-9 _-]+$') { throw 'Invalid application name' }
if (!$BinaryDirectory) { $BinaryDirectory = Join-Path $SourceRoot 'rustdesk' }
if (!(Test-Path -LiteralPath (Join-Path $BinaryDirectory "$AppName.exe"))) {
    throw 'Client EXE required before packaging MSI'
}
$output = Join-Path $SourceRoot 'SignOutput'
New-Item -ItemType Directory -Force -Path $output | Out-Null
Push-Location (Join-Path $SourceRoot 'res/msi')
$previousVersion = $env:VERSION
try {
    Remove-Item Env:VERSION -ErrorAction SilentlyContinue
    $packageName = $AppName -replace '\s', '_'
    if ($packageName -ne $AppName) { Copy-Item -LiteralPath (Join-Path $BinaryDirectory "$AppName.exe") -Destination (Join-Path $BinaryDirectory "$packageName.exe") -Force }
    python preprocess.py --app-name $packageName --arp -d $BinaryDirectory
    if ($LASTEXITCODE -ne 0) { throw 'MSI preprocessing failed' }
    # Restore native WiX packages explicitly, at the directory referenced by the vcxproj.
    nuget restore CustomActions/packages.config -PackagesDirectory packages -NonInteractive
    if ($LASTEXITCODE -ne 0) { throw 'WiX CustomActions package restore failed' }
    msbuild msi.sln -restore -p:RestorePackagesConfig=true -p:Configuration=Release -p:Platform=x64 /p:TargetVersion=Windows10
    if ($LASTEXITCODE -ne 0) { throw 'MSI build failed' }
    $package = 'Package/bin/x64/Release/en-us/Package.msi'
    if (!(Test-Path -LiteralPath $package) -or (Get-Item -LiteralPath $package).Length -eq 0) {
        throw 'MSBuild did not produce the MSI'
    }
    Copy-Item -LiteralPath $package -Destination (Join-Path $output 'rustdesk.msi') -Force
    Copy-Item -LiteralPath $package -Destination (Join-Path $output 'rustdesk-latest.msi') -Force
    Get-FileHash -LiteralPath $package -Algorithm SHA256
} finally {
    Pop-Location
    if ($null -ne $previousVersion) { $env:VERSION = $previousVersion }
}
