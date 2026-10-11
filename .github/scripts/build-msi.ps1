param(
    [Parameter(Mandatory)][string]$AppName,
    [string]$SourceRoot = (Get-Location).Path,
    [string]$BinaryDirectory,
    [string]$UpdaterSource,
    [string]$PackageVersion = $env:package_version
)
$ErrorActionPreference = 'Stop'
if ($AppName -notmatch '^[A-Za-z0-9 _-]+$') { throw 'Invalid application name' }
if ($PackageVersion -and $PackageVersion -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}$') { throw 'Invalid package version' }
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
    $preprocessArgs = @('preprocess.py', '--app-name', $packageName, '--arp', '-d', $BinaryDirectory)
    if ($PackageVersion) { $preprocessArgs += @('--version', $PackageVersion, '--revision-version', '0') }
    python @preprocessArgs
    if ($LASTEXITCODE -ne 0) { throw 'MSI preprocessing failed' }
    if ($AppName -ceq 'Nextec-Connect') {
        if (!$UpdaterSource) { $UpdaterSource = Join-Path $PSScriptRoot 'nextec-update' }
        $updater = Join-Path $UpdaterSource 'Instalar-Nextec.ps1'
        if (!(Test-Path -LiteralPath $updater)) { throw 'Nextec updater script is missing' }
        $resourceDir = Join-Path $SourceRoot 'res/msi/Package/Resources'
        New-Item -ItemType Directory -Force -Path $resourceDir | Out-Null
        # Windows PowerShell 5.1 needs a BOM for accented text in scripts.
        [IO.File]::WriteAllText((Join-Path $resourceDir 'Instalar-Nextec.ps1'), [IO.File]::ReadAllText($updater), [Text.UTF8Encoding]::new($true))

        $packageWxs = Join-Path $SourceRoot 'res/msi/Package/Package.wxs'
        $xml = [IO.File]::ReadAllText($packageWxs)
        if (!$xml.Contains('Nextec.RegisterUpdater')) {
            $component = @'
        <DirectoryRef Id="INSTALLFOLDER_INNER">
            <Component Id="Nextec.Updater" Guid="*">
                <File Id="Nextec.UpdaterScript" Source="Resources\Instalar-Nextec.ps1" KeyPath="yes" />
            </Component>
        </DirectoryRef>
        <CustomAction Id="Nextec.RegisterUpdater" Directory="System64Folder" ExeCommand="&quot;[System64Folder]WindowsPowerShell\v1.0\powershell.exe&quot; -NoProfile -NonInteractive -ExecutionPolicy Bypass -File &quot;[INSTALLFOLDER_INNER]Instalar-Nextec.ps1&quot; -UrlBase &quot;https://painel-remoto.nex.tec.br/api/nextec/update&quot; -Registrar" Execute="deferred" Impersonate="no" Return="check" />
'@
            if ($PackageVersion) { $component = $component.Replace(' -Registrar', " -PacoteVersao $PackageVersion -Registrar") }
            if (!$xml.Contains('</Feature>') -or !$xml.Contains('</Package>') -or !$xml.Contains('</InstallExecuteSequence>')) {
                throw 'Unexpected WiX Package.wxs layout; refusing to patch MSI'
            }
            $xml = $xml.Replace('</Feature>', "            <ComponentRef Id=`"Nextec.Updater`" />`r`n`t`t</Feature>")
            $xml = $xml.Replace('</InstallExecuteSequence>', "            <Custom Action=`"Nextec.RegisterUpdater`" After=`"InstallFiles`" Condition=`"NOT REMOVE~=&quot;ALL&quot;`" />`r`n`t`t</InstallExecuteSequence>")
            $xml = $xml.Replace('</Package>', "$component`r`n`t</Package>")
            [IO.File]::WriteAllText($packageWxs, $xml, [Text.UTF8Encoding]::new($false))
        }
    }
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
