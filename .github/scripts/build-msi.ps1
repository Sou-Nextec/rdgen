param(
    [Parameter(Mandatory)][string]$AppName,
    [string]$SourceRoot = (Get-Location).Path,
    [string]$BinaryDirectory,
    [string]$UpdaterSource,
    [string]$PackageVersion = $env:package_version,
    # Chave de inscricao global e URL do painel (secrets do build, ja mascarados no Actions). Nunca sao impressos.
    [string]$EnrollmentKey = $env:enroll_key,
    [string]$EnrollmentPanel = $env:enroll_panel,
    # Flag explicito do build: 'false' = app de suporte avulso (sem agente/atualizador). Qualquer outro valor
    # (inclusive vazio) inclui o agente. A decisao NUNCA depende do nome do app, que pode ser qualquer um.
    [string]$IncludeAgent = $env:nx_agent,
    # Painel do build para o atualizador (somente https). Sem valor, usa enroll_panel e depois o apiServer.
    [string]$PanelUrl = '',
    [string]$ApiServer = $env:apiServer
)
$ErrorActionPreference = 'Stop'
if ($AppName -notmatch '^[A-Za-z0-9 _-]+$') { throw 'Invalid application name' }
if ($IncludeAgent -and $IncludeAgent -notin @('true','false')) { throw 'Invalid agent flag' }
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
    $withAgent = $IncludeAgent -ne 'false'
    if (!$PanelUrl) { $PanelUrl = if ($EnrollmentPanel) { $EnrollmentPanel } else { $ApiServer } }
    # Trava de seguranca: o atualizador so fala com um painel https definido no build, nunca com valor vindo da rede.
    $updateUrlBase = ''
    if ($PanelUrl -match '^https://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?/?$') { $updateUrlBase = $PanelUrl.TrimEnd('/') + '/api/nextec/update' }
    $markerFile = Join-Path $SourceRoot 'res/msi/Package/Resources/nextec-marker.json'
    if (!$withAgent) { Remove-Item -LiteralPath $markerFile -Force -ErrorAction SilentlyContinue }
    if ($withAgent) {
        if (!$UpdaterSource) { $UpdaterSource = Join-Path $PSScriptRoot 'nextec-update' }
        $updater = Join-Path $UpdaterSource 'Instalar-Nextec.ps1'
        $agent = Join-Path $UpdaterSource 'Agente-Senha-Nextec.ps1'
        if (!(Test-Path -LiteralPath $updater)) { throw 'Nextec updater script is missing' }
        if (!(Test-Path -LiteralPath $agent)) { throw 'Nextec password agent script is missing' }
        $resourceDir = Join-Path $SourceRoot 'res/msi/Package/Resources'
        New-Item -ItemType Directory -Force -Path $resourceDir | Out-Null
        # Windows PowerShell 5.1 needs a BOM for accented text in scripts.
        [IO.File]::WriteAllText((Join-Path $resourceDir 'Instalar-Nextec.ps1'), [IO.File]::ReadAllText($updater), [Text.UTF8Encoding]::new($true))
        Copy-Item -LiteralPath $agent -Destination (Join-Path $resourceDir 'Agente-Senha-Nextec.ps1') -Force
        foreach ($scriptName in @('Coordenar-Agente-Nextec.ps1','Provisionar-Agente-Nextec.ps1')) {
            $source = Join-Path $UpdaterSource $scriptName
            if (!(Test-Path -LiteralPath $source -PathType Leaf)) { throw "Management component missing: $scriptName" }
            Copy-Item -LiteralPath $source -Destination (Join-Path $resourceDir $scriptName) -Force
        }

        $packageWxs = Join-Path $SourceRoot 'res/msi/Package/Package.wxs'
        $xml = [IO.File]::ReadAllText($packageWxs)
        $packageChanged = $false
        if (!$xml.Contains('Nextec.PasswordAgent')) {
            $agentComponent = @'
        <DirectoryRef Id="INSTALLFOLDER_INNER">
            <Component Id="Nextec.PasswordAgent" Guid="*">
                <File Id="Nextec.PasswordAgentScript" Source="Resources\Agente-Senha-Nextec.ps1" KeyPath="yes" />
            </Component>
            <Component Id="Nextec.Coordinator" Guid="*">
                <File Id="Nextec.CoordinatorScript" Source="Resources\Coordenar-Agente-Nextec.ps1" KeyPath="yes" />
            </Component>
            <Component Id="Nextec.Provisioner" Guid="*">
                <File Id="Nextec.ProvisionerScript" Source="Resources\Provisionar-Agente-Nextec.ps1" KeyPath="yes" />
            </Component>
        </DirectoryRef>
'@
            if (!$xml.Contains('</Feature>') -or !$xml.Contains('</Package>')) {
                throw 'Unexpected WiX Package.wxs layout; refusing to add password agent payload'
            }
            $xml = $xml.Replace('</Feature>', "            <ComponentRef Id=`"Nextec.PasswordAgent`" />`r`n`t`t</Feature>")
            $xml = $xml.Replace('</Feature>', "            <ComponentRef Id=`"Nextec.Coordinator`" />`r`n            <ComponentRef Id=`"Nextec.Provisioner`" />`r`n`t`t</Feature>")
            $xml = $xml.Replace('</Package>', "$agentComponent`r`n`t</Package>")
            $packageChanged = $true
        }
        # Return="ignore": o script do agente/atualizador nunca desfaz a instalacao do app (antes: erro 1603 por qualquer
        # falha de script, inclusive arquivo de agente antigo). A falha fica no log do agente e o teste real confere as tarefas.
        if (!$xml.Contains('Nextec.RegisterUpdater')) {
            $component = @'
        <DirectoryRef Id="INSTALLFOLDER_INNER">
            <Component Id="Nextec.Updater" Guid="*">
                <File Id="Nextec.UpdaterScript" Source="Resources\Instalar-Nextec.ps1" KeyPath="yes" />
            </Component>
        </DirectoryRef>
        <CustomAction Id="Nextec.RegisterUpdater" Directory="System64Folder" ExeCommand="&quot;[System64Folder]WindowsPowerShell\v1.0\powershell.exe&quot; -NoProfile -NonInteractive -ExecutionPolicy Bypass -File &quot;[INSTALLFOLDER_INNER]Instalar-Nextec.ps1&quot; -Registrar" Execute="deferred" Impersonate="no" Return="ignore" />
'@
            if ($updateUrlBase) { $component = $component.Replace(' -Registrar', " -UrlBase &quot;$updateUrlBase&quot; -Registrar") }
            if ($PackageVersion) { $component = $component.Replace(' -Registrar', " -PacoteVersao $PackageVersion -Registrar") }
            if (!$xml.Contains('</Feature>') -or !$xml.Contains('</Package>') -or !$xml.Contains('</InstallExecuteSequence>')) {
                throw 'Unexpected WiX Package.wxs layout; refusing to patch MSI'
            }
            $xml = $xml.Replace('</Feature>', "            <ComponentRef Id=`"Nextec.Updater`" />`r`n`t`t</Feature>")
            $xml = $xml.Replace('</InstallExecuteSequence>', "            <Custom Action=`"Nextec.RegisterUpdater`" After=`"InstallFiles`" Condition=`"NOT REMOVE~=&quot;ALL&quot;`" />`r`n`t`t</InstallExecuteSequence>")
            $xml = $xml.Replace('</Package>', "$component`r`n`t</Package>")
            $packageChanged = $true
        }
        if (!$xml.Contains('Nextec.RegisterCoordinator')) {
            $actions = @'
        <CustomAction Id="Nextec.RegisterCoordinator" Directory="System64Folder" ExeCommand="&quot;[System64Folder]WindowsPowerShell\v1.0\powershell.exe&quot; -NoProfile -NonInteractive -ExecutionPolicy Bypass -File &quot;[INSTALLFOLDER_INNER]Coordenar-Agente-Nextec.ps1&quot; -Registrar" Execute="deferred" Impersonate="no" Return="ignore" />
        <CustomAction Id="Nextec.RemoveCoordinator" Directory="System64Folder" ExeCommand="&quot;[System64Folder]WindowsPowerShell\v1.0\powershell.exe&quot; -NoProfile -NonInteractive -ExecutionPolicy Bypass -File &quot;[INSTALLFOLDER_INNER]Coordenar-Agente-Nextec.ps1&quot; -Remover" Execute="deferred" Impersonate="no" Return="ignore" />
        <CustomAction Id="Nextec.RemoveUpdater" Directory="System64Folder" ExeCommand="&quot;[System64Folder]WindowsPowerShell\v1.0\powershell.exe&quot; -NoProfile -NonInteractive -ExecutionPolicy Bypass -File &quot;[INSTALLFOLDER_INNER]Instalar-Nextec.ps1&quot; -Remover" Execute="deferred" Impersonate="no" Return="ignore" />
'@
            $xml = $xml.Replace('</Package>', "$actions`r`n`t</Package>")
            $xml = $xml.Replace('</InstallExecuteSequence>', '            <Custom Action="Nextec.RegisterCoordinator" After="Nextec.RegisterUpdater" Condition="NOT REMOVE~=&quot;ALL&quot;" />' + "`r`n" + '            <Custom Action="Nextec.RemoveCoordinator" Before="Nextec.RemoveUpdater" Condition="REMOVE~=&quot;ALL&quot; AND NOT UPGRADINGPRODUCTCODE" />' + "`r`n" + '            <Custom Action="Nextec.RemoveUpdater" Before="RemoveFiles" Condition="REMOVE~=&quot;ALL&quot; AND NOT UPGRADINGPRODUCTCODE" />' + "`r`n`t`t</InstallExecuteSequence>")
            $packageChanged = $true
        }
        # Marcador de instalacao independente de nome: arquivo junto dos scripts + registro HKLM\SOFTWARE\Nextec\Agente.
        $upgradeCode = ''
        foreach ($wxFile in @(Get-ChildItem -LiteralPath (Join-Path $SourceRoot 'res/msi/Package') -Include '*.wxs','*.wxi' -Recurse -File -ErrorAction SilentlyContinue)) {
            $found = [regex]::Match([IO.File]::ReadAllText($wxFile.FullName), 'UpgradeCode\W{1,6}\{?([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})')
            if ($found.Success) { $upgradeCode = $found.Groups[1].Value.ToLowerInvariant(); break }
        }
        # O painel do build vai no marcador: o agente o le da pasta de dados mesmo quando o instalador saiu SEM chave de
        # inscricao (inscricao.json ausente). So o formato que o agente aceita (https://dominio em minusculas, sem porta).
        $markerData = [ordered]@{ v = 1; app = $AppName; upgrade_code = $upgradeCode }
        $markerPanel = $PanelUrl.TrimEnd('/')
        if ($markerPanel -cmatch '^https://([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$') { $markerData['painel'] = $markerPanel }
        elseif ($PanelUrl) { Write-Output "::warning title=Painel fora do formato do agente::O painel '$PanelUrl' nao e https://dominio em minusculas sem porta; o marcador do instalador sai sem painel e o agente usara o padrao." }
        $markerJson = $markerData | ConvertTo-Json -Compress
        [IO.File]::WriteAllText($markerFile, $markerJson, [Text.UTF8Encoding]::new($false))
        if (!$xml.Contains('Nextec.AgentMarker')) {
            if (!$xml.Contains('</Feature>') -or !$xml.Contains('</Package>')) { throw 'Unexpected WiX Package.wxs layout; refusing to add installation marker' }
            $markerComponent = @'
        <DirectoryRef Id="INSTALLFOLDER_INNER">
            <Component Id="Nextec.AgentMarker" Guid="*">
                <File Id="Nextec.AgentMarkerFile" Source="Resources\nextec-marker.json" KeyPath="yes" />
            </Component>
            <Component Id="Nextec.AgentRegistry" Guid="*">
                <RegistryKey Root="HKLM" Key="SOFTWARE\Nextec\Agente">
                    <RegistryValue Name="InstallDir" Type="string" Value="[INSTALLFOLDER_INNER]" KeyPath="yes" />
                    <RegistryValue Name="AppName" Type="string" Value="__NX_APP__" />
                </RegistryKey>
            </Component>
        </DirectoryRef>
'@
            $markerComponent = $markerComponent.Replace('__NX_APP__', $AppName)
            # O painel do build tambem vai para o registro (valor Painel): o agente o le mesmo sem inscricao.json e sem o arquivo de marcador.
            if ($markerData.Contains('painel')) {
                $appValue = '<RegistryValue Name="AppName" Type="string" Value="' + $AppName + '" />'
                $panelValue = '<RegistryValue Name="Painel" Type="string" Value="' + $markerData['painel'] + '" />'
                $markerComponent = $markerComponent.Replace($appValue, $appValue + "`r`n                    " + $panelValue)
            }
            $xml = $xml.Replace('</Feature>', "            <ComponentRef Id=`"Nextec.AgentMarker`" />`r`n            <ComponentRef Id=`"Nextec.AgentRegistry`" />`r`n`t`t</Feature>")
            $xml = $xml.Replace('</Package>', "$markerComponent`r`n`t</Package>")
            $packageChanged = $true
        } else {
            $refreshed = [regex]::Replace($xml, '(Name="AppName" Type="string" Value=")[^"]*(")', { param($m) $m.Groups[1].Value + $AppName + $m.Groups[2].Value })
            # painel do build no registro: remove o valor antigo e grava o atual (so quando valido)
            $refreshed = [regex]::Replace($refreshed, '\r?\n[ \t]*<RegistryValue Name="Painel"[^>]*/>', '')
            if ($markerData.Contains('painel')) {
                $panelValue = '<RegistryValue Name="Painel" Type="string" Value="' + $markerData['painel'] + '" />'
                $refreshed = [regex]::Replace($refreshed, '(<RegistryValue Name="AppName"[^>]*/>)', { param($m) $m.Groups[1].Value + "`r`n                    " + $panelValue })
            }
            if ($refreshed -ne $xml) { $xml = $refreshed; $packageChanged = $true }
        }
        if ($packageChanged) { [IO.File]::WriteAllText($packageWxs, $xml, [Text.UTF8Encoding]::new($false)) }
    }
    # Inscricao global: Resources\inscricao.json vai em componente proprio, fora dos scripts assinados (hash intacto).
    $enrollmentFile = Join-Path $SourceRoot 'res/msi/Package/Resources/inscricao.json'
    if (($EnrollmentKey -or $EnrollmentPanel) -and $withAgent) {
        if ($EnrollmentKey -notmatch '^nx1\.[0-9]{1,12}\.[A-Za-z0-9_-]{16,128}$') { throw 'Invalid enrollment key format' }
        if ($EnrollmentPanel.TrimEnd('/') -cnotmatch '^https://([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$') {
            throw 'Invalid enrollment panel URL: use https://dominio (minusculas, sem porta nem caminho), o unico formato que o agente aceita'
        }
        $resourceDir = Split-Path -Parent $enrollmentFile
        New-Item -ItemType Directory -Force -Path $resourceDir | Out-Null
        $enrollment = [ordered]@{ v = 1; painel = $EnrollmentPanel.TrimEnd('/'); chave = $EnrollmentKey } | ConvertTo-Json -Compress
        [IO.File]::WriteAllText($enrollmentFile, $enrollment, [Text.UTF8Encoding]::new($false))
        $packageWxs = Join-Path $SourceRoot 'res/msi/Package/Package.wxs'
        $xml = [IO.File]::ReadAllText($packageWxs)
        if (!$xml.Contains('Nextec.Enrollment')) {
            if (!$xml.Contains('</Feature>') -or !$xml.Contains('</Package>')) { throw 'Unexpected WiX Package.wxs layout; refusing to add enrollment payload' }
            $component = @'
        <DirectoryRef Id="INSTALLFOLDER_INNER">
            <Component Id="Nextec.Enrollment" Guid="*">
                <File Id="Nextec.EnrollmentFile" Source="Resources\inscricao.json" KeyPath="yes" />
            </Component>
        </DirectoryRef>
'@
            $xml = $xml.Replace('</Feature>', "            <ComponentRef Id=`"Nextec.Enrollment`" />`r`n`t`t</Feature>")
            $xml = $xml.Replace('</Package>', "$component`r`n`t</Package>")
            [IO.File]::WriteAllText($packageWxs, $xml, [Text.UTF8Encoding]::new($false))
        }
        Write-Output 'Inscricao global incorporada ao instalador (Resources\inscricao.json).'
    } else {
        Remove-Item -LiteralPath $enrollmentFile -Force -ErrorAction SilentlyContinue
        if ($withAgent) { Write-Output '::warning title=Instalador sem inscricao automatica::A chave de inscricao global (NX_ENROLL_KEY) nao foi fornecida; o instalador sera gerado SEM inscricao.json.' }
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
