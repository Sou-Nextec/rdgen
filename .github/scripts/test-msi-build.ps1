$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$buildScript = Join-Path $PSScriptRoot 'build-msi.ps1'
$installTestScript = Join-Path $PSScriptRoot 'test-msi-install.ps1'
$updaterSource = Join-Path $repoRoot 'nextec/atualizacao'
$agentSource = Join-Path $updaterSource 'Agente-Senha-Nextec.ps1'
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('nextec-msi-build-test-' + [Guid]::NewGuid().ToString('N'))
$sourceRoot = Join-Path $fixture 'source'
$binaryDirectory = Join-Path $sourceRoot 'rustdesk'
$packageWxs = Join-Path $sourceRoot 'res/msi/Package/Package.wxs'

function python { $global:LASTEXITCODE = 0 }
function nuget { $global:LASTEXITCODE = 0 }
function msbuild {
    $global:LASTEXITCODE = 0
    $fakeMsi = Join-Path (Get-Location).Path 'Package/bin/x64/Release/en-us/Package.msi'
    New-Item -ItemType Directory -Force (Split-Path $fakeMsi) | Out-Null
    [IO.File]::WriteAllBytes($fakeMsi, [byte[]]@(0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1))
}

try {
    $testAst = [System.Management.Automation.Language.Parser]::ParseFile($installTestScript, [ref]$null, [ref]$null)
    $aclPredicateAst = $testAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Test-NextecAclGrantsWrite' }, $true)
    if (!$aclPredicateAst) { throw 'ACL write predicate is missing from installation test' }
    . ([scriptblock]::Create($aclPredicateAst.Extent.Text))
    $aclReaderAst = $testAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-NextecAclEntries' }, $true)
    if (!$aclReaderAst) { throw 'SID ACL reader missing' }
    . ([scriptblock]::Create($aclReaderAst.Extent.Text))
    $unknownSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-21-123456789-234567890-345678901-54321')
    $aclFixture = [Security.AccessControl.FileSecurity]::new()
    $aclFixture.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($unknownSid, [Security.AccessControl.FileSystemRights]::Read, [Security.AccessControl.AccessControlType]::Allow))
    $aclEntries = @(Get-NextecAclEntries -Acl $aclFixture)
    if ($aclEntries.Count -ne 1 -or $aclEntries[0].IdentityReference.Value -ne $unknownSid.Value) { throw 'Unresolvable SID was not preserved by ACL inspection' }
    $rightsType = [Security.AccessControl.FileSystemRights]
    foreach ($readRights in @($rightsType::Read, $rightsType::ReadAndExecute)) {
        if (Test-NextecAclGrantsWrite -Rights $readRights) { throw "Read-only ACL right was treated as write: $readRights" }
    }
    foreach ($writeRight in @($rightsType::Write, $rightsType::Modify, $rightsType::FullControl)) {
        if (-not (Test-NextecAclGrantsWrite -Rights $writeRight)) { throw "Write ACL right was not detected: $writeRight" }
    }

    New-Item -ItemType Directory -Force $binaryDirectory, (Split-Path $packageWxs) | Out-Null
    [IO.File]::WriteAllText((Join-Path $binaryDirectory 'Nextec-Connect.exe'), 'fixture')
    [IO.File]::WriteAllText($packageWxs, '<Wix><Package><Feature></Feature><InstallExecuteSequence></InstallExecuteSequence></Package></Wix>')

    $resourceDir = Join-Path $sourceRoot 'res/msi/Package/Resources'
    $enrollmentResource = Join-Path $resourceDir 'inscricao.json'
    $enrollKey = 'nx1.1790000000.AbCdEf0123456789_-AbCdEf0123456789'
    $enrollPanel = 'https://painel-remoto.nex.tec.br'
    $scriptNames = @('Agente-Senha-Nextec.ps1', 'Coordenar-Agente-Nextec.ps1', 'Provisionar-Agente-Nextec.ps1')

    # 1) Sem chave: o build continua, avisa com clareza e nao produz inscricao.json nem componente.
    $env:enroll_key = ''; $env:enroll_panel = ''
    $noKeyOutput = (& $buildScript -AppName 'Nextec-Connect' -PackageVersion '2.0.7' -SourceRoot $sourceRoot `
            -BinaryDirectory $binaryDirectory -UpdaterSource $updaterSource *>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'MSI fixture build without enrollment key returned a failure code' }
    if ($noKeyOutput -notmatch 'SEM inscricao\.json') { throw 'Missing-key warning was not printed' }
    if (Test-Path -LiteralPath $enrollmentResource) { throw 'inscricao.json must not exist without a key' }
    if ([IO.File]::ReadAllText($packageWxs).Contains('Nextec.Enrollment')) { throw 'Enrollment component must not exist without a key' }
    $hashesBefore = @{}
    foreach ($name in $scriptNames) { $hashesBefore[$name] = (Get-FileHash -LiteralPath (Join-Path $resourceDir $name) -Algorithm SHA256).Hash }

    # 2) Com chave (duas vezes, para provar que e repetivel): arquivo instalado, hashes dos scripts iguais.
    $env:enroll_key = $enrollKey; $env:enroll_panel = $enrollPanel
    $withKeyOutput = ''
    1..2 | ForEach-Object {
        $withKeyOutput += (& $buildScript -AppName 'Nextec-Connect' -PackageVersion '2.0.7' -SourceRoot $sourceRoot `
                -BinaryDirectory $binaryDirectory -UpdaterSource $updaterSource *>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) { throw 'MSI fixture build returned a failure code' }
    }
    Remove-Item Env:enroll_key, Env:enroll_panel -ErrorAction SilentlyContinue
    if ($withKeyOutput.Contains($enrollKey) -or $noKeyOutput.Contains($enrollKey)) { throw 'Enrollment key leaked to build output' }
    if ($withKeyOutput -match 'SEM inscricao\.json') { throw 'Warning printed although the key was supplied' }
    if (!(Test-Path -LiteralPath $enrollmentResource)) { throw 'inscricao.json resource is missing' }
    $enrollment = [IO.File]::ReadAllText($enrollmentResource) | ConvertFrom-Json
    if ($enrollment.v -ne 1 -or $enrollment.painel -ne $enrollPanel -or $enrollment.chave -ne $enrollKey) { throw 'inscricao.json content is wrong' }
    foreach ($name in $scriptNames) {
        if ((Get-FileHash -LiteralPath (Join-Path $resourceDir $name) -Algorithm SHA256).Hash -ne $hashesBefore[$name]) { throw "Script hash changed by enrollment: $name" }
    }
    # Os componentes empacotados sao exatamente as fontes revisadas (inclusive Coordenar/Provisionar).
    foreach ($name in $scriptNames) {
        if ((Get-FileHash -LiteralPath (Join-Path $resourceDir $name) -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath (Join-Path $updaterSource $name) -Algorithm SHA256).Hash) { throw "MSI resource differs from the reviewed source: $name" }
    }
    # Integrado: o Provisionar empacotado le a chave do inscricao.json empacotado e faz o POST self-enroll.
    $integrated = Join-Path $updaterSource 'test_self_enroll_installed.ps1'
    $integratedOutput = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $integrated -InstallDir $resourceDir 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or $integratedOutput -notmatch 'PASS: installed self-enrollment') { throw "Packaged self-enrollment integration test failed: $integratedOutput" }
    if ($integratedOutput.Contains($enrollKey)) { throw 'Enrollment key leaked to integration test output' }
    # Integrado: o agente empacotado recebe 401 tres vezes de um painel falso local, descarta a credencial e refaz o cadastro.
    $authTest = Join-Path $updaterSource 'test_agent_401_integration.ps1'
    $authOutput = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $authTest -InstallDir $resourceDir 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or $authOutput -notmatch 'PASS: agent 401 recovery') { throw "Packaged agent 401 recovery integration test failed: $authOutput" }
    # Chave mal formada e recusada sem repetir o valor.
    $env:enroll_key = 'nx1.1.curta'; $env:enroll_panel = $enrollPanel
    $rejected = $false
    try { & $buildScript -AppName 'Nextec-Connect' -SourceRoot $sourceRoot -BinaryDirectory $binaryDirectory -UpdaterSource $updaterSource | Out-Null }
    catch { $rejected = ($_.Exception.Message -eq 'Invalid enrollment key format') }
    Remove-Item Env:enroll_key, Env:enroll_panel -ErrorAction SilentlyContinue
    if (!$rejected) { throw 'Malformed enrollment key was accepted' }

    [xml]$wxs = [IO.File]::ReadAllText($packageWxs)
    $xmlText = $wxs.OuterXml
    foreach ($component in $wxs.SelectNodes('//Component[@Guid="*"]')) {
        if ($component.SelectNodes('File').Count + $component.SelectNodes('RegistryKey').Count -ne 1) { throw 'Automatic WiX GUID requires a single unversioned script or registry key per component' }
    }
    foreach ($id in @('Nextec.PasswordAgent', 'Nextec.PasswordAgentScript', 'Nextec.CoordinatorScript', 'Nextec.ProvisionerScript', 'Nextec.RegisterCoordinator', 'Nextec.RemoveCoordinator', 'Nextec.Updater', 'Nextec.UpdaterScript', 'Nextec.RegisterUpdater')) {
        if (!$xmlText.Contains($id)) { throw "WiX output is missing $id" }
    }
    foreach ($id in @('Nextec.Enrollment', 'Nextec.EnrollmentFile')) {
        if (!$xmlText.Contains($id)) { throw "WiX output is missing $id" }
    }
    foreach ($id in @('Nextec.PasswordAgent', 'Nextec.Updater', 'Nextec.Enrollment', 'Nextec.AgentMarker', 'Nextec.AgentRegistry')) {
        if ([regex]::Matches($xmlText, "Component Id=`"$id`"").Count -ne 1) { throw "WiX component $id was duplicated on rebuild" }
        if ([regex]::Matches($xmlText, "ComponentRef Id=`"$id`"").Count -ne 1) { throw "WiX feature reference $id was duplicated on rebuild" }
    }
    if ($xmlText -match 'Nextec\.PasswordAgent[^<]*(CustomAction|ChaveAgente|bootstrap)') {
        throw 'Password agent must remain an inert payload without enrollment action or embedded credential'
    }

    $agentResource = Join-Path $sourceRoot 'res/msi/Package/Resources/Agente-Senha-Nextec.ps1'
    $expectedHash = (Get-FileHash -LiteralPath $agentSource -Algorithm SHA256).Hash
    $actualHash = (Get-FileHash -LiteralPath $agentResource -Algorithm SHA256).Hash
    if ($actualHash -ne $expectedHash) { throw 'MSI resource differs from the reviewed password agent source' }
    if (!$xmlText.Contains('Source="Resources\inscricao.json"')) { throw 'Enrollment component must point to inscricao.json' }
    if ($xmlText.Contains($enrollKey)) { throw 'Enrollment key must never be embedded in Package.wxs or a custom action' }
    # Nome livre: o agente depende so do flag nx_agent (IncludeAgent), nunca do nome do app. Fixture limpo por caso.
    $upgradeCodeFixture = '1d2a3b4c-5e6f-4a1b-8c2d-0123456789ab'
    $cases = @(
        @{ Name = 'XPTO'; Flag = 'true'; Agent = $true; Panel = 'https://painel.xpto.example' },
        @{ Name = 'XPTO'; Flag = ''; Agent = $true; Panel = 'https://painel.xpto.example' },
        @{ Name = 'Client-Nextec-Connect'; Flag = 'true'; Agent = $true; Panel = 'https://suporte.cliente.example' },
        @{ Name = 'Nextec-Connect'; Flag = 'true'; Agent = $true; Panel = 'https://painel.xpto.example' },
        @{ Name = 'Nextec-Connect'; Flag = 'false'; Agent = $false; Panel = 'https://painel.xpto.example' },
        @{ Name = 'Suporte-XPTO'; Flag = 'false'; Agent = $false; Panel = 'https://painel.xpto.example' }
    )
    # Painel que o agente recusaria (http, porta, caminho, maiuscula): o build falha em vez de gerar instalador que nunca se inscreve.
    foreach ($badPanel in @('http://painel.xpto.example', 'https://painel.xpto.example:8443', 'https://painel.xpto.example/painel', 'https://Painel.Xpto.example')) {
        $badRoot = Join-Path $fixture ('bad-' + [Guid]::NewGuid().ToString('N'))
        $badBinary = Join-Path $badRoot 'rustdesk'
        $badWxs = Join-Path $badRoot 'res/msi/Package/Package.wxs'
        New-Item -ItemType Directory -Force $badBinary, (Split-Path $badWxs) | Out-Null
        [IO.File]::WriteAllText((Join-Path $badBinary 'XPTO.exe'), 'fixture')
        [IO.File]::WriteAllText($badWxs, '<Wix><Package><Feature></Feature><InstallExecuteSequence></InstallExecuteSequence></Package></Wix>')
        $env:enroll_key = $enrollKey; $env:enroll_panel = $badPanel
        $refused = $false
        try { & $buildScript -AppName 'XPTO' -IncludeAgent 'true' -PackageVersion '2.0.7' -SourceRoot $badRoot -BinaryDirectory $badBinary -UpdaterSource $updaterSource | Out-Null }
        catch { $refused = $_.Exception.Message -match 'Invalid enrollment panel URL' }
        finally { Remove-Item Env:enroll_key, Env:enroll_panel -ErrorAction SilentlyContinue }
        if (!$refused) { throw "Build accepted a panel the agent rejects: $badPanel" }
    }
    foreach ($case in $cases) {
        $label = "$($case.Name) flag='$($case.Flag)'"
        $caseRoot = Join-Path $fixture ('case-' + [Guid]::NewGuid().ToString('N'))
        $caseBinary = Join-Path $caseRoot 'rustdesk'
        $caseWxs = Join-Path $caseRoot 'res/msi/Package/Package.wxs'
        New-Item -ItemType Directory -Force $caseBinary, (Split-Path $caseWxs) | Out-Null
        [IO.File]::WriteAllText((Join-Path $caseBinary ($case.Name + '.exe')), 'fixture')
        [IO.File]::WriteAllText($caseWxs, '<Wix><?define UpgradeCode = "{' + $upgradeCodeFixture.ToUpperInvariant() + '}"?><Package><Feature></Feature><InstallExecuteSequence></InstallExecuteSequence></Package></Wix>')
        $env:enroll_key = $enrollKey; $env:enroll_panel = $case.Panel
        try {
            & $buildScript -AppName $case.Name -IncludeAgent $case.Flag -PackageVersion '2.0.7' -SourceRoot $caseRoot -BinaryDirectory $caseBinary -UpdaterSource $updaterSource | Out-Null
        } finally { Remove-Item Env:enroll_key, Env:enroll_panel -ErrorAction SilentlyContinue }
        $caseText = [IO.File]::ReadAllText($caseWxs)
        $caseResources = Join-Path $caseRoot 'res/msi/Package/Resources'
        $caseMarker = Join-Path $caseResources 'nextec-marker.json'
        if ($caseText -match 'nex\.tec\.br') { throw "Fixed domain found in MSI ($label)" }
        if ($caseText.Contains($enrollKey)) { throw "Enrollment key embedded in Package.wxs ($label)" }
        if ($case.Agent) {
            foreach ($id in @('Nextec.PasswordAgent', 'Nextec.Coordinator', 'Nextec.Provisioner', 'Nextec.RegisterUpdater', 'Nextec.RegisterCoordinator', 'Nextec.AgentMarker', 'Nextec.AgentRegistry')) {
                if (!$caseText.Contains($id)) { throw "Agent payload is missing $id ($label)" }
            }
            # script do agente nunca desfaz a instalacao do app (erro 1603)
            foreach ($ca in ([regex]::Matches($caseText, '<CustomAction Id="Nextec\.[^"]+"[^>]*>'))) {
                if ($ca.Value -notmatch 'Return="ignore"') { throw "Nextec custom action can roll back the app install: $($ca.Value) ($label)" }
            }
            if (!(Test-Path -LiteralPath (Join-Path $caseResources 'Coordenar-Agente-Nextec.ps1'))) { throw "Coordinator script not packaged ($label)" }
            if (!(Test-Path -LiteralPath $caseMarker)) { throw "nextec-marker.json missing ($label)" }
            $markerData = [IO.File]::ReadAllText($caseMarker) | ConvertFrom-Json
            if ($markerData.v -ne 1 -or $markerData.app -ne $case.Name -or $markerData.upgrade_code -ne $upgradeCodeFixture) { throw "nextec-marker.json content is wrong ($label)" }
            # o painel do build fica no marcador (o agente le da pasta de dados, mesmo sem inscricao.json)
            if ($markerData.painel -ne $case.Panel) { throw "nextec-marker.json does not carry the build panel ($label)" }
            [xml]$caseXml = $caseText
            $registry = $caseXml.SelectSingleNode('//RegistryKey[@Key="SOFTWARE\Nextec\Agente"]')
            if (!$registry -or $registry.Root -ne 'HKLM') { throw "HKLM\SOFTWARE\Nextec\Agente registration missing ($label)" }
            $values = @{}
            foreach ($v in $registry.SelectNodes('RegistryValue')) { $values[$v.Name] = $v.Value }
            if ($values['AppName'] -ne $case.Name -or $values['InstallDir'] -ne '[INSTALLFOLDER_INNER]') { throw "Registry values are wrong ($label)" }
            # o painel do build tambem no registro (valor Painel), independente de haver chave de inscricao
            if ($values['Painel'] -ne $case.Panel) { throw "HKLM Painel registry value does not carry the build panel ($label)" }
            $expectedUrl = $case.Panel + '/api/nextec/update'
            if ($case.Panel.StartsWith('https://')) {
                if (!$caseText.Contains('-UrlBase &quot;' + $expectedUrl + '&quot;')) { throw "Updater does not use the build panel ($label)" }
            } elseif ($caseText.Contains('-UrlBase')) { throw "Updater received a non-https panel ($label)" }
        } else {
            foreach ($id in @('Nextec.', 'Instalar-Nextec', 'Agente-Senha', 'Coordenar-Agente', 'Provisionar-Agente')) {
                if ($caseText.Contains($id)) { throw "Support app must not carry the agent: found $id ($label)" }
            }
            if (Test-Path -LiteralPath $caseMarker) { throw "Support app must not carry nextec-marker.json ($label)" }
            if (Test-Path -LiteralPath (Join-Path $caseResources 'inscricao.json')) { throw "Support app must not carry the enrollment key ($label)" }
        }
    }
    # Instalador SEM chave de inscricao (painel inacessivel no build): o painel continua no marcador, para o agente
    # nao cair no endereco padrao. Painel fora do formato do agente sai sem o campo.
    foreach ($case in @(@{ Api = 'https://painel.semchave.example'; Painel = 'https://painel.semchave.example' }, @{ Api = 'painel.semchave.example:21114'; Painel = $null })) {
        $nRoot = Join-Path $fixture ('nokey-' + [Guid]::NewGuid().ToString('N'))
        $nBinary = Join-Path $nRoot 'rustdesk'
        $nWxs = Join-Path $nRoot 'res/msi/Package/Package.wxs'
        New-Item -ItemType Directory -Force $nBinary, (Split-Path $nWxs) | Out-Null
        [IO.File]::WriteAllText((Join-Path $nBinary 'XPTO.exe'), 'fixture')
        [IO.File]::WriteAllText($nWxs, '<Wix><?define UpgradeCode = "{' + $upgradeCodeFixture.ToUpperInvariant() + '}"?><Package><Feature></Feature><InstallExecuteSequence></InstallExecuteSequence></Package></Wix>')
        $env:enroll_key = ''; $env:enroll_panel = ''; $env:apiServer = $case.Api
        try { & $buildScript -AppName 'XPTO' -IncludeAgent 'true' -PackageVersion '2.0.7' -SourceRoot $nRoot -BinaryDirectory $nBinary -UpdaterSource $updaterSource | Out-Null }
        finally { Remove-Item Env:enroll_key, Env:enroll_panel, Env:apiServer -ErrorAction SilentlyContinue }
        $nResources = Join-Path $nRoot 'res/msi/Package/Resources'
        if (Test-Path -LiteralPath (Join-Path $nResources 'inscricao.json')) { throw 'inscricao.json present without a key' }
        $nMarker = [IO.File]::ReadAllText((Join-Path $nResources 'nextec-marker.json')) | ConvertFrom-Json
        if ($nMarker.painel -ne $case.Painel) { throw "marker panel without enrollment key is wrong for $($case.Api): $($nMarker.painel)" }
        # sem chave de inscricao o registro tambem leva o painel valido; painel fora do formato sai sem o valor
        $nText = [IO.File]::ReadAllText($nWxs)
        [xml]$nXml = $nText
        $nRegistry = $nXml.SelectSingleNode('//RegistryKey[@Key="SOFTWARE\Nextec\Agente"]')
        if (!$nRegistry) { throw "HKLM Nextec Agente registration missing without key for $($case.Api)" }
        $nPanelValue = @($nRegistry.SelectNodes('RegistryValue') | Where-Object { $_.Name -eq 'Painel' })
        if ($case.Painel) { if ($nPanelValue.Count -ne 1 -or $nPanelValue[0].Value -ne $case.Painel) { throw "HKLM Painel value is wrong without key for $($case.Api)" } }
        elseif ($nPanelValue.Count -ne 0) { throw "HKLM Painel value must be absent for an invalid panel ($($case.Api))" }
    }
    if ([IO.File]::ReadAllText($buildScript) -match "AppName\s+-imatch") { throw 'build-msi.ps1 still decides the agent by app name' }
    Write-Output 'PASS: repeatable WiX payload registration, exact inert agent resource, enrollment file separate from script hashes, warning without key'
} finally {
    Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue
}
