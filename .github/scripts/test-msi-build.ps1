$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$buildScript = Join-Path $PSScriptRoot 'build-msi.ps1'
$installTestScript = Join-Path $PSScriptRoot 'test-msi-install.ps1'
$updaterSource = Join-Path $repoRoot 'nextec/atualizacao'
$agentSource = Join-Path $updaterSource 'Agente-Senha-Nextec.ps1'
# Versao do pacote = versao do gerador (fonte unica); o ProductVersion do MSI e X.Y.Z.0.
$generatorVersion = ([IO.File]::ReadAllText((Join-Path $repoRoot 'rdgenerator/VERSION'))).Trim()
if ($generatorVersion -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,5}$') { throw "rdgenerator/VERSION invalid: $generatorVersion" }
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('nextec-msi-build-test-' + [Guid]::NewGuid().ToString('N'))
$sourceRoot = Join-Path $fixture 'source'
$binaryDirectory = Join-Path $sourceRoot 'rustdesk'
$packageWxs = Join-Path $sourceRoot 'res/msi/Package/Package.wxs'

function python { $global:PreprocessArgs = @($args); $global:LASTEXITCODE = 0 }
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
    $noKeyOutput = (& $buildScript -AppName 'Nextec-Connect' -PackageVersion $generatorVersion -SourceRoot $sourceRoot `
            -BinaryDirectory $binaryDirectory -UpdaterSource $updaterSource *>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'MSI fixture build without enrollment key returned a failure code' }
    $pp = @($global:PreprocessArgs)
    $ix = [array]::IndexOf($pp, '--version')
    if ($ix -lt 0 -or $pp[$ix + 1] -ne $generatorVersion) { throw "MSI --version is not the generator version ($generatorVersion): $($pp -join ' ')" }
    $rx = [array]::IndexOf($pp, '--revision-version')
    if ($rx -lt 0 -or $pp[$rx + 1] -ne '0') { throw 'MSI ProductVersion must be X.Y.Z.0 (revision 0)' }
    if ($noKeyOutput -notmatch 'SEM inscricao\.json') { throw 'Missing-key warning was not printed' }
    if (Test-Path -LiteralPath $enrollmentResource) { throw 'inscricao.json must not exist without a key' }
    if ([IO.File]::ReadAllText($packageWxs).Contains('Nextec.Enrollment')) { throw 'Enrollment component must not exist without a key' }

    # 1b) Nome dos atalhos: troca so as strings SC_* do idioma; o nome tecnico (Product, servico, ARP) continua o do app.
    $langDir = Join-Path $sourceRoot 'res/msi/Package/Language'
    New-Item -ItemType Directory -Force $langDir | Out-Null
    $langFile = Join-Path $langDir 'Package.en-us.wxl'
    $langBase = '<WixLocalization><String Id="AR_Comment" Value="Nextec-Connect" /><String Id="SC_Uninstall" Value="Uninstall Nextec-Connect" /><String Id="SC_Client" Value="Nextec-Connect" /><String Id="SC_Client_Desc" Value="Start Nextec-Connect." /><String Id="SC_Client_Tray" Value="Nextec-Connect Tray" /><String Id="Service_DisplayName" Value="Nextec-Connect Service" /></WixLocalization>'
    [IO.File]::WriteAllText($langFile, $langBase)
    $env:enroll_key = ''; $env:enroll_panel = ''
    & $buildScript -AppName 'Nextec-Connect' -ShortcutName 'Suporte Nextec' -PackageVersion $generatorVersion -SourceRoot $sourceRoot `
            -BinaryDirectory $binaryDirectory -UpdaterSource $updaterSource *>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'MSI fixture build with a shortcut name returned a failure code' }
    $lang = [IO.File]::ReadAllText($langFile)
    foreach ($expected in @('Id="SC_Client" Value="Suporte Nextec"', 'Value="Start Suporte Nextec."', 'Value="Suporte Nextec Tray"', 'Value="Uninstall Suporte Nextec"')) {
        if (-not $lang.Contains($expected)) { throw "Shortcut string was not renamed: $expected" }
    }
    foreach ($kept in @('Id="AR_Comment" Value="Nextec-Connect"', 'Id="Service_DisplayName" Value="Nextec-Connect Service"')) {
        if (-not $lang.Contains($kept)) { throw "Technical string must keep the app name: $kept" }
    }
    # nome com acento vale; nome invalido e recusado antes de tocar em qualquer arquivo
    [IO.File]::WriteAllText($langFile, $langBase)
    & $buildScript -AppName 'Nextec-Connect' -ShortcutName 'Suporte Técnico' -PackageVersion $generatorVersion -SourceRoot $sourceRoot `
            -BinaryDirectory $binaryDirectory -UpdaterSource $updaterSource *>&1 | Out-Null
    if (-not ([IO.File]::ReadAllText($langFile)).Contains('Id="SC_Client" Value="Suporte Técnico"')) { throw 'Accented shortcut name was not applied' }
    foreach ($bad in @('a/b', 'Nome.', 'x*y', '<b>', ('n' * 41), 'CON', 'nul', 'Com1', 'LPT9', 'aux.txt')) {
        [IO.File]::WriteAllText($langFile, $langBase)
        $refused = $false
        try {
            & $buildScript -AppName 'Nextec-Connect' -ShortcutName $bad -PackageVersion $generatorVersion -SourceRoot $sourceRoot `
                    -BinaryDirectory $binaryDirectory -UpdaterSource $updaterSource *>&1 | Out-Null
        } catch { $refused = $true }
        if (-not $refused) { throw "Invalid shortcut name was accepted: '$bad'" }
        if ([IO.File]::ReadAllText($langFile) -ne $langBase) { throw "Invalid shortcut name changed the language file: '$bad'" }
    }
    # so a caixa muda (NEXTEC -> Nextec): e uma troca de marca valida e precisa ser aplicada
    [IO.File]::WriteAllText($langFile, $langBase.Replace('Nextec-Connect', 'NEXTEC'))
    Copy-Item -LiteralPath (Join-Path $binaryDirectory 'Nextec-Connect.exe') -Destination (Join-Path $binaryDirectory 'NEXTEC.exe') -Force
    & $buildScript -AppName 'NEXTEC' -ShortcutName 'Nextec' -PackageVersion $generatorVersion -SourceRoot $sourceRoot `
            -BinaryDirectory $binaryDirectory -UpdaterSource $updaterSource *>&1 | Out-Null
    if (-not ([IO.File]::ReadAllText($langFile)).Contains('Id="SC_Client" Value="Nextec"')) { throw 'A shortcut name that differs only by case was not applied' }
    # sem nome de atalho, os atalhos ficam com o nome do app
    [IO.File]::WriteAllText($langFile, $langBase)
    & $buildScript -AppName 'Nextec-Connect' -PackageVersion $generatorVersion -SourceRoot $sourceRoot `
            -BinaryDirectory $binaryDirectory -UpdaterSource $updaterSource *>&1 | Out-Null
    if ([IO.File]::ReadAllText($langFile) -ne $langBase) { throw 'Language file changed without a shortcut name' }
    $hashesBefore = @{}
    foreach ($name in $scriptNames) { $hashesBefore[$name] = (Get-FileHash -LiteralPath (Join-Path $resourceDir $name) -Algorithm SHA256).Hash }

    # 2) Com chave (duas vezes, para provar que e repetivel): arquivo instalado, hashes dos scripts iguais.
    $env:enroll_key = $enrollKey; $env:enroll_panel = $enrollPanel
    $withKeyOutput = ''
    1..2 | ForEach-Object {
        $withKeyOutput += (& $buildScript -AppName 'Nextec-Connect' -PackageVersion $generatorVersion -SourceRoot $sourceRoot `
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
    # Integrado: pendente (provisionamento-agente.json) de OUTRO painel no pacote: descartado em 0 e em 20 min, chega ao self-enroll.
    $otherPanelTest = Join-Path $updaterSource 'test_provisionar_outro_painel_installed.ps1'
    $otherPanelOutput = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $otherPanelTest -InstallDir $resourceDir 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or $otherPanelOutput -notmatch 'PASS: other-panel pending journal regression') { throw "Packaged other-panel pending regression failed: $otherPanelOutput" }
    if ($otherPanelOutput.Contains($enrollKey)) { throw 'Enrollment key leaked to other-panel test output' }
    # Hash do pacote = hash registrado em FONTE-AGENTE.json (fonte unica do painel), para todos os scripts vendored.
    $fonte = [IO.File]::ReadAllText((Join-Path $updaterSource 'FONTE-AGENTE.json')) | ConvertFrom-Json
    foreach ($name in $scriptNames) {
        $registered = [string]$fonte.sha256.$name
        if (-not $registered -or (Get-FileHash -LiteralPath (Join-Path $resourceDir $name) -Algorithm SHA256).Hash -ne $registered.ToUpperInvariant()) { throw "Packaged script hash differs from FONTE-AGENTE.json: $name" }
    }    # Chave mal formada e recusada sem repetir o valor.
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
    # Convite de instalacao: o MSI entrega o proprio caminho ao coordenador (o codigo vem do nome do arquivo).
    $registerCoordinator = $wxs.SelectSingleNode('//*[local-name()="CustomAction"][@Id="Nextec.RegisterCoordinator"]')
    if (-not $registerCoordinator -or $registerCoordinator.GetAttribute('ExeCommand') -notmatch '-Registrar -Origem "\[OriginalDatabase\]"') { throw 'RegisterCoordinator does not pass [OriginalDatabase] as -Origem' }
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
        try { & $buildScript -AppName 'XPTO' -IncludeAgent 'true' -PackageVersion $generatorVersion -SourceRoot $badRoot -BinaryDirectory $badBinary -UpdaterSource $updaterSource | Out-Null }
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
            & $buildScript -AppName $case.Name -IncludeAgent $case.Flag -PackageVersion $generatorVersion -SourceRoot $caseRoot -BinaryDirectory $caseBinary -UpdaterSource $updaterSource | Out-Null
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
            # o marcador identifica o pacote: versao do gerador e hash do conjunto de scripts do agente
            if ($markerData.package_version -ne $generatorVersion -or $markerData.generator_version -ne $generatorVersion) { throw "nextec-marker.json versions are not the generator version ($label)" }
            $fonteJson = [IO.File]::ReadAllText((Join-Path $updaterSource 'FONTE-AGENTE.json')) | ConvertFrom-Json
            $fonteText = ''
            foreach ($fn in @($fonteJson.sha256.PSObject.Properties.Name | Sort-Object { $_.ToLowerInvariant() })) { $fonteText += $fn + '=' + ([string]$fonteJson.sha256.$fn).ToLowerInvariant() + "`n" }
            $expectedAgentHash = -join ([Security.Cryptography.SHA256]::Create().ComputeHash([Text.UTF8Encoding]::new($false).GetBytes($fonteText)) | ForEach-Object { $_.ToString('x2') })
            if ($markerData.agent_hash -ne $expectedAgentHash) { throw "nextec-marker.json agent_hash is wrong ($label)" }
            [xml]$caseXml = $caseText
            $registry = $caseXml.SelectSingleNode('//RegistryKey[@Key="SOFTWARE\Nextec\Agente"]')
            if (!$registry -or $registry.Root -ne 'HKLM') { throw "HKLM\SOFTWARE\Nextec\Agente registration missing ($label)" }
            $values = @{}
            foreach ($v in $registry.SelectNodes('RegistryValue')) { $values[$v.Name] = $v.Value }
            if ($values['AppName'] -ne $case.Name -or $values['InstallDir'] -ne '[INSTALLFOLDER_INNER]') { throw "Registry values are wrong ($label)" }
            # o painel do build tambem no registro (valor Painel), independente de haver chave de inscricao
            if ($values['Version'] -ne $generatorVersion -or $values['GeneratorVersion'] -ne $generatorVersion -or $values['AgentHash'] -ne $expectedAgentHash) { throw "HKLM Version/GeneratorVersion/AgentHash registry values are wrong ($label)" }
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
        try { & $buildScript -AppName 'XPTO' -IncludeAgent 'true' -PackageVersion $generatorVersion -SourceRoot $nRoot -BinaryDirectory $nBinary -UpdaterSource $updaterSource | Out-Null }
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
