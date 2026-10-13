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
        if ($component.SelectNodes('File').Count -ne 1) { throw 'Automatic WiX GUID requires a single unversioned script per component' }
    }
    foreach ($id in @('Nextec.PasswordAgent', 'Nextec.PasswordAgentScript', 'Nextec.CoordinatorScript', 'Nextec.ProvisionerScript', 'Nextec.RegisterCoordinator', 'Nextec.RemoveCoordinator', 'Nextec.Updater', 'Nextec.UpdaterScript', 'Nextec.RegisterUpdater')) {
        if (!$xmlText.Contains($id)) { throw "WiX output is missing $id" }
    }
    foreach ($id in @('Nextec.Enrollment', 'Nextec.EnrollmentFile')) {
        if (!$xmlText.Contains($id)) { throw "WiX output is missing $id" }
    }
    foreach ($id in @('Nextec.PasswordAgent', 'Nextec.Updater', 'Nextec.Enrollment')) {
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
    # O agente vai em qualquer app cujo nome termine em Nextec-Connect (ex.: Client-Nextec-Connect), nao so no nome exato.
    $gate = [regex]::Match([IO.File]::ReadAllText($buildScript), "if \(\`$AppName -imatch '([^']+)'\)").Groups[1].Value
    if (!$gate) { throw 'Nextec payload gate not found in build-msi.ps1' }
    foreach ($n in @('Nextec-Connect', 'Client-Nextec-Connect')) { if ($n -notmatch $gate) { throw "Nextec payload gate rejects $n" } }
    foreach ($n in @('Suporte Nextec', 'Nextec-Connect-Old', 'RustDesk')) { if ($n -match $gate) { throw "Nextec payload gate accepts $n" } }
    Write-Output 'PASS: repeatable WiX payload registration, exact inert agent resource, enrollment file separate from script hashes, warning without key'
} finally {
    Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue
}
