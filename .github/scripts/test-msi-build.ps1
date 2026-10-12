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

    1..2 | ForEach-Object {
        & $buildScript -AppName 'Nextec-Connect' -PackageVersion '2.0.7' -SourceRoot $sourceRoot `
            -BinaryDirectory $binaryDirectory -UpdaterSource $updaterSource | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'MSI fixture build returned a failure code' }
    }

    [xml]$wxs = [IO.File]::ReadAllText($packageWxs)
    $xmlText = $wxs.OuterXml
    foreach ($id in @('Nextec.PasswordAgent', 'Nextec.PasswordAgentScript', 'Nextec.Updater', 'Nextec.UpdaterScript', 'Nextec.RegisterUpdater')) {
        if (!$xmlText.Contains($id)) { throw "WiX output is missing $id" }
    }
    foreach ($id in @('Nextec.PasswordAgent', 'Nextec.Updater')) {
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
    Write-Output 'PASS: repeatable WiX payload registration, exact inert agent resource, no enrollment credentials'
} finally {
    Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue
}
