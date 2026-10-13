param(
    [Parameter(Mandatory)][string]$MsiPath,
    [string]$Version = '2.0.7',
    [string]$AgentSha256 = '',
    # Quando o MSI foi construido com a chave de inscricao de teste, exige o arquivo instalado e o seu conteudo.
    [string]$EnrollmentKey = '',
    [string]$EnrollmentPanel = ''
)
$ErrorActionPreference = 'Stop'
# Run only on disposable GitHub Windows runners, never on a user's computer.
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Installation test requires an isolated GitHub Actions runner' }
$msi = (Resolve-Path $MsiPath).Path
$log = Join-Path $env:RUNNER_TEMP 'nextec-real-install.log'
$uninstallLog = Join-Path $env:RUNNER_TEMP 'nextec-real-uninstall.log'
$agentPath = $null

function Get-NextecAclEntries {
    param([Security.AccessControl.FileSecurity]$Acl)
    return $Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
}

function Test-NextecAclGrantsWrite {
    param([Security.AccessControl.FileSystemRights]$Rights)

    $writeRights = [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    return (([int]$Rights -band [int]$writeRights) -ne 0)
}

try {
    $p = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart INSTALLPRINTER=0 /l*v `"$log`"" -Wait -PassThru -WindowStyle Hidden
    if ($p.ExitCode -notin @(0,3010)) {
        Select-String -Path $log -Pattern 'Return value 3|Nextec.RegisterUpdater|1722|Error' -Context 2,5 | Select-Object -Last 12
        throw "Actual installation failed: $($p.ExitCode). See uploaded log."
    }
    $task = Get-ScheduledTask -TaskName 'Nextec Acesso - Atualizacao' -ErrorAction Stop
    if ($task.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or $task.Triggers[0].RandomDelay -ne 'PT2H') { throw 'Updater task is not correctly configured' }
    $coordinator = Get-ScheduledTask -TaskName 'Nextec Acesso - Cadastro de agente' -ErrorAction Stop
    if ($coordinator.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or $coordinator.Triggers[0].Repetition.Interval -ne 'PT5M') { throw 'Coordinator task not registered as SYSTEM every five minutes' }
    $root = Join-Path $env:ProgramData 'Nextec/Acesso'
    foreach ($component in @('Coordenar-Agente-Nextec.ps1','Provisionar-Agente-Nextec.ps1','Agente-Senha-Nextec.ps1')) {
        $path = Join-Path $root $component
        if (!(Test-Path -LiteralPath $path)) { throw "Installed management component absent: $component" }
        foreach ($entry in (Get-NextecAclEntries -Acl (Get-Acl -LiteralPath $path))) {
            if ($entry.AccessControlType -eq 'Allow' -and $entry.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')) { throw "Unexpected access to SYSTEM component: $component" }
        }
    }
    $agents = @(Get-ChildItem -LiteralPath $env:ProgramFiles -Filter 'Agente-Senha-Nextec.ps1' -File -Recurse -ErrorAction SilentlyContinue)
    if ($agents.Count -ne 1) { throw "Expected one installed password agent payload, found $($agents.Count)" }
    $agentPath = $agents[0].FullName
    if ($AgentSha256 -and (Get-FileHash -LiteralPath $agentPath -Algorithm SHA256).Hash -ne $AgentSha256) {
        throw 'Installed password agent differs from the reviewed package source'
    }
    $enrollmentPath = Join-Path (Split-Path -Parent $agentPath) 'inscricao.json'
    if ($EnrollmentKey) {
        if (!(Test-Path -LiteralPath $enrollmentPath -PathType Leaf)) { throw 'Installed enrollment file inscricao.json is missing' }
        $enrollment = [IO.File]::ReadAllText($enrollmentPath) | ConvertFrom-Json
        if ($enrollment.v -ne 1 -or $enrollment.chave -ne $EnrollmentKey -or $enrollment.painel -ne $EnrollmentPanel) { throw 'Installed enrollment file content differs from the build input' }
        $install = [IO.File]::ReadAllText($log)
        if ($install.Contains($EnrollmentKey)) { throw 'Enrollment key leaked to the installation log' }
        # Integrado: o Provisionar INSTALADO le a chave do inscricao.json INSTALADO e faz o POST self-enroll (painel falso local).
        $integrated = Join-Path $PSScriptRoot '../../nextec/atualizacao/test_self_enroll_installed.ps1'
        $integratedOutput = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $integrated -InstallDir (Split-Path -Parent $agentPath) 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0 -or $integratedOutput -notmatch 'PASS: installed self-enrollment') { throw "Installed self-enrollment integration test failed: $integratedOutput" }
        if ($integratedOutput.Contains($EnrollmentKey)) { throw 'Enrollment key leaked to integration test output' }
    } elseif (Test-Path -LiteralPath $enrollmentPath) {
        throw 'inscricao.json must not be installed when the build had no enrollment key'
    }
    $agentAcl = Get-Acl -LiteralPath $agentPath
    foreach ($entry in (Get-NextecAclEntries -Acl $agentAcl)) {
        $sid = $entry.IdentityReference.Value
        if ($entry.AccessControlType -eq 'Allow' -and
            $sid -notin @('S-1-5-18','S-1-5-32-544') -and
            (Test-NextecAclGrantsWrite -Rights $entry.FileSystemRights)) {
            throw 'Password agent is writable by a non-administrator identity'
        }
    }
    $state = Get-ItemProperty 'HKLM:\SOFTWARE\Nextec\Acesso'
    if ($state.Versao -ne $Version) { throw 'Installed package version was not recorded' }
    $script = Join-Path $env:ProgramData 'Nextec/Acesso/Instalar-Nextec.ps1'
    if (!(Test-Path $script)) { throw 'Installed updater missing' }
    $acl = Get-Acl $script
    foreach ($entry in (Get-NextecAclEntries -Acl $acl)) {
        $sid = $entry.IdentityReference.Value
        if ($entry.AccessControlType -eq 'Allow' -and $sid -notin @('S-1-5-18','S-1-5-32-544')) { throw 'Unexpected access to privileged updater script' }
    }
    # Run again to validate repair/reinstallation and idempotent task registration.
    $repairLog = Join-Path $env:RUNNER_TEMP 'nextec-real-repair.log'
    $p = Start-Process msiexec.exe -ArgumentList "/fa `"$msi`" /qn /norestart /l*v `"$repairLog`"" -Wait -PassThru -WindowStyle Hidden
    if ($p.ExitCode -notin @(0,3010)) { throw "Repair failed: $($p.ExitCode)" }
    Write-Output 'PASS: real install/repair, SYSTEM updater task, inert password agent payload/hash/ACL, version and restricted updater ACL'
} finally {
    $p = Start-Process msiexec.exe -ArgumentList "/x `"$msi`" /qn /norestart /l*v `"$uninstallLog`"" -Wait -PassThru -WindowStyle Hidden
    if ($p.ExitCode -notin @(0,3010)) { throw "Uninstall failed: $($p.ExitCode)" }
    foreach ($taskName in @('Nextec Acesso - Atualizacao','Nextec Acesso - Cadastro de agente','Nextec Acesso - Senha')) {
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { throw "Uninstall left scheduled task: $taskName" }
    }
    if ($agentPath -and (Test-Path -LiteralPath $agentPath)) { throw 'MSI uninstall left the password agent payload behind' }
    if ($agentPath -and (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $agentPath) 'inscricao.json'))) { throw 'MSI uninstall left inscricao.json behind' }
}
