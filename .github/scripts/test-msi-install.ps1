param(
    [Parameter(Mandatory)][string]$MsiPath,
    [string]$Version = '2.0.7',
    [string]$AgentSha256 = ''
)
$ErrorActionPreference = 'Stop'
# Run only on disposable GitHub Windows runners, never on a user's computer.
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Installation test requires an isolated GitHub Actions runner' }
$msi = (Resolve-Path $MsiPath).Path
$log = Join-Path $env:RUNNER_TEMP 'nextec-real-install.log'
$uninstallLog = Join-Path $env:RUNNER_TEMP 'nextec-real-uninstall.log'
$agentPath = $null

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
    $agents = @(Get-ChildItem -LiteralPath $env:ProgramFiles -Filter 'Agente-Senha-Nextec.ps1' -File -Recurse -ErrorAction SilentlyContinue)
    if ($agents.Count -ne 1) { throw "Expected one installed password agent payload, found $($agents.Count)" }
    $agentPath = $agents[0].FullName
    if ($AgentSha256 -and (Get-FileHash -LiteralPath $agentPath -Algorithm SHA256).Hash -ne $AgentSha256) {
        throw 'Installed password agent differs from the reviewed package source'
    }
    $agentAcl = Get-Acl -LiteralPath $agentPath
    foreach ($entry in $agentAcl.Access) {
        $sid = $entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
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
    foreach ($entry in $acl.Access) {
        $sid = $entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
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
    Unregister-ScheduledTask -TaskName 'Nextec Acesso - Atualizacao' -Confirm:$false -ErrorAction SilentlyContinue
    if ($agentPath -and (Test-Path -LiteralPath $agentPath)) { throw 'MSI uninstall left the password agent payload behind' }
}
