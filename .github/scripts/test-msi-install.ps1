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

# Maquina "suja" como a do campo (13/10/2026): agente antigo de 11/10 em ProgramData, com permissao herdada e
# credencial que o painel nao reconhece mais. Antes, o MSI novo falhava com 1603 (unsafe_path) e, se passasse,
# o agente ficava em 401 para sempre. Nada aqui fala com a producao: o painel do build aponta para 127.0.0.1.
$dataRoot = Join-Path $env:ProgramData 'Nextec\Acesso'
New-Item -ItemType Directory -Force -Path $dataRoot | Out-Null
Set-Content -LiteralPath (Join-Path $dataRoot 'Agente-Senha-Nextec.ps1') -Value '# agente antigo (11/10/2026), sem coordenador' -Encoding UTF8
Set-Content -LiteralPath (Join-Path $dataRoot 'agente-senha.json') -Value '{"painel":"https://painel-remoto.nex.tec.br","id":"111111111","token":"credencial-morta"}' -Encoding UTF8
if ($EnrollmentPanel) {
    $panelHost = ([Uri]$EnrollmentPanel).Host
    Add-Content -LiteralPath (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') -Value "`r`n127.0.0.1 $panelHost" -Encoding ASCII
    Clear-DnsClientCache -ErrorAction SilentlyContinue
}

function Wait-NextecProvisionCodes {
    param([string]$Log, [int]$Skip, [string]$Until, [int]$Seconds = 150)
    $limit = (Get-Date).AddSeconds($Seconds)
    do {
        Start-Sleep -Seconds 3
        $lines = @()
        if (Test-Path -LiteralPath $Log) { $lines = @(Get-Content -LiteralPath $Log | Select-Object -Skip $Skip) }
        if (($lines -join "`n") -match $Until) { return $lines }
    } while ((Get-Date) -lt $limit)
    return $lines
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

    # Agente antigo substituido sem desfazer a instalacao.
    $coordinatorLog = Join-Path $dataRoot 'coordenador.log'
    if (!(Test-Path -LiteralPath $coordinatorLog) -or ((Get-Content -LiteralPath $coordinatorLog -Raw) -notmatch 'arquivos antigos substituidos: .*Agente-Senha-Nextec\.ps1')) {
        throw 'Legacy agent file was not replaced during installation (coordenador.log)'
    }
    if ((Get-FileHash -LiteralPath (Join-Path $dataRoot 'Agente-Senha-Nextec.ps1') -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $agentPath -Algorithm SHA256).Hash) {
        throw 'Legacy agent script in ProgramData was not replaced by the packaged one'
    }

    # Ponta a ponta com o servico RustDesk real: a tarefa SYSTEM do coordenador acha o servico, le o ID,
    # aposenta a credencial morta e tenta a inscricao (que so pode falhar por rede, pois o painel aponta para 127.0.0.1).
    $installDir = (Split-Path -Parent $agentPath).TrimEnd('\')
    $service = @(Get-CimInstance -ClassName Win32_Service | Where-Object { [string]$_.PathName -match '--service' -and [string]$_.PathName -like "*$installDir*" })
    if ($service.Count -ne 1) { throw "Expected the MSI to create one RustDesk service in $installDir, found $($service.Count)" }
    if ($service[0].State -ne 'Running') { Start-Service -Name $service[0].Name; Start-Sleep -Seconds 5 }
    $provisionLog = Join-Path $dataRoot 'provisionamento-agente.log'
    # O log so passa a existir depois da instalacao: e lido inteiro, inclusive a execucao agendada que ja tenha rodado.
    $skip = 0
    Start-ScheduledTask -TaskName 'Nextec Acesso - Cadastro de agente'
    $codes = Wait-NextecProvisionCodes -Log $provisionLog -Skip $skip -Until '(network_retry|peer_not_registered|rate_limited|self_enrolled|identity_conflict|protocol_error|unsafe_path|component_missing)'
    $text = ($codes -join "`n")
    Write-Output "provisionamento-agente.log (novas linhas):`n$text"
    if ($text -match 'identity_conflict|component_missing|unsafe_path') { throw "Real coordinator could not use the installed RustDesk service: $text" }
    if ($text -notmatch 'agent_config_unreadable|identity_changed') { throw "Dead legacy credential was not retired: $text" }
    if ($EnrollmentKey -and $text -notmatch 'network_retry') { throw "Self-enrollment was not attempted after discovery: $text" }
    if (Test-Path -LiteralPath (Join-Path $dataRoot 'agente-senha.json')) { throw 'Dead legacy credential is still active' }
    if (!(Test-Path -LiteralPath (Join-Path $dataRoot 'agente-senha.json.anterior'))) { throw 'Dead legacy credential was not kept aside' }
    Write-Output 'PASS: real SYSTEM coordinator found the installed service, retired the dead credential and attempted enrollment'
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
