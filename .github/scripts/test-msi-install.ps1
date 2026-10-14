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

# Painel falso (so no runner descartavel): HTTPS de verdade em 443 com certificado proprio confiado na maquina, para o
# agente SYSTEM instalado percorrer o protocolo inteiro: inscricao (200), sync, proposta de senha e confirmacao.
$script:fakePanel = $null
function Start-NextecFakePanel {
    param([Parameter(Mandatory)][string]$HostName, [Parameter(Mandatory)][string]$ExpectedKey)
    $cert = New-SelfSignedCertificate -DnsName $HostName -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddDays(2)
    $cer = Join-Path $env:RUNNER_TEMP 'nextec-fake-panel.cer'
    Export-Certificate -Cert $cert -FilePath $cer | Out-Null
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Stop-Service -Name W3SVC -Force -ErrorAction SilentlyContinue
    $appId = '{6f0b5c1e-3b1a-4d63-9a3e-1f2f6a7a1c10}'
    & netsh http delete sslcert ipport=0.0.0.0:443 2>&1 | Out-Null
    $netsh = & netsh http add sslcert ipport=0.0.0.0:443 certhash=$($cert.Thumbprint) appid=$appId 2>&1
    if ($LASTEXITCODE -ne 0) { throw "netsh add sslcert failed: $netsh" }
    $state = [hashtable]::Synchronized(@{
        Calls = (New-Object System.Collections.ArrayList); Expected = $ExpectedKey
        Token = ''; PeerId = ''; Confirmed = $false; PasswordLength = 0; OperationId = ''
    })
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("https://$HostName/")
    $listener.Start()
    $ps = [PowerShell]::Create()
    [void]$ps.AddScript({
        param($listener, $state)
        while ($listener.IsListening) {
            try { $ctx = $listener.GetContext() } catch { break }
            $status = 404; $payload = @{ error = 'not_found' }
            try {
                $path = $ctx.Request.Url.AbsolutePath
                $reader = New-Object IO.StreamReader($ctx.Request.InputStream, [Text.Encoding]::UTF8)
                $raw = $reader.ReadToEnd()
                $data = $null
                if ($raw) { $data = $raw | ConvertFrom-Json }
                [void]$state.Calls.Add($path)
                switch ($path) {
                    '/api/nextec/agent/self-enroll' {
                        if ($data.enroll_key -ceq $state.Expected -and ([string]$data.id) -match '^\d{6,64}$' -and $data.uuid -and $data.proposed_token) {
                            $state.Token = [string]$data.proposed_token; $state.PeerId = [string]$data.id
                            $status = 200; $payload = @{ token = $data.proposed_token; state = 'assigned' }
                        } else { $status = 401; $payload = @{ error = 'enroll_key_invalid' } }
                    }
                    '/api/nextec/agent/sync' {
                        if ($state.Token -and $data.token -ceq $state.Token -and ([string]$data.id) -eq $state.PeerId) {
                            $status = 200
                            $payload = @{ managed = $true; transaction_v1 = $true; approve_mode = 'password'; verification_method = 'use-permanent-password'; interval = 180; rotate = $false }
                            if (-not $state.Confirmed) { $payload.rotate = $true; $payload.operation = @{ operation_id = 'op-ci-1'; pending_version = 1 } }
                        } else { $status = 401; $payload = @{ error = 'unauthorized' } }
                    }
                    '/api/nextec/agent/password' {
                        if ($state.Token -and $data.token -ceq $state.Token -and $data.operation_id -eq 'op-ci-1') {
                            $state.PasswordLength = ([string]$data.password).Length
                            $status = 200; $payload = @{ ok = $true; operation_id = 'op-ci-1'; pending_version = 1 }
                        } else { $status = 401; $payload = @{ error = 'unauthorized' } }
                    }
                    '/api/nextec/agent/confirm' {
                        if ($state.Token -and $data.token -ceq $state.Token -and $data.operation_id -eq 'op-ci-1') {
                            $state.Confirmed = $true
                            $status = 200; $payload = @{ ok = $true; active_version = 1 }
                        } else { $status = 401; $payload = @{ error = 'unauthorized' } }
                    }
                }
            } catch { $status = 500; $payload = @{ error = 'internal' } }
            $bytes = [Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress -Depth 5))
            $ctx.Response.StatusCode = $status
            $ctx.Response.ContentType = 'application/json'
            $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            $ctx.Response.Close()
        }
    }).AddArgument($listener).AddArgument($state)
    $handle = $ps.BeginInvoke()
    return [pscustomobject]@{ Listener = $listener; State = $state; Ps = $ps; Handle = $handle; Cert = $cert; Cer = $cer }
}

function Stop-NextecFakePanel {
    param($Panel)
    if (!$Panel) { return }
    try { $Panel.Listener.Stop(); $Panel.Listener.Close() } catch { }
    try { $Panel.Ps.Dispose() } catch { }
    & netsh http delete sslcert ipport=0.0.0.0:443 2>&1 | Out-Null
    Remove-Item -LiteralPath ('Cert:\LocalMachine\My\' + $Panel.Cert.Thumbprint) -Force -ErrorAction SilentlyContinue
    Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $Panel.Cert.Thumbprint } | Remove-Item -Force -ErrorAction SilentlyContinue
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

if ($EnrollmentKey -and $EnrollmentPanel) { $script:fakePanel = Start-NextecFakePanel -HostName ([Uri]$EnrollmentPanel).Host -ExpectedKey $EnrollmentKey }

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
    $codes = Wait-NextecProvisionCodes -Log $provisionLog -Skip $skip -Until '(self_enrolled|complete|network_retry|peer_not_registered|rate_limited|identity_conflict|protocol_error|unsafe_path|component_missing)'
    $text = ($codes -join "`n")
    Write-Output "provisionamento-agente.log (novas linhas):`n$text"
    if ($text -match 'identity_conflict|component_missing|unsafe_path') { throw "Real coordinator could not use the installed RustDesk service: $text" }
    if ($text -notmatch 'agent_config_unreadable|identity_changed') { throw "Dead legacy credential was not retired: $text" }
    if (!(Test-Path -LiteralPath (Join-Path $dataRoot 'agente-senha.json.anterior'))) { throw 'Dead legacy credential was not kept aside' }
    if ($script:fakePanel) {
        # Cadastro completo: inscricao aceita (HTTP 200) e credencial funcional gravada.
        if ($text -notmatch 'self_enrolled') { throw "Self-enrollment did not complete against the panel: $text" }
        $state = $script:fakePanel.State
        if ($state.Calls -notcontains '/api/nextec/agent/self-enroll') { throw 'Agent never called self-enroll' }
        if (!$state.Token -or !(Test-Path -LiteralPath (Join-Path $dataRoot 'agente-senha.json'))) { throw 'Enrollment did not produce a working agent credential' }
        $realId = ''
        $serviceExe = [regex]::Match([string]$service[0].PathName, '^\s*"([^"]+)"').Groups[1].Value
        if ($serviceExe) { try { $realId = ((& $serviceExe --get-id 2>&1 | Out-String).Trim() -split "`r?`n")[-1] } catch { } }
        if ($realId -match '^\d{6,}$' -and $state.PeerId -ne $realId) { throw "Enrolled ID $($state.PeerId) differs from the RustDesk ID $realId" }
        $senhaTask = Get-ScheduledTask -TaskName 'Nextec Acesso - Senha' -ErrorAction Stop
        if ($senhaTask.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or $senhaTask.Triggers[0].Repetition.Interval -ne 'PT5M') { throw 'Password task is not SYSTEM every five minutes' }
        # Primeira sincronizacao de senha: o agente instalado propoe a senha, aplica no RustDesk (--password, "Done!") e confirma.
        $limit = (Get-Date).AddSeconds(240)
        while (-not $state.Confirmed -and (Get-Date) -lt $limit) { Start-Sleep -Seconds 3 }
        $senhaLog = Join-Path $dataRoot 'agente-senha.log'
        $senhaText = if (Test-Path -LiteralPath $senhaLog) { (Get-Content -LiteralPath $senhaLog -Tail 20) -join "`n" } else { '(sem agente-senha.log)' }
        Write-Output "agente-senha.log:`n$senhaText"
        if (-not $state.Confirmed) {
            # diagnostico do CLI do RustDesk como administrador (sem a senha do agente): o que ele imprime e devolve
            if ($serviceExe) {
                foreach ($cli in @(@('--get-id'), @('--option', 'approve-mode'), @('--password', 'CiTeste0Descartavel9'))) {
                    $cliOut = (& $serviceExe @cli 2>&1 | Out-String).Trim()
                    Write-Output ("CLI $($cli[0]) => exit=$LASTEXITCODE saida='$($cliOut -replace '\s+', ' ')'")
                }
                Get-CimInstance Win32_Service | Where-Object { [string]$_.PathName -match '--service' } | ForEach-Object { Write-Output "servico $($_.Name) conta=$($_.StartName) estado=$($_.State)" }
                $uninst = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'RustDesk|Nextec' } | Select-Object DisplayName, InstallLocation, UninstallString
                $uninst | Format-List | Out-String | Write-Output
            }
            throw "Password sync did not complete (no confirmation reached the panel). Calls: $($state.Calls -join ', ')"
        }
        if ($state.PasswordLength -lt 16) { throw "Proposed password is too short ($($state.PasswordLength))" }
        if ($state.Calls -notcontains '/api/nextec/agent/sync' -or $state.Calls -notcontains '/api/nextec/agent/password') { throw 'Sync protocol steps are missing' }
        Write-Output 'PASS: real SYSTEM agent enrolled (HTTP 200), registered its task, proposed, applied and confirmed the password'
    } else {
        Write-Output 'AVISO: sem chave de inscricao no build; cadastro completo nao testado'
    }
    Write-Output 'PASS: real SYSTEM coordinator found the installed service, retired the dead credential and enrolled'
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
    Stop-NextecFakePanel -Panel $script:fakePanel
    $p = Start-Process msiexec.exe -ArgumentList "/x `"$msi`" /qn /norestart /l*v `"$uninstallLog`"" -Wait -PassThru -WindowStyle Hidden
    if ($p.ExitCode -notin @(0,3010)) { throw "Uninstall failed: $($p.ExitCode)" }
    foreach ($taskName in @('Nextec Acesso - Atualizacao','Nextec Acesso - Cadastro de agente','Nextec Acesso - Senha')) {
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { throw "Uninstall left scheduled task: $taskName" }
    }
    if ($agentPath -and (Test-Path -LiteralPath $agentPath)) { throw 'MSI uninstall left the password agent payload behind' }
    if ($agentPath -and (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $agentPath) 'inscricao.json'))) { throw 'MSI uninstall left inscricao.json behind' }
}
