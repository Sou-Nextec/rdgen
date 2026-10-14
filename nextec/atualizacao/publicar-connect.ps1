# Requires Windows PowerShell, Python 3, OpenSSL, and the encrypted Nextec monitoring private key.
# The passphrase is entered only in OpenSSL's prompt. The private key stays on this PC.
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

function Select-File([string]$Title, [string]$Filter) {
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title = $Title
    $dialog.Filter = $Filter
    $dialog.Multiselect = $false
    if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        throw 'Operação cancelada.'
    }
    return $dialog.FileName
}

function Select-OptionalDeb([string]$Title) {
    $answer = [System.Windows.Forms.MessageBox]::Show(
        "Deseja incluir o pacote Linux $Title nesta publicação?",
        'Atualização Nextec Connect',
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question
    )
    if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return $null }
    return Select-File "Selecione o pacote Linux $Title" 'Pacote Debian (*.deb)|*.deb|Todos os arquivos (*.*)|*.*'
}

try {
    $msi = Select-File 'Selecione o MSI Nextec Connect' 'Instalador MSI (*.msi)|*.msi'
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.OpenDatabase($msi, 0)
    $view = $database.OpenView("SELECT Value FROM Property WHERE Property='ProductVersion'")
    $view.Execute()
    $record = $view.Fetch()
    $version = if ($record) { $record.StringData(1) } else { '' }
    if ($version -notmatch '^\d{1,4}\.\d{1,4}\.\d{1,4}(\.\d{1,4})?$') {
        throw "A versão ProductVersion do MSI não é válida: $version"
    }

    $debAmd64 = Select-OptionalDeb 'amd64'
    $debArm64 = Select-OptionalDeb 'arm64'

    $appData = Join-Path $env:APPDATA 'Nextec\Connect'
    New-Item -ItemType Directory -Force -Path $appData | Out-Null
    $configPath = Join-Path $appData 'publisher-config.json'
    $keyPath = $null
    if (Test-Path -LiteralPath $configPath) {
        try { $keyPath = (Get-Content -Raw -LiteralPath $configPath | ConvertFrom-Json).keyPath } catch {}
    }
    if (-not $keyPath -or -not (Test-Path -LiteralPath $keyPath)) {
        $keyPath = Select-File 'Selecione a chave privada RSA cifrada do monitoramento' 'Chave privada (*.pem;*.key)|*.pem;*.key|Todos os arquivos (*.*)|*.*'
        @{ keyPath = $keyPath } | ConvertTo-Json | Set-Content -LiteralPath $configPath -Encoding UTF8
    }

    $openssl = Get-Command openssl -ErrorAction SilentlyContinue
    if (-not $openssl) {
        $gitOpenSsl = Join-Path $env:ProgramFiles 'Git\usr\bin\openssl.exe'
        if (Test-Path -LiteralPath $gitOpenSsl) {
            $env:PATH = "$(Split-Path -Parent $gitOpenSsl);$env:PATH"
        } else {
            throw 'OpenSSL não encontrado. Instale o Git for Windows ou coloque o OpenSSL no PATH.'
        }
    }
    $python = Get-Command py -ErrorAction SilentlyContinue
    $pythonArgs = @()
    if ($python) {
        $pythonCommand = $python.Source
        $pythonArgs += '-3'
    } else {
        $python = Get-Command python -ErrorAction SilentlyContinue
        if (-not $python) { throw 'Python 3 não encontrado. Instale o Python ou o launcher py.exe.' }
        $pythonCommand = $python.Source
    }

    $stateDir = Join-Path $env:LOCALAPPDATA 'Nextec\Connect'
    New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
    $sequenceFile = Join-Path $stateDir 'manifest-sequence.txt'
    $releaseRoot = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'Nextec\Connect\Releases'
    $lastSequence = [long]0
    if (Test-Path -LiteralPath $sequenceFile) {
        if (-not [long]::TryParse((Get-Content -Raw -LiteralPath $sequenceFile).Trim(), [ref]$lastSequence)) {
            throw 'O contador local de sequência está inválido; corrija-o antes de assinar.'
        }
    } elseif (Test-Path -LiteralPath $releaseRoot) {
        Get-ChildItem -LiteralPath $releaseRoot -Filter 'manifesto-connect.json' -File -Recurse | ForEach-Object {
            try {
                $manifest = Get-Content -Raw -LiteralPath $_.FullName | ConvertFrom-Json
                if ($manifest.produto -eq 'nextec-connect' -and $manifest.sequencia -gt $lastSequence) {
                    $lastSequence = [long]$manifest.sequencia
                }
            } catch {}
        }
    }
    if (-not (Test-Path -LiteralPath $sequenceFile) -and $lastSequence -eq 0) {
        Add-Type -AssemblyName Microsoft.VisualBasic
        $answer = [Microsoft.VisualBasic.Interaction]::InputBox(
            'Informe a última sequência já publicada. Digite 0 somente se ainda não publicou nenhuma versão.',
            'Sequência de segurança do atualizador',
            '0'
        )
        if ($answer -notmatch '^\d+

    $script = Join-Path $PSScriptRoot 'publicar-connect.py'
    $arguments = @($pythonArgs) + @($script, '--msi', $msi, '--versao', $version,
        '--sequencia', "$sequence", '--chave', $keyPath, '--saida', $output)
    if ($debAmd64) { $arguments += @('--deb-amd64', $debAmd64) }
    if ($debArm64) { $arguments += @('--deb-arm64', $debArm64) }

    Write-Host ("Versão detectada: " + $version + " | sequência: " + $sequence)
    Write-Host 'O OpenSSL pedirá a senha da chave cifrada. Ela não será salva.'
    & $pythonCommand @arguments
    if ($LASTEXITCODE -ne 0) { throw "A assinatura falhou (código $LASTEXITCODE). A sequência não foi avançada." }

    Set-Content -LiteralPath $sequenceFile -Value $sequence -Encoding ASCII
    $newline = [Environment]::NewLine
    [System.Windows.Forms.MessageBox]::Show(
        ("Manifesto assinado para a versão " + $version + "." + $newline + "Arquivos em:" + $newline + $output),
        'Nextec Connect',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
    Start-Process explorer.exe -ArgumentList $output
} catch {
    [System.Windows.Forms.MessageBox]::Show(
        $_.Exception.Message,
        'Falha ao assinar a atualização',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    exit 1
}
) { throw 'Sequência inválida ou operação cancelada.' }
        $lastSequence = [long]$answer
    }
    $sequence = $lastSequence + 1
    $output = Join-Path $releaseRoot "$version-$sequence"
    New-Item -ItemType Directory -Force -Path $releaseRoot | Out-Null

    $script = Join-Path $PSScriptRoot 'publicar-connect.py'
    $arguments = @($pythonArgs) + @($script, '--msi', $msi, '--versao', $version,
        '--sequencia', "$sequence", '--chave', $keyPath, '--saida', $output)
    if ($debAmd64) { $arguments += @('--deb-amd64', $debAmd64) }
    if ($debArm64) { $arguments += @('--deb-arm64', $debArm64) }

    Write-Host ("Versão detectada: " + $version + " | sequência: " + $sequence)
    Write-Host 'O OpenSSL pedirá a senha da chave cifrada. Ela não será salva.'
    & $pythonCommand @arguments
    if ($LASTEXITCODE -ne 0) { throw "A assinatura falhou (código $LASTEXITCODE). A sequência não foi avançada." }

    Set-Content -LiteralPath $sequenceFile -Value $sequence -Encoding ASCII
    $newline = [Environment]::NewLine
    [System.Windows.Forms.MessageBox]::Show(
        ("Manifesto assinado para a versão " + $version + "." + $newline + "Arquivos em:" + $newline + $output),
        'Nextec Connect',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
    Start-Process explorer.exe -ArgumentList $output
} catch {
    [System.Windows.Forms.MessageBox]::Show(
        $_.Exception.Message,
        'Falha ao assinar a atualização',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    exit 1
}
