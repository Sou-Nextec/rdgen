# Aplica o patch Nextec de deduplicacao da area de transferencia no codigo do RustDesk.
#   -Fonte    pasta com nextec_clipboard_dedup.rs e clipboardDedup.diff (em Actions: $RUNNER_TEMP/nextec-clipboard)
#   -Versao   tag do RustDesk em build. O diff foi gerado contra 1.5.0.
#   -Rustdesk raiz do checkout do RustDesk (padrao: pasta atual)
# Em 1.5.0 o diff precisa aplicar, senao falha o build. Em outra versao (ou master) avisa e segue sem o patch:
# o build continua valido, so volta o comportamento antigo da area de transferencia.
# Somente ASCII neste arquivo (roda em pwsh e em Windows PowerShell sem depender de BOM).
param(
    [Parameter(Mandatory = $true)][string]$Fonte,
    [string]$Versao = '',
    [string]$Rustdesk = '.'
)
$ErrorActionPreference = 'Stop'

$fonteAbs = (Resolve-Path -LiteralPath $Fonte).Path
$modulo = Join-Path $fonteAbs 'nextec_clipboard_dedup.rs'
$diff = Join-Path $fonteAbs 'clipboardDedup.diff'
foreach ($f in @($modulo, $diff)) {
    if (-not (Test-Path -LiteralPath $f)) { throw "Arquivo do patch ausente: $f" }
}

Push-Location -LiteralPath $Rustdesk
try {
    if (-not (Test-Path -LiteralPath 'src/clipboard.rs')) { throw "src/clipboard.rs nao encontrado em $((Get-Location).Path)" }

    # --ignore-whitespace: nos runners Windows o checkout pode vir com CRLF.
    git apply --check --ignore-whitespace $diff 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) {
        if ($Versao -eq '1.5.0') {
            throw "clipboardDedup.diff nao aplica no RustDesk 1.5.0 (patch quebrado)."
        }
        Write-Host "::warning::clipboardDedup.diff nao aplica no RustDesk '$Versao' (gerado para 1.5.0). Build segue sem o patch de deduplicacao da area de transferencia."
        return
    }

    Copy-Item -LiteralPath $modulo -Destination 'src/nextec_clipboard_dedup.rs' -Force
    git apply --ignore-whitespace $diff 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "git apply falhou depois do --check." }

    $lib = Get-Content -LiteralPath 'src/lib.rs' -Raw
    $clip = Get-Content -LiteralPath 'src/clipboard.rs' -Raw
    if ($lib -notmatch 'mod nextec_clipboard_dedup;') { throw 'src/lib.rs sem o mod nextec_clipboard_dedup.' }
    foreach ($chamada in 'nextec_clipboard_dedup::deve_aplicar', 'nextec_clipboard_dedup::enviado') {
        if (-not $clip.Contains($chamada)) { throw "src/clipboard.rs sem a chamada $chamada." }
    }
    Write-Host 'Patch de deduplicacao da area de transferencia aplicado.'
}
finally {
    Pop-Location
}
