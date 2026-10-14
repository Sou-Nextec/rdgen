#requires -version 5.1
# Imported by the installed updater, never downloaded/executed from the manifest.
# RSA PKCS#1 v1.5 / SHA-256: same trust key and primitive as Nextec monitoring.
function Test-ManifestoConnect {
    param(
        [Parameter(Mandatory)][byte[]]$Dados,
        [Parameter(Mandatory)][string]$Assinatura,
        [long]$UltimaSequencia = 0,
        [string]$UltimoHash = '',
        [DateTime]$Agora = [DateTime]::UtcNow
    )
    if ($Dados.Length -eq 0 -or $Dados.Length -gt 65536 -or $Assinatura.Length -gt 4096) {
        throw 'Manifesto ou assinatura acima do limite.'
    }
    $keys = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'chaves-publicas.json') -Raw | ConvertFrom-Json
    $signature = [Convert]::FromBase64String($Assinatura.Trim())
    $signer = $null
    foreach ($key in $keys) {
        if ($key.n -notmatch '^[a-f0-9]{768,1024}$' -or $key.n.Length % 2 -ne 0 -or $key.e -ne 65537) { continue }
        $modulus = New-Object byte[] ($key.n.Length / 2)
        for ($i = 0; $i -lt $modulus.Length; $i++) { $modulus[$i] = [Convert]::ToByte($key.n.Substring($i * 2, 2), 16) }
        if ($signature.Length -ne $modulus.Length) { continue }
        $rsa = [Security.Cryptography.RSA]::Create()
        try {
            $parameters = New-Object Security.Cryptography.RSAParameters
            $parameters.Modulus = $modulus
            $parameters.Exponent = [byte[]]@(1, 0, 1)
            $rsa.ImportParameters($parameters)
            if ($rsa.VerifyData($Dados, $signature, [Security.Cryptography.HashAlgorithmName]::SHA256,
                               [Security.Cryptography.RSASignaturePadding]::Pkcs1)) { $signer = $key.id; break }
        } finally { $rsa.Dispose() }
    }
    if (-not $signer) { throw 'Assinatura não confere com a chave Nextec.' }
    $m = [Text.Encoding]::UTF8.GetString($Dados) | ConvertFrom-Json
    if ($m.produto -cne 'nextec-connect' -or $m.formato -ne 1) { throw 'Manifesto de outro produto ou formato.' }
    if ($m.sequencia -isnot [long] -and $m.sequencia -isnot [int]) { throw 'Sequência inválida.' }
    if ($m.sequencia -lt 1 -or $m.sequencia -gt 9007199254740991) { throw 'Sequência inválida.' }
    if ($m.versao -cnotmatch '^\d{1,4}\.\d{1,4}\.\d{1,4}(\.\d{1,4})?$') { throw 'Versão inválida.' }
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    # PowerShell 7 can convert ISO dates to DateTime; Windows PowerShell 5.1 keeps strings.
    $issued = if ($m.publicado_em -is [DateTime]) { $m.publicado_em.ToUniversalTime() } else {
        [DateTime]::ParseExact($m.publicado_em, 'yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture, $styles)
    }
    $expires = if ($m.valido_ate -is [DateTime]) { $m.valido_ate.ToUniversalTime() } else {
        [DateTime]::ParseExact($m.valido_ate, 'yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture, $styles)
    }
    if ($issued -gt $Agora.AddMinutes(5) -or $expires -le $issued -or $expires -gt $issued.AddDays(30) -or $expires -le $Agora) {
        throw 'Manifesto vencido ou validade inválida.'
    }
    if ($m.windows.arquivo -cne "files/nextec-acesso-$($m.versao).msi" -or $m.windows.sha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'Caminho do MSI ou hash inválido.'
    }
    if (($m.windows.tamanho -isnot [long] -and $m.windows.tamanho -isnot [int]) -or
        $m.windows.tamanho -lt 8 -or $m.windows.tamanho -gt 314572800) { throw 'Tamanho do MSI inválido.' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = ([BitConverter]::ToString($sha.ComputeHash($Dados))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
    if ($m.sequencia -lt $UltimaSequencia -or ($m.sequencia -eq $UltimaSequencia -and $hash -cne $UltimoHash)) {
        throw 'Manifesto antigo ou divergente.'
    }
    return [pscustomobject]@{ Manifesto = $m; Hash = $hash; Assinante = $signer }
}
