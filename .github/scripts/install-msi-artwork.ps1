param(
    [Parameter(Mandatory)][string]$GeneratorUrl,
    [string]$SourceRoot = (Get-Location).Path
)
$ErrorActionPreference = 'Stop'
$base = [Uri]($GeneratorUrl.TrimEnd('/') + '/')
if ($base.Scheme -ne 'https') { throw 'MSI artwork requires HTTPS' }
$resources = Join-Path $SourceRoot 'res/msi/Package/Resources'
New-Item -ItemType Directory -Path $resources -Force | Out-Null

foreach ($asset in @(
    @{ Name = 'msi_dialog'; File = 'WixUIDialogBmp.bmp'; Width = 493; Height = 312 },
    @{ Name = 'msi_banner'; File = 'WixUIBannerBmp.bmp'; Width = 493; Height = 58 }
)) {
    $url = [Uri]::new($base, "get_artwork/$($asset.Name)")
    $temporary = Join-Path $env:RUNNER_TEMP ([Guid]::NewGuid().ToString() + '.bmp')
    try {
        try {
            Invoke-WebRequest -Uri $url -OutFile $temporary -MaximumRedirection 0 -TimeoutSec 30
        } catch {
            if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) { continue }
            throw
        }
        $bytes = [IO.File]::ReadAllBytes($temporary)
        if ($bytes.Length -lt 54 -or $bytes.Length -gt 2000000 -or
            $bytes[0] -ne 0x42 -or $bytes[1] -ne 0x4d -or
            [BitConverter]::ToInt32($bytes, 18) -ne $asset.Width -or
            [BitConverter]::ToInt32($bytes, 22) -ne $asset.Height -or
            [BitConverter]::ToInt32($bytes, 30) -ne 0) {
            throw "Invalid MSI bitmap: $($asset.Name)"
        }
        Copy-Item -LiteralPath $temporary -Destination (Join-Path $resources $asset.File) -Force
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}
