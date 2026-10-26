#requires -version 5.1
<#
Regressao (rdgen#61, 2026-10-26): maquina instalada por convite entrava como Pendente, sem cliente.
Causa: o painel 2.12 (patch 0048) serve o MSI do convite com nome fixo, sem o codigo, e o codigo so existe na marca de
origem do arquivo (Zone.Identifier). O gerador continuava empacotando a copia antiga do coordenador, que so lia o codigo
no nome do arquivo. Os dois repositorios tinham CI verde porque cada um testava so o proprio lado.

Este teste roda contra o coordenador que o MSI deste repositorio instala e simula o arquivo exatamente como o painel o
entrega: nome nextec-acesso-<versao>.msi e marca de origem do navegador apontando para /i/<codigo>/baixar. O lado do
painel tem o contrato espelhado (nextec/testes/convite-download-contrato.test.mjs no rustdesk-api-web): se o formato
mudar la, este teste precisa mudar junto.

Funcoes extraidas do script por AST (sem executar o resto); arquivo real com fluxo alternativo NTFS.
#>
[CmdletBinding()]
param([string]$Coordinator)
$ErrorActionPreference = 'Stop'
if (-not $Coordinator) { $Coordinator = Join-Path $PSScriptRoot '..\..\nextec\atualizacao\Coordenar-Agente-Nextec.ps1' }
function Assert($value, [string]$message) { if (-not $value) { throw "ASSERT: $message" } }

$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $Coordinator).Path, [ref]$tokens, [ref]$errors)
Assert (-not $errors -or $errors.Count -eq 0) 'coordenador sem erro de sintaxe'
# carrega todas as funcoes Get-NextecInviteCode* (a entrada publica e as auxiliares que existirem)
$funcs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -like 'Get-NextecInviteCode*' }, $true)
foreach ($f in $funcs) { . ([scriptblock]::Create($f.Extent.Text)) }
Assert (Get-Command Get-NextecInviteCode -ErrorAction SilentlyContinue) 'Get-NextecInviteCode existe no coordenador empacotado'

$work = Join-Path ([IO.Path]::GetTempPath()) ('nextec-convite-agente-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$code = 'K7M2QX9P4TA8B3C5D6E2'
function New-Msi([string]$name, [string[]]$zone) {
  $path = Join-Path $work $name
  [IO.File]::WriteAllBytes($path, [byte[]](0xD0, 0xCF, 0x11, 0xE0))
  if ($zone) { Set-Content -LiteralPath $path -Stream 'Zone.Identifier' -Value $zone -Encoding ASCII }
  $path
}
try {
  # download do Chrome/Edge: nome fixo do painel, codigo so no HostUrl/ReferrerUrl
  $p = New-Msi 'nextec-acesso-2.4.1.msi' @('[ZoneTransfer]', 'ZoneId=3', "ReferrerUrl=https://painel-remoto.nex.tec.br/i/$code", "HostUrl=https://painel-remoto.nex.tec.br/i/$code/baixar")
  Assert ((Get-NextecInviteCode -Origem $p) -ceq $code) 'MSI com nome fixo do painel: codigo lido da marca de origem'

  # segundo download do mesmo arquivo (o navegador acrescenta " (1)")
  $p = New-Msi 'nextec-acesso-2.4.1 (1).msi' @('[ZoneTransfer]', 'ZoneId=3', "HostUrl=https://painel-remoto.nex.tec.br/i/$code/baixar")
  Assert ((Get-NextecInviteCode -Origem $p) -ceq $code) 'download repetido com sufixo (1)'

  # navegador que grava so o ReferrerUrl
  $p = New-Msi 'nextec-acesso-2.4.1-b.msi' @('[ZoneTransfer]', 'ZoneId=3', "ReferrerUrl=https://painel-remoto.nex.tec.br/i/$code")
  Assert ((Get-NextecInviteCode -Origem $p) -ceq $code) 'so ReferrerUrl'

  # MSI sem marca e sem codigo no nome (copiado de pendrive, por exemplo): nenhum codigo, maquina fica Pendente
  $p = New-Msi 'nextec-acesso-2.4.1-c.msi' $null
  Assert ((Get-NextecInviteCode -Origem $p) -eq '') 'sem marca: vazio'

  'OK test-convite-agente'
} finally { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
