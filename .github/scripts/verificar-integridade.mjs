// Trava de integridade do repositório (sem dependências). Roda no CI antes dos testes e do build:
//   node .github/scripts/verificar-integridade.mjs
// Falha, listando os arquivos, se:
//   (a) .sh, .service, .timer, Dockerfile ou workflow estiver com CRLF no repositório (o sh e o systemd do Linux rejeitam);
//   (b) .ps1 com byte não ASCII não começar com BOM UTF-8 (o Windows PowerShell 5.1 lê como ANSI e quebra o parse);
import { execFileSync } from 'node:child_process'

const git = (...a) => execFileSync('git', a, { maxBuffer: 256 * 1024 * 1024 })
const raiz = git('rev-parse', '--show-toplevel').toString().trim()
process.chdir(raiz)
const arquivos = git('ls-files', '-z').toString().split('\0').filter(Boolean)
const eol = new Map()
for (const l of git('ls-files', '--eol').toString().split('\n')) {
  const m = l.match(/^i\/(\S+)\s+w\/\S+\s+attr\/.*?\t(.+)$/)
  if (m) eol.set(m[2], m[1])
}
const erros = []
const falha = (titulo, lista, dica) => { if (lista.length) erros.push(`${titulo}\n${lista.map(f => '    ' + f).join('\n')}\n  Como corrigir: ${dica}`) }

// (a) CRLF no repositório (índice) em arquivos que o Linux lê
const linux = f => /\.(sh|yml|yaml|service|timer)$/.test(f) || /(^|\/)Dockerfile$/.test(f)
falha('(a) CRLF em arquivo lido pelo Linux (.sh, .service, .timer, Dockerfile ou workflow):',
  arquivos.filter(f => linux(f) && ['crlf', 'mixed'].includes(eol.get(f))),
  'converta para LF (dos2unix ou "git add --renormalize <arquivo>" com o .gitattributes do repositório) e use o .gitattributes do repositório')

// (b) .ps1 com não ASCII precisa de BOM
const semBom = []
for (const f of arquivos.filter(f => /\.ps1$/i.test(f))) {
  const b = git('show', ':' + f)
  const bom = b.length >= 3 && b[0] === 0xEF && b[1] === 0xBB && b[2] === 0xBF
  if (!bom && b.some(x => x > 0x7F)) semBom.push(f)
}
falha('(b) .ps1 com caracteres não ASCII sem BOM UTF-8:', semBom,
  'salve como UTF-8 com BOM (EF BB BF) e valide no Windows PowerShell 5.1 com [System.Management.Automation.Language.Parser]::ParseFile')

if (erros.length) {
  console.error('VERIFICAÇÃO DE INTEGRIDADE FALHOU\n\n' + erros.join('\n\n') + '\n')
  process.exit(1)
}
console.log(`Integridade ok: ${arquivos.length} arquivos, .ps1 conferidos.`)
