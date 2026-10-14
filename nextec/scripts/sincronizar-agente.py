#!/usr/bin/env python3
"""Fonte unica dos scripts Windows do agente Nextec.

Os scripts que o MSI instala (agente de senha, coordenador, provisionamento, atualizador) sao mantidos no
repositorio do painel (Sou-Nextec/rustdesk-api-web, pasta nextec/atualizacao). Aqui ficam copias identicas,
byte a byte, de um commit fixo, registradas em nextec/atualizacao/FONTE-AGENTE.json.

  python nextec/scripts/sincronizar-agente.py --commit <sha>   copia do painel e atualiza o registro
  python nextec/scripts/sincronizar-agente.py --verificar      confere os hashes locais (sem rede)
  python nextec/scripts/sincronizar-agente.py --verificar --remoto
                                                               confere tambem contra o painel no commit registrado

Nunca edite esses arquivos a mao neste repositorio: corrija no painel e sincronize.
"""
import argparse
import hashlib
import json
import pathlib
import re
import sys
import urllib.request

REPO = 'Sou-Nextec/rustdesk-api-web'
PASTA_ORIGEM = 'nextec/atualizacao'
ARQUIVOS = [
    'Agente-Senha-Nextec.ps1',
    'Coordenar-Agente-Nextec.ps1',
    'Provisionar-Agente-Nextec.ps1',
    'Instalar-Nextec.ps1',
    'Manifesto-Connect.ps1',
]
RAIZ = pathlib.Path(__file__).resolve().parents[2]
DESTINO = RAIZ / 'nextec' / 'atualizacao'
REGISTRO = DESTINO / 'FONTE-AGENTE.json'
PROVENIENCIA = DESTINO / 'Agente-Senha-Nextec.provenance.txt'


def sha256(dados):
    return hashlib.sha256(dados).hexdigest()


def baixar(commit, nome):
    url = 'https://raw.githubusercontent.com/%s/%s/%s/%s' % (REPO, commit, PASTA_ORIGEM, nome)
    with urllib.request.urlopen(url, timeout=30) as resposta:
        return resposta.read()


def sincronizar(commit):
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        sys.exit('Informe o SHA completo (40 caracteres) do commit do painel.')
    hashes = {}
    for nome in ARQUIVOS:
        dados = baixar(commit, nome)
        if nome.endswith('.ps1') and not dados.startswith(b'\xef\xbb\xbf'):
            try:
                dados.decode('ascii')
            except UnicodeDecodeError:
                sys.exit('%s tem acento sem BOM no painel; corrija la antes de sincronizar.' % nome)
        (DESTINO / nome).write_bytes(dados)
        hashes[nome] = sha256(dados)
    registro = {'repositorio': REPO, 'pasta': PASTA_ORIGEM, 'commit': commit, 'sha256': hashes}
    REGISTRO.write_text(json.dumps(registro, indent=2, ensure_ascii=False) + '\n', encoding='utf-8', newline='\n')
    PROVENIENCIA.write_text(
        'Source: https://github.com/%s\n'
        'Commit: %s\n'
        'Path: %s/Agente-Senha-Nextec.ps1\n'
        'vendored file SHA-256: %s\n'
        'State: copiado por nextec/scripts/sincronizar-agente.py; a lista completa e os hashes estao em FONTE-AGENTE.json.\n'
        % (REPO, commit, PASTA_ORIGEM, hashes['Agente-Senha-Nextec.ps1']),
        encoding='utf-8', newline='\n')
    print('Sincronizado com %s@%s: %s' % (REPO, commit[:12], ', '.join(ARQUIVOS)))


def verificar(remoto):
    try:
        registro = json.loads(REGISTRO.read_text(encoding='utf-8'))
    except FileNotFoundError:
        sys.exit('FONTE-AGENTE.json ausente: rode --commit <sha> para sincronizar com o painel.')
    erros = []
    if sorted(registro.get('sha256', {})) != sorted(ARQUIVOS):
        erros.append('FONTE-AGENTE.json nao lista exatamente os arquivos sincronizados: %s' % ', '.join(ARQUIVOS))
    for nome, esperado in registro.get('sha256', {}).items():
        caminho = DESTINO / nome
        if not caminho.is_file():
            erros.append('%s ausente' % nome)
            continue
        atual = sha256(caminho.read_bytes())
        if atual != esperado:
            erros.append('%s foi alterado neste repositorio (hash %s, registrado %s). Corrija no painel e sincronize.' % (nome, atual[:12], esperado[:12]))
        if remoto:
            origem = sha256(baixar(registro['commit'], nome))
            if origem != esperado:
                erros.append('%s difere do painel em %s' % (nome, registro['commit'][:12]))
    linha = re.search(r'^vendored file SHA-256: ([0-9a-f]{64})$', PROVENIENCIA.read_text(encoding='utf-8'), re.M)
    if not linha or linha.group(1) != registro.get('sha256', {}).get('Agente-Senha-Nextec.ps1'):
        erros.append('Agente-Senha-Nextec.provenance.txt nao bate com FONTE-AGENTE.json')
    if erros:
        print('Scripts do agente fora da fonte unica:')
        for erro in erros:
            print(' - ' + erro)
        sys.exit(1)
    print('Scripts do agente identicos ao painel em %s@%s%s.' % (registro['repositorio'], registro['commit'][:12], ' (conferido na origem)' if remoto else ''))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    grupo = parser.add_mutually_exclusive_group(required=True)
    grupo.add_argument('--commit', help='SHA do commit do painel a copiar')
    grupo.add_argument('--verificar', action='store_true', help='confere os arquivos locais')
    parser.add_argument('--remoto', action='store_true', help='com --verificar, confere tambem no GitHub')
    args = parser.parse_args()
    if args.commit:
        sincronizar(args.commit)
    else:
        verificar(args.remoto)


if __name__ == '__main__':
    main()
