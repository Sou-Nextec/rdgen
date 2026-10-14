"""Regrava nextec/conteudo-pacote.lock com o conteudo atual do pacote e a versao de rdgenerator/VERSION.

Use depois de subir a versao do gerador quando o conteudo empacotado (scripts do agente, imagens MSI,
build-msi.ps1) mudou. O teste test_pacote_versao.py falha no CI se o conteudo mudar sem a versao subir.
"""
import json

from django.core.management.base import BaseCommand

from rdgenerator import nextec


class Command(BaseCommand):
    help = 'Atualiza nextec/conteudo-pacote.lock (versao do gerador + hash do conteudo empacotado).'

    def handle(self, *args, **options):
        digest, files = nextec.package_content_hash()
        data = {'versao': nextec.package_version(), 'hash': digest, 'agente_hash': nextec.agent_set_hash(), 'arquivos': files}
        nextec.PACKAGE_LOCK.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n', encoding='utf-8', newline='\n')
        self.stdout.write(f'Lock atualizado: versao {data["versao"]}, hash {digest[:12]}.')
