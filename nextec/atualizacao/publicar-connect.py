"""Sign a Connect release locally with the existing encrypted monitoring RSA key."""
import argparse
import base64
import hashlib
import json
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from manifest import validate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--msi', type=Path, required=True)
    parser.add_argument('--versao', required=True)
    parser.add_argument('--sequencia', type=int, required=True)
    parser.add_argument('--chave', type=Path, required=True, help='Mesma chave privada cifrada usada no monitoramento; nunca vai para o servidor.')
    parser.add_argument('--saida', type=Path, required=True)
    args = parser.parse_args()
    openssl = shutil.which('openssl')
    if not openssl:
        raise SystemExit('OpenSSL não encontrado. Use o OpenSSL do Git for Windows.')
    with args.msi.open('rb') as file:
        if file.read(8) != bytes.fromhex('d0cf11e0a1b11ae1'):
            raise SystemExit('O arquivo não é um MSI.')
        file.seek(0)
        digest = hashlib.sha256()
        for block in iter(lambda: file.read(1024 * 1024), b''):
            digest.update(block)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    m = {'produto': 'nextec-connect', 'formato': 1, 'sequencia': args.sequencia,
         'versao': args.versao, 'publicado_em': now.strftime('%Y-%m-%dT%H:%M:%SZ'),
         'valido_ate': (now + timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%SZ'),
         'windows': {'arquivo': f'files/nextec-acesso-{args.versao}.msi',
                     'sha256': digest.hexdigest(), 'tamanho': args.msi.stat().st_size}}
    raw = json.dumps(m, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    with tempfile.TemporaryDirectory() as folder:
        payload, signature = Path(folder) / 'manifesto.json', Path(folder) / 'signature.bin'
        payload.write_bytes(raw)
        # Password is prompted by OpenSSL; never passed through argv, environment or logs.
        subprocess.run([openssl, 'dgst', '-sha256', '-sign', str(args.chave), '-out', str(signature), str(payload)], check=True)
        signed = base64.b64encode(signature.read_bytes())
        validate(raw, signed)  # Refuse a key different from the trusted monitoring key.
    args.saida.mkdir(parents=True, exist_ok=True)
    destination = args.saida / 'manifesto-connect.json'
    if destination.exists() or destination.with_suffix('.json.sig').exists():
        raise SystemExit('A saída já existe; use outra pasta para preservar a release anterior.')
    destination.write_bytes(raw)
    destination.with_suffix('.json.sig').write_bytes(signed + b'\n')
    print(f'Manifesto assinado: {destination}. Chave privada permanece no computador.')


if __name__ == '__main__':
    main()
