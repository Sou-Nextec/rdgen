"""Connect release manifests; RSA PKCS#1 v1.5/SHA-256 as used by Nextec monitoring."""
import base64
import hashlib
import hmac
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

PRODUCT = 'nextec-connect'
MAX_BYTES = 65536
DIGEST_INFO = bytes.fromhex('3031300d060960864801650304020105000420')


def trusted_keys():
    return json.loads(Path(__file__).with_name('chaves-publicas.json').read_text(encoding='utf-8'))


def verify_signature(raw, signature, keys=None):
    if not 0 < len(raw) <= MAX_BYTES:
        raise ValueError('Manifesto excede o limite permitido.')
    try:
        sig = base64.b64decode(signature.strip(), validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError('Assinatura ilegível.') from exc
    for key in trusted_keys() if keys is None else keys:
        n, e = int(key['n'], 16), int(key['e'])
        if n.bit_length() < 3072 or e != 65537:
            continue
        size = (n.bit_length() + 7) // 8
        if len(sig) != size or int.from_bytes(sig, 'big') >= n:
            continue
        block = pow(int.from_bytes(sig, 'big'), e, n).to_bytes(size, 'big')
        tail = DIGEST_INFO + hashlib.sha256(raw).digest()
        expected = b'\x00\x01' + b'\xff' * (size - len(tail) - 3) + b'\x00' + tail
        if hmac.compare_digest(block, expected):
            return key['id']
    raise ValueError('Assinatura não confere com a chave Nextec.')


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Campo duplicado no manifesto.')
        result[key] = value
    return result


def validate(raw, signature, *, keys=None, now=None, previous_sequence=0, previous_hash=''):
    signer = verify_signature(raw, signature, keys)
    m = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object)
    if m.get('produto') != PRODUCT or type(m.get('formato')) is not int or m['formato'] != 1:
        raise ValueError('Manifesto de outro produto ou formato.')
    sequence = m.get('sequencia')
    if type(sequence) is not int or not 1 <= sequence <= 9007199254740991:
        raise ValueError('Sequência inválida.')
    version = m.get('versao', '')
    if not isinstance(version, str) or not re.fullmatch(r'\d{1,4}\.\d{1,4}\.\d{1,4}(\.\d{1,4})?', version):
        raise ValueError('Versão inválida.')
    try:
        issued = datetime.strptime(m['publicado_em'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        expiry = datetime.strptime(m['valido_ate'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except (KeyError, ValueError, TypeError) as exc:
        raise ValueError('Datas inválidas.') from exc
    now = now or datetime.now(timezone.utc)
    if issued > now + timedelta(minutes=5) or not issued < expiry <= issued + timedelta(days=30) or expiry <= now:
        raise ValueError('Manifesto vencido ou validade inválida.')
    item = m.get('windows', {})
    if not isinstance(item, dict) or item.get('arquivo') != f'files/nextec-acesso-{version}.msi':
        raise ValueError('Caminho do MSI inválido.')
    if not isinstance(item.get('sha256'), str) or not re.fullmatch('[a-f0-9]{64}', item['sha256']):
        raise ValueError('Hash inválido.')
    if type(item.get('tamanho')) is not int or not 8 <= item['tamanho'] <= 300 * 1024 * 1024:
        raise ValueError('Tamanho do MSI inválido.')
    digest = hashlib.sha256(raw).hexdigest()
    if sequence < previous_sequence or (sequence == previous_sequence and previous_hash != digest):
        raise ValueError('Manifesto antigo ou divergente.')
    return m, digest, signer
