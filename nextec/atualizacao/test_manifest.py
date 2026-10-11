import base64
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from manifest import validate


class ManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.openssl = shutil.which('openssl') or r'C:\Program Files\Git\usr\bin\openssl.exe'
        if not Path(cls.openssl).is_file():
            if os.environ.get('CI'):
                raise RuntimeError('OpenSSL required in CI')
            raise unittest.SkipTest('OpenSSL unavailable')
        cls.temp = tempfile.TemporaryDirectory()
        cls.folder = Path(cls.temp.name)
        cls.key = cls.folder / 'disposable-test-key.pem'
        subprocess.run([cls.openssl, 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', str(cls.key)], check=True, capture_output=True)
        modulus = subprocess.check_output([cls.openssl, 'rsa', '-in', str(cls.key), '-noout', '-modulus']).decode().strip().split('=')[1].lower()
        cls.keys = [{'id': 'disposable-test-key', 'e': 65537, 'n': modulus}]
        cls.now = datetime.now(timezone.utc).replace(microsecond=0)
        cls.m = {'produto': 'nextec-connect', 'formato': 1, 'sequencia': 5, 'versao': '2.0.3',
                 'publicado_em': cls.now.strftime('%Y-%m-%dT%H:%M:%SZ'),
                 'valido_ate': (cls.now + timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                 'windows': {'arquivo': 'files/nextec-acesso-2.0.3.msi', 'sha256': 'a' * 64, 'tamanho': 100}}

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def sign(self, m):
        raw = json.dumps(m, sort_keys=True, separators=(',', ':')).encode()
        payload = self.folder / 'payload.json'
        payload.write_bytes(raw)
        signature = subprocess.check_output([self.openssl, 'dgst', '-sha256', '-sign', str(self.key), str(payload)])
        return raw, base64.b64encode(signature)

    def verify(self, m, **kwargs):
        return validate(*self.sign(m), keys=self.keys, now=self.now, **kwargs)

    def test_valid_release_and_unchanged_sequence(self):
        m, digest, signer = self.verify(self.m)
        self.assertEqual(signer, 'disposable-test-key')
        self.assertEqual(self.verify(self.m, previous_sequence=5, previous_hash=digest)[0], m)

    def test_tampered_manifest_and_wrong_trust_key_are_rejected(self):
        raw, sig = self.sign(self.m)
        with self.assertRaisesRegex(ValueError, 'Assinatura'):
            validate(raw.replace(b'2.0.3', b'2.0.4'), sig, keys=self.keys)
        with self.assertRaisesRegex(ValueError, 'Assinatura'):
            validate(raw, sig)  # Real public monitoring key must reject disposable test key.

    def test_other_product_expired_future_and_wrong_path_are_rejected(self):
        cases = [{'produto': 'nextec-monitoramento'}, {'sequencia': True},
                 {'valido_ate': (self.now - timedelta(seconds=1)).strftime('%Y-%m-%dT%H:%M:%SZ')},
                 {'publicado_em': (self.now + timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')},
                 {'windows': {'arquivo': 'files/../../other.exe', 'sha256': 'a' * 64, 'tamanho': 100}}]
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.verify(dict(self.m, **changes))

    def test_replayed_sequence_and_same_sequence_changed_content_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'antigo'):
            self.verify(self.m, previous_sequence=6)
        with self.assertRaisesRegex(ValueError, 'divergente'):
            self.verify(self.m, previous_sequence=5, previous_hash='b' * 64)

    @unittest.skipUnless(os.name == 'nt', 'Windows PowerShell integration')
    def test_windows_powershell_uses_same_signature_contract(self):
        script = Path(__file__).with_name('Manifesto-Connect.ps1')
        shutil.copyfile(script, self.folder / script.name)
        (self.folder / 'chaves-publicas.json').write_text(json.dumps(self.keys))
        raw, signature = self.sign(self.m)
        (self.folder / 'payload.json').write_bytes(raw)
        (self.folder / 'payload.sig').write_bytes(signature)
        harness = self.folder / 'verify.ps1'
        harness.write_text("$ErrorActionPreference='Stop'\n. (Join-Path $PSScriptRoot 'Manifesto-Connect.ps1')\n"
                           "$r=Test-ManifestoConnect -Dados ([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'payload.json'))) -Assinatura (Get-Content (Join-Path $PSScriptRoot 'payload.sig') -Raw)\n"
                           "if ($r.Assinante -ne 'disposable-test-key') { throw 'Signer mismatch' }\n"
                           "$rejected=$false\ntry { Test-ManifestoConnect -Dados ([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'payload.json'))) -Assinatura (Get-Content (Join-Path $PSScriptRoot 'payload.sig') -Raw) -UltimaSequencia 6 } catch { $rejected=$true }\n"
                           "if (-not $rejected) { throw 'Replay accepted' }\n", encoding='utf-8-sig')
        result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(harness)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))


if __name__ == '__main__':
    unittest.main()
