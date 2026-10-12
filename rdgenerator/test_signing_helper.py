import io
import os
import re
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

from django.test import TestCase

from .signing_helper import ARCHIVE_NAME, SIGNER_FILES


PRIVATE_PEM_BLOCK = re.compile(
    rb"-----BEGIN (?P<label>(?:(?:ENCRYPTED|RSA) )?PRIVATE KEY)-----\r?\n"
    rb"(?:(?:Proc-Type|DEK-Info):[^\r\n]*\r?\n)*\r?\n?"
    rb"(?:[A-Za-z0-9+/=]{32,76}\r?\n)+[A-Za-z0-9+/=]{1,76}\r?\n"
    rb"-----END (?P=label)-----"
)


class SigningHelperDownloadTests(TestCase):
    url = "/nextec/atualizacao/assinador.zip"

    def test_requires_cloudflare_access_identity(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"], "Autenticação do Cloudflare Access necessária.")

    def test_allowlist_is_enforced_for_authenticated_download(self):
        with patch.dict(os.environ, {"NX_ALLOWED_EMAILS": "admin@example.com"}):
            response = self.client.get(self.url, REMOTE_ADDR="203.0.113.10",
                                       HTTP_CF_ACCESS_AUTHENTICATED_USER_EMAIL="other@example.com")
        self.assertEqual(response.status_code, 403)

    def test_download_contains_only_fixed_signer_files_and_no_private_key(self):
        with patch.dict(os.environ, {"NX_ALLOWED_EMAILS": "admin@example.com"}):
            response = self.client.get(self.url, HTTP_CF_ACCESS_AUTHENTICATED_USER_EMAIL="admin@example.com")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Disposition"], f'attachment; filename="{ARCHIVE_NAME}"')
        self.assertEqual(response["Cache-Control"], "private, no-store")
        archive_bytes = b"".join(response.streaming_content)
        response.close()
        with ZipFile(io.BytesIO(archive_bytes)) as archive:
            self.assertEqual(set(archive.namelist()), set(SIGNER_FILES))
            signer_dir = Path(__file__).resolve().parents[1] / "nextec" / "atualizacao"
            for name in SIGNER_FILES:
                self.assertEqual(archive.read(name), (signer_dir / name).read_bytes())
            names = " ".join(archive.namelist()).lower()
            self.assertNotIn("private", names)
            self.assertNotIn(".pem", names)
            self.assertNotIn(".key", names)
            for name in archive.namelist():
                self.assertIsNone(PRIVATE_PEM_BLOCK.search(archive.read(name)), f"private-key PEM block found in {name}")

    def test_launcher_uses_bundled_script_without_password_arguments(self):
        launcher = (Path(__file__).resolve().parents[1] / "nextec" / "atualizacao" / "Assinar-Connect.cmd").read_text(encoding="ascii")
        self.assertIn('powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0assinar-pedido-connect.ps1"', launcher)
        self.assertNotIn("%1", launcher)
        self.assertNotIn("senha", launcher.lower())
