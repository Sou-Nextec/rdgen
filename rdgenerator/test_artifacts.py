import hashlib
import os
import tempfile
from pathlib import Path
from unittest.mock import patch
from django.test import TestCase, override_settings
from .models import GithubRun

@override_settings(SH_SECRET='test-internal-secret')
class ArtifactTests(TestCase):
    uuid = 'aaaaaaaa-0000-0000-0000-000000000001'
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.before = os.getcwd()
        os.chdir(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(lambda: os.chdir(self.before))
        self.directory = Path('exe') / self.uuid
        self.directory.mkdir(parents=True)
        self.payload = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1payload'
        (self.directory / 'Nextec-Connect.msi').write_bytes(self.payload)
        (self.directory / 'Nextec-Connect.exe').write_bytes(b'MZportable')
        self.run = GithubRun.objects.create(uuid=self.uuid, status='success', filename='Nextec-Connect', platform='windows', package_version='2.0.7', profile='default')
    def get(self, **query):
        return self.client.get('/api/artifact', {'uuid': self.uuid, **query}, HTTP_AUTHORIZATION='Bearer test-internal-secret')
    def test_identity_header_cannot_replace_internal_authentication(self):
        response = self.client.get('/api/artifact', {'uuid': self.uuid}, HTTP_CF_ACCESS_AUTHENTICATED_USER_EMAIL='admin@example.com')
        self.assertEqual(response.status_code, 403)
    def test_metadata_and_download_match_the_stored_payload(self):
        with patch.dict(os.environ, {'NX_ALLOWED_EMAILS': 'admin@example.com'}):
            response = self.get()
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()['sha256'], hashlib.sha256(self.payload).hexdigest())
            self.assertEqual(response.json()['package_version'], '2.0.7')
            response = self.get(file='1')
            self.assertEqual(b''.join(response.streaming_content), self.payload)
            response.close()
    def test_missing_exe_prevents_importing_a_false_complete_build(self):
        (self.directory / 'Nextec-Connect.exe').unlink()
        self.assertEqual(self.get().status_code, 409)
    def test_nonterminal_build_and_traversal_are_rejected(self):
        self.run.status = 'in_progress'; self.run.save()
        self.assertEqual(self.get().status_code, 409)
        self.assertEqual(self.client.get('/api/artifact', {'uuid': '../escape'}, HTTP_AUTHORIZATION='Bearer test-internal-secret').status_code, 409)
