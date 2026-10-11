import json
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import requests
from django.test import Client, TestCase, override_settings

from .models import GithubRun


class GenerationCatalogTests(TestCase):
    EMAIL = 'HTTP_CF_ACCESS_AUTHENTICATED_USER_EMAIL'

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_cwd = os.getcwd()
        os.chdir(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(os.chdir, self.old_cwd)
        self.client = Client()
        self.headers = {self.EMAIL: 'operador@nex.tec.br'}

    def _run(self, uuid, **kwargs):
        return GithubRun.objects.create(uuid=uuid, status='in_progress', **kwargs)

    def test_catalog_requires_access_identity_and_paginates_without_github_calls(self):
        self._run('run-1', filename='Cliente-1', client_name='Cliente 1', rustdesk_version='1.5.0',
                  package_version='2.0.7', generator_version='2.0.2')
        self._run('run-2', filename='Cliente-2', client_name='Cliente 2', rustdesk_version='master')
        with patch('rdgenerator.views.requests.get') as github_get:
            self.assertEqual(self.client.get('/nextec/geracoes/').status_code, 403)
            response = self.client.get('/nextec/geracoes/?page_size=1', **self.headers)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual((body['count'], body['page'], body['page_size']), (2, 1, 1))
        self.assertEqual(len(body['results']), 1)
        self.assertEqual(body['results'][0]['client_name'], 'Cliente 2')
        self.assertIsNone(body['results'][0]['progress'])
        github_get.assert_not_called()

    def test_catalog_rejects_invalid_page_size(self):
        for query in ('page_size=101', 'page_size=true', 'page=1.5'):
            with self.subTest(query=query):
                response = self.client.get(f'/nextec/geracoes/?{query}', **self.headers)
                self.assertEqual(response.status_code, 400)

    def test_generation_metadata_is_validated_by_form_and_api_validator(self):
        from .forms import validate_generate_params

        for data in (
            {'exename': 'Cliente', 'profile': 'unknown'},
            {'exename': 'Cliente', 'package_version': 'versão solta'},
            {'exename': 'Cliente', 'notes': 'n' * 1001},
            {'exename': 'Cliente', 'client_name': 'c' * 121},
        ):
            with self.subTest(data=data):
                _, errors = validate_generate_params(data)
                self.assertTrue(errors)

    def test_detail_refreshes_only_selected_run_and_returns_received_files(self):
        uuid = '11111111-2222-3333-4444-555555555555'
        run = self._run(uuid, filename='Nextec-Connect', platform='windows', github_run_id=456,
                        client_name='Carteira A', profile='client', rustdesk_version='1.5.0',
                        package_version='2.0.7', generator_version='2.0.2', notes='Piloto')
        output = Path('exe') / uuid
        output.mkdir(parents=True)
        (output / 'Nextec-Connect.exe').write_bytes(b'build')
        with override_settings(GHBEARER='catalog-test-token'):
            with patch('rdgenerator.views.requests.get', return_value=Mock(
                    status_code=200, json=lambda: {'status': 'completed', 'conclusion': 'success'})) as github_get:
                response = self.client.get(f'/nextec/geracoes/{uuid}/', **self.headers)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body['status'], 'incomplete')  # Windows expects both exe and msi.
        self.assertEqual(body['rustdesk_version'], '1.5.0')
        self.assertEqual(body['package_version'], '2.0.7')
        self.assertEqual(body['generator_version'], '2.0.2')
        self.assertEqual(body['profile'], 'client')
        self.assertEqual(body['notes'], 'Piloto')
        self.assertEqual(body['files'][0]['name'], 'Nextec-Connect.exe')
        self.assertEqual(github_get.call_count, 2)  # run status, then its jobs for progress.
        run.refresh_from_db()
        self.assertEqual(run.status, 'success')

    def test_failed_github_submission_is_persisted_without_secrets(self):
        from . import nextec
        from . import views

        response = Mock(status_code=422)
        with (
            patch.object(nextec, 'config_problems', return_value=[]),
            patch.object(nextec, 'is_configured', return_value=False),
            patch.object(views, 'save_png', return_value=('false', 'false', 'false')),
            patch.object(views, 'validate_build_inputs'),
            patch.object(views.requests, 'post', return_value=response),
            override_settings(GHBEARER='test-token', GHUSER='test-owner', ZIP_PASSWORD='test-password'),
        ):
            result = views.generate_custom_client({
                'exename': 'Nextec-Connect', 'appname': 'Nextec-Connect', 'version': '1.5.0',
                'package_version': '2.0.7', 'profile': 'client', 'client_name': 'Carteira A',
                'notes': 'Build piloto', 'key': 'public-key', 'permanentPassword': 'do-not-save',
            }, 'https://generator.example', created_by='operador@nex.tec.br')

        self.assertFalse(result['success'])
        run = GithubRun.objects.get(uuid=result.get('uuid')) if result.get('uuid') else GithubRun.objects.latest('id')
        self.assertEqual(run.status, 'failure')
        self.assertEqual(run.created_by, 'operador@nex.tec.br')
        self.assertEqual(run.client_name, 'Carteira A')
        self.assertEqual(run.rustdesk_version, '1.5.0')
        self.assertEqual(run.package_version, '2.0.7')
        self.assertEqual(run.profile, 'client')
        self.assertEqual(run.notes, 'Build piloto')
        self.assertIn('HTTP 422', run.submission_error)
        persisted = {field.name: getattr(run, field.name) for field in run._meta.fields}
        self.assertNotIn('do-not-save', json.dumps(persisted, default=str))
        self.assertNotIn('public-key', json.dumps(persisted, default=str))

    def test_timeout_is_persisted_as_uncertain_not_definite_failure(self):
        from . import nextec
        from . import views

        with (
            patch.object(nextec, 'config_problems', return_value=[]),
            patch.object(nextec, 'is_configured', return_value=False),
            patch.object(views, 'save_png', return_value=('false', 'false', 'false')),
            patch.object(views, 'validate_build_inputs'),
            patch.object(views.requests, 'post', side_effect=requests.Timeout()),
            override_settings(GHBEARER='test-token', GHUSER='test-owner', ZIP_PASSWORD='test-password'),
        ):
            result = views.generate_custom_client(
                {'exename': 'Nextec-Connect', 'appname': 'Nextec-Connect'},
                'https://generator.example', created_by='operador@nex.tec.br')

        self.assertFalse(result['success'])
        run = GithubRun.objects.latest('id')
        self.assertEqual(run.status, 'submission_unknown')
        self.assertIn('pode ter aceitado', run.submission_error)
