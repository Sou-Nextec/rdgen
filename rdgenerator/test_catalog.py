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


class GenerationDeleteTests(TestCase):
    EMAIL = 'HTTP_CF_ACCESS_AUTHENTICATED_USER_EMAIL'
    U1 = 'aaaaaaaa-1111-1111-1111-111111111111'
    U2 = 'bbbbbbbb-2222-2222-2222-222222222222'
    U3 = 'cccccccc-3333-3333-3333-333333333333'

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_cwd = os.getcwd()
        os.chdir(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(os.chdir, self.old_cwd)
        self.client = Client()
        self.headers = {self.EMAIL: 'operador@nex.tec.br', 'HTTP_X_NEXTEC_ACAO': 'excluir'}

    def _run(self, uuid, status, **kwargs):
        run = GithubRun.objects.create(uuid=uuid, status=status, filename='Cliente', platform='windows', **kwargs)
        for base in ('exe', 'png'):
            Path(base, uuid).mkdir(parents=True)
            if base == 'exe':
                # Instalador completo no Windows: EXE e MSI (senão o item é "incompleto" e conta como falha).
                Path(base, uuid, 'Cliente.msi').write_bytes(b'x')
                Path(base, uuid, 'Cliente.exe').write_bytes(b'x')
            else:
                Path(base, uuid, 'icon.png').write_bytes(b'x')
        Path('temp_zips').mkdir(exist_ok=True)
        Path('temp_zips', f'secrets_{uuid}.zip').write_bytes(b'z')
        return run

    def test_failed_item_is_removed_with_its_files(self):
        self._run(self.U1, 'failure')
        response = self.client.delete(f'/nextec/geracoes/{self.U1}/excluir/', **self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(GithubRun.objects.filter(uuid=self.U1).exists())
        self.assertFalse(Path('exe', self.U1).exists())
        self.assertFalse(Path('png', self.U1).exists())
        self.assertFalse(Path('temp_zips', f'secrets_{self.U1}.zip').exists())

    def test_delete_requires_identity_and_action_header(self):
        self._run(self.U1, 'failure')
        self.assertEqual(self.client.delete(f'/nextec/geracoes/{self.U1}/excluir/',
                                            HTTP_X_NEXTEC_ACAO='excluir').status_code, 403)
        self.assertEqual(self.client.delete(f'/nextec/geracoes/{self.U1}/excluir/',
                                            **{self.EMAIL: 'operador@nex.tec.br'}).status_code, 400)
        self.assertTrue(GithubRun.objects.filter(uuid=self.U1).exists())

    def test_bulk_removes_selected_and_clears_failures_only(self):
        self._run(self.U1, 'failure')
        self._run(self.U2, 'in_progress', github_run_id=1)
        self._run(self.U3, 'success')
        response = self.client.post('/nextec/geracoes/excluir/', data=json.dumps({'scope': 'failed'}),
                                    content_type='application/json', **self.headers)
        self.assertEqual(response.json()['deleted'], [self.U1])
        self.assertTrue(GithubRun.objects.filter(uuid=self.U2).exists())
        self.assertTrue(GithubRun.objects.filter(uuid=self.U3).exists())
        response = self.client.post('/nextec/geracoes/excluir/', data=json.dumps({'uuids': [self.U3, self.U2]}),
                                    content_type='application/json', **self.headers)
        body = response.json()
        self.assertEqual(body['deleted'], [self.U3])
        self.assertEqual([item['code'] for item in body['blocked']], ['in_progress'])
        self.assertTrue(Path('exe', self.U2).exists())

    def test_submission_error_item_can_be_deleted(self):
        self._run(self.U1, 'Starting generator...please wait', submission_error='falha ao enviar')
        self.assertEqual(self.client.delete(f'/nextec/geracoes/{self.U1}/excluir/', **self.headers).status_code, 200)

    def test_in_progress_item_is_refused(self):
        self._run(self.U1, 'in_progress', github_run_id=7)
        response = self.client.delete(f'/nextec/geracoes/{self.U1}/excluir/', **self.headers)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()['code'], 'in_progress')
        self.assertTrue(GithubRun.objects.filter(uuid=self.U1).exists())
        self.assertTrue(Path('exe', self.U1).exists())

    def test_item_sent_to_updates_requires_explicit_confirmation(self):
        from django.utils import timezone
        self._run(self.U1, 'success', imported_at=timezone.now())
        response = self.client.delete(f'/nextec/geracoes/{self.U1}/excluir/', **self.headers)
        self.assertEqual((response.status_code, response.json()['code']), (409, 'imported'))
        self.assertTrue(GithubRun.objects.filter(uuid=self.U1).exists())
        response = self.client.delete(f'/nextec/geracoes/{self.U1}/excluir/?confirmar=1', **self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Path('exe', self.U1).exists())

    def test_path_traversal_identifier_is_refused(self):
        outside = Path('segredo.txt')
        outside.write_text('nao apagar')
        for bad in ('..', '../x', '..%2F..%2Fsegredo.txt', 'aaaaaaaa-1111-1111-1111-11111111111/'):
            response = self.client.delete(f'/nextec/geracoes/{bad}/excluir/', **self.headers)
            self.assertIn(response.status_code, (400, 404))
        response = self.client.post('/nextec/geracoes/excluir/', data=json.dumps({'uuids': ['../../etc']}),
                                    content_type='application/json', **self.headers)
        self.assertEqual(response.status_code, 400)
        self.assertTrue(outside.exists())

    def test_symlinked_directory_is_unlinked_without_touching_target(self):
        target = Path('fora'); target.mkdir(); (target / 'keep.txt').write_text('ok')
        run = GithubRun.objects.create(uuid=self.U1, status='failure')
        Path('exe').mkdir()
        try:
            os.symlink(target.resolve(), Path('exe', self.U1), target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest('symlinks indisponíveis neste sistema')
        self.assertEqual(self.client.delete(f'/nextec/geracoes/{self.U1}/excluir/', **self.headers).status_code, 200)
        self.assertTrue((target / 'keep.txt').exists())
        self.assertFalse(GithubRun.objects.filter(pk=run.pk).exists())

    def test_catalog_flags_deletable_items(self):
        self._run(self.U1, 'failure')
        self._run(self.U2, 'in_progress', github_run_id=1)
        items = {item['uuid']: item for item in self.client.get('/nextec/geracoes/', **self.headers).json()['results']}
        self.assertTrue(items[self.U1]['deletable'])
        self.assertFalse(items[self.U2]['deletable'])
