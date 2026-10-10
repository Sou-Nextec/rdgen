import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pyzipper
from django.test import Client, SimpleTestCase, TestCase, override_settings
from .build_inputs import FIELDS, validate_build_inputs
from .forms import validate_generate_params


class BuildInputTests(SimpleTestCase):
    def test_no_build_field_accepts_shell_syntax_or_newlines(self):
        for field in FIELDS:
            for value in ('value\nappname=changed', 'value\rchanged', "value';echo injected;'", '$(echo injected)', 'value\x00'):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    validate_build_inputs({field: value})

    def test_unknown_or_non_string_fields_are_rejected(self):
        for payload in ([], {'GITHUB_ENV': '/tmp/evil'}, {'appname': 1}, {'filename': None}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                    validate_build_inputs(payload)

        for key in ('apiServer', 'genurl', 'urlLink', 'downloadLink', 'iconlink_url', 'custom', 'key', 'token', 'uuid', 'iconlink_file'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_build_inputs({key: 'value;echo injected'})

    def test_json_uses_form_choices_defaults_and_limits(self):
        cleaned, errors = validate_generate_params({'exename': 'Cliente'})
        self.assertFalse(errors)
        self.assertEqual(cleaned['version'], '1.5.0')
        self.assertTrue(cleaned['enableKeyboard'])
        for data in ([], {'exename': 12}, {'exename': 'x', 'version': 'unknown'},
                     {'exename': 'x', 'platform': 'android'}, {'exename': 'x', 'appname': 'Bad Name'},
                     {'exename': 'x', 'serverPort': '21117'}, {'exename': 'x', 'enableAudio': 'false'},
                     {'exename': 'x', 'androidappid': 'com.test\nappname=changed'}):
            with self.subTest(data=data):
                self.assertTrue(validate_generate_params(data)[1])

    def test_workflow_validates_before_exporting(self):
        action = Path(__file__).resolve().parents[1] / '.github/actions/decrypt-secrets/action.yml'
        if not action.exists():
            self.skipTest('Mount .github/actions/decrypt-secrets for the workflow integration test.')
        code = action.read_text().rsplit('      run: |\n', 1)[1]
        code = '\n'.join(line[8:] if line.startswith('        ') else line for line in code.splitlines())
        # Test the actual composite action, including a password that would break Python interpolation.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            zip_path, env_path = tmp / 'secrets.zip', tmp / 'github_env'
            password = "test-only-'quoted'"
            for payload, expected in (({'appname': 'Nextec-Connect', 'compname': 'Nextec'}, True),
                                      ({'appname': 'Safe', 'androidappid': 'com.test\nappname=unsafe'}, False)):
                with pyzipper.AESZipFile(zip_path, 'w', encryption=pyzipper.WZ_AES) as zf:
                    zf.setpassword(password.encode())
                    zf.writestr('secrets.json', json.dumps(payload))
                env_path.write_text('sentinel=yes\n')
                env = dict(os.environ, ZIP_PATH=str(zip_path), ZIP_PASSWORD=password,
                           GITHUB_ENV=str(env_path), VALIDATION_PATH=str(Path(__file__).resolve().parent))
                result = subprocess.run([sys.executable, '-c', code], env=env, capture_output=True)
                if expected:
                    self.assertEqual(result.returncode, 0, result.stderr.decode())
                    self.assertIn('appname=Nextec-Connect\n', env_path.read_text())
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(env_path.read_text(), 'sentinel=yes\n')


@override_settings(GHBEARER='test-only-token', GHUSER='test-owner', ZIP_PASSWORD='test-only-zip',
                   SH_SECRET='test-only-api', GENURL='https://generator.example')
class GenerationSecurityTests(TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self._old_cwd = os.getcwd()
        os.chdir(self._dir.name)
        self.addCleanup(self._dir.cleanup)
        self.addCleanup(os.chdir, self._old_cwd)

    def test_api_requires_token_and_json_object(self):
        client = Client(enforce_csrf_checks=True)
        self.assertEqual(client.post('/api/generate', data='{}', content_type='application/json').status_code, 403)
        for body in ('[]', '{"exename": 10}', '{"exename":"x", "androidappid":"com.test\\nappname=evil"}'):
            with patch('rdgenerator.api_views.generate_custom_client') as generate:
                response = client.post('/api/generate', data=body, content_type='application/json',
                                       HTTP_AUTHORIZATION='Bearer test-only-api')
                self.assertEqual(response.status_code, 400)
                generate.assert_not_called()

    def test_form_requires_csrf(self):
        client = Client(enforce_csrf_checks=True)
        self.assertEqual(client.post('/generator', {'exename': 'x'}).status_code, 403)
        page = client.get('/')
        self.assertIn('csrfmiddlewaretoken', page.content.decode())
        token = client.cookies['csrftoken'].value
        response = client.post('/generator', {'csrfmiddlewaretoken': token})
        self.assertEqual(response.status_code, 200)  # invalid form, but CSRF succeeds

    def test_upload_callback_still_accepts_build_token_without_csrf(self):
        from django.core.files.uploadedfile import SimpleUploadedFile
        from .views import build_token
        uuid = '11111111-2222-3333-4444-555555555555'
        response = Client(enforce_csrf_checks=True).post('/save_custom_client',
            {'uuid': uuid, 'file': SimpleUploadedFile('test.exe', b'test')},
            HTTP_AUTHORIZATION='Bearer ' + build_token(uuid))
        self.assertEqual(response.status_code, 200)

    def test_legacy_generation_routes_are_closed(self):
        for route in ('/startgh', '/creategh'):
            self.assertEqual(self.client.post(route, data='{}', content_type='application/json').status_code, 410)

    def test_missing_files_are_404_and_downloads_are_streamed(self):
        uuid = '11111111-2222-3333-4444-555555555555'
        self.assertEqual(self.client.get('/download').status_code, 403)
        self.assertEqual(self.client.get('/download', {'uuid': uuid, 'filename': 'test.exe'}).status_code, 404)
        self.assertEqual(self.client.get('/get_png', {'uuid': uuid, 'filename': 'icon.png'}).status_code, 404)
        self.assertEqual(self.client.get('/get_zip', {'filename': 'secrets_' + uuid + '.zip'}).status_code, 404)
        directory = Path('exe') / uuid
        directory.mkdir(parents=True)
        (directory / 'test.exe').write_bytes(b'test')
        response = self.client.get('/download', {'uuid': uuid, 'filename': 'test.exe'})
        self.assertTrue(response.streaming)
        self.assertEqual(b''.join(response.streaming_content), b'test')

    def test_missing_configuration_stays_unhealthy_without_dispatch(self):
        with override_settings(GHBEARER='', ZIP_PASSWORD='', SH_SECRET=''), patch('rdgenerator.views.requests.post') as post:
            self.assertEqual(self.client.get('/').status_code, 503)
            self.assertEqual(self.client.post('/api/generate', data='{}', content_type='application/json').status_code, 503)
            post.assert_not_called()

    def test_valid_generation_dispatch_and_empty_response(self):
        from .views import generate_custom_client
        response = Mock(status_code=200)
        response.json.return_value = {'workflow_run_id': 123, 'html_url': 'https://github.com/test/actions/runs/123'}
        with patch('rdgenerator.views.requests.post', return_value=response) as post:
            result = generate_custom_client({'exename': 'Cliente', 'appname': 'Nextec-Connect'}, 'https://generator.example')
            self.assertTrue(result['success'], result)
            self.assertEqual(post.call_args.kwargs['timeout'], (5, 30))
            response.status_code = 204
            response.json.side_effect = ValueError('empty response')
            result = generate_custom_client({'exename': 'Cliente'}, 'https://generator.example')
            self.assertFalse(result['success'])
            response.json.assert_called_once()  # only the successful 200 is parsed
