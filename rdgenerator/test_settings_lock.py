"""'Desativar configurações' com o agente: oculta as abas na interface sem bloquear o CLI que o agente usa.

No RustDesk 1.5.0, `disable-settings=Y` faz `--password` e `--option` responderem "Settings are disabled!",
e o agente de senha nunca consegue aplicar a troca. Com o agente, o gerador troca por opções `hide-*`."""
import base64
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pyzipper
from django.test import TestCase, override_settings

from . import nextec

HIDE_KEYS = ('hide-security-settings', 'hide-network-settings', 'hide-server-settings', 'hide-proxy-settings',
             'hide-websocket-settings', 'hide-remote-printer-settings', 'hide-stop-service')


@override_settings(GHBEARER='test-only-token', GHUSER='test-owner', ZIP_PASSWORD='test-only-zip',
                   SH_SECRET='test-only-api', GENURL='https://generator.example')
class SettingsLockTests(TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self._old_cwd = os.getcwd()
        os.chdir(self._dir.name)
        self.addCleanup(self._dir.cleanup)
        self.addCleanup(os.chdir, self._old_cwd)

    def custom(self, **params):
        from .views import generate_custom_client
        response = Mock(status_code=200)
        response.json.return_value = {'workflow_run_id': 123}
        base = {'exename': 'Cliente', 'appname': 'Qualquer-Nome', 'settings': 'settingsN'}
        base.update(params)
        with patch('rdgenerator.views.requests.post', return_value=response):
            result = generate_custom_client(base, 'https://generator.example')
        self.assertTrue(result['success'], result)
        with pyzipper.AESZipFile(Path('temp_zips') / ('secrets_' + result['uuid'] + '.zip')) as zf:
            zf.setpassword(b'test-only-zip')
            inputs = json.loads(zf.read('secrets.json'))
        return json.loads(base64.b64decode(inputs['custom']))

    def test_with_agent_never_disables_settings_and_hides_tabs(self):
        for flag in ('true', ''):
            with self.subTest(nx_agent=flag):
                custom = self.custom(nx_agent=flag)
                self.assertNotIn('disable-settings', custom)
                for key in HIDE_KEYS:
                    self.assertEqual(custom['override-settings'].get(key), 'Y', key)
                # nada que bloqueie a senha permanente pelo CLI do agente
                self.assertNotEqual(custom['override-settings'].get('disable-change-permanent-password'), 'Y')

    def test_without_agent_keeps_disable_settings(self):
        custom = self.custom(nx_agent='false')
        self.assertEqual(custom.get('disable-settings'), 'Y')
        for key in HIDE_KEYS:
            self.assertNotIn(key, custom['override-settings'])

    def test_settings_allowed_adds_nothing(self):
        for flag in ('true', 'false'):
            with self.subTest(nx_agent=flag):
                custom = self.custom(nx_agent=flag, settings='settingsY')
                self.assertNotIn('disable-settings', custom)
                for key in HIDE_KEYS:
                    self.assertNotIn(key, custom['override-settings'])

    def test_helper_is_pure(self):
        self.assertEqual(nextec.settings_lock(False, True), ({'disable-settings': 'Y'}, {}))
        hard, override = nextec.settings_lock(True, True)
        self.assertEqual(hard, {})
        self.assertEqual(set(override), set(HIDE_KEYS))
        self.assertEqual(nextec.settings_lock(True, False), ({}, {}))

    def test_form_explains_agent_behaviour(self):
        page = self.client.get('/').content.decode()
        self.assertIn('a senha automática continua funcionando', page)
        self.assertNotIn('—', page.split('a senha automática continua funcionando')[0][-200:])
