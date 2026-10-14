"""Instalador por cliente: o seletor "Cliente do painel" leva a credencial nx2 do cliente para o pacote do build."""
import io
import json
import os
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

import pyzipper
from django.test import TestCase, override_settings

from . import nextec
from .build_inputs import validate_build_inputs
from .forms import GenerateForm, validate_generate_params
from .views import generate_custom_client

CLIENT_KEY = 'nx2.7.3.' + 'ab12' * 16
GLOBAL_KEY = 'nx1.1790000000.AbCdEf0123456789_-AbCdEf0123456789'
PANEL = 'https://painel-remoto.nex.tec.br'
CLIENTS = {'clients': [{'id': 3, 'name': 'Acme'}, {'id': 7, 'name': 'Cliente A <b>'}]}


@override_settings(GHBEARER='t', GHUSER='u', ZIP_PASSWORD='test-only-zip', SH_SECRET='outra-forte', GENURL='https://generator.example')
class ClientEnrollmentTests(TestCase):
    def setUp(self):
        self.old = os.getcwd()
        self.tmp = tempfile.TemporaryDirectory()
        os.chdir(self.tmp.name)
        self.addCleanup(lambda: (os.chdir(self.old), self.tmp.cleanup()))
        nextec._fetch_cache.update(at=0.0, key='', ok=False)
        nextec._clients_cache.update(at=0.0, items=[])
        env = {'NX_SERVER_HOST': 'remoto.nex.tec.br', 'NX_KEY': 'CHAVEPUBLICA=', 'NX_KEY_FILE': '',
               'NX_API_SERVER': PANEL, 'NX_ENROLL_KEY': GLOBAL_KEY, 'NX_PANEL_INTERNAL_URL': 'http://rustdesk:21114'}
        patcher = patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)

    def panel(self, key_payload=None, clients=CLIENTS):
        """Painel falso: lista de clientes e credencial por cliente."""
        def fake(path, what):
            if path.startswith('/api/nextec/gen/clients'):
                return clients
            if path.startswith('/api/nextec/gen/enroll-key?group='):
                return key_payload
            return None
        return patch.object(nextec, '_panel_get_json', side_effect=fake)

    def generate(self, extra=None):
        response = Mock(status_code=200)
        response.json.return_value = {'workflow_run_id': 5, 'html_url': 'https://github.com/test/actions/runs/5'}
        params = {'exename': 'Cliente', 'appname': 'Nextec-Connect'}
        params.update(extra or {})
        with patch('rdgenerator.views.requests.post', return_value=response), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return generate_custom_client(params, 'https://generator.example')

    def secrets(self, result):
        with pyzipper.AESZipFile(Path('temp_zips') / ('secrets_' + result['uuid'] + '.zip')) as zf:
            zf.setpassword(b'test-only-zip')
            return json.loads(zf.read('secrets.json'))

    def test_cliente_escolhido_leva_a_credencial_do_cliente(self):
        payload = {'enroll_key': CLIENT_KEY, 'client_id': 7, 'client_name': 'Cliente A'}
        with self.panel(payload):
            result = self.generate({'client_id': '7'})
        self.assertTrue(result['success'], result)
        data = self.secrets(result)
        self.assertEqual(data['enroll_key'], CLIENT_KEY)
        self.assertEqual(data['enroll_panel'], PANEL)
        self.assertEqual(result['client_id'], '7')
        from .models import GithubRun
        self.assertEqual(GithubRun.objects.get(uuid=result['uuid']).client_name, 'Cliente A')
        validate_build_inputs(data)

    def test_sem_cliente_continua_global(self):
        with self.panel(None):
            result = self.generate()
        self.assertTrue(result['success'], result)
        self.assertEqual(self.secrets(result)['enroll_key'], GLOBAL_KEY)

    def test_painel_fora_do_ar_nao_cai_na_chave_global(self):
        with self.panel(None):
            result = self.generate({'client_id': '7'})
        self.assertFalse(result['success'])
        self.assertEqual(result['status_code'], 503)
        self.assertFalse(list(Path('temp_zips').glob('*.zip')) if Path('temp_zips').exists() else [])

    def test_sem_url_do_painel_nao_gera_instalador_por_cliente(self):
        # revisao do #46: a credencial veio, mas sem URL do painel o instalador sairia sem inscricao.json
        payload = {'enroll_key': CLIENT_KEY, 'client_id': 7, 'client_name': 'Cliente A'}
        with patch.dict(os.environ, {'NX_API_SERVER': ''}), self.panel(payload):
            result = self.generate({'client_id': '7', 'apiServer': 'remoto.nex.tec.br:21114'})
        self.assertFalse(result['success'], result)
        self.assertEqual(result['status_code'], 503)
        self.assertIn('sem inscrição automática', result['error'])
        self.assertFalse(list(Path('temp_zips').glob('*.zip')) if Path('temp_zips').exists() else [])
        from .models import GithubRun
        self.assertFalse(GithubRun.objects.exists())

    def test_sem_url_do_painel_o_instalador_geral_continua_com_aviso(self):
        with patch.dict(os.environ, {'NX_API_SERVER': ''}), self.panel(None):
            result = self.generate({'apiServer': 'remoto.nex.tec.br:21114'})
        self.assertTrue(result['success'], result)
        self.assertTrue(result['avisos'])
        self.assertNotIn('enroll_key', self.secrets(result))

    def test_instalador_por_cliente_sem_agente_e_recusado(self):
        payload = {'enroll_key': CLIENT_KEY, 'client_id': 7, 'client_name': 'Cliente A'}
        with self.panel(payload):
            result = self.generate({'client_id': '7', 'nx_agent': 'false'})
        self.assertFalse(result['success'], result)
        self.assertEqual(result['status_code'], 400)

    def test_credencial_de_outro_cliente_ou_formato_errado_e_recusada(self):
        for payload in ({'enroll_key': 'nx2.8.3.' + 'ab12' * 16, 'client_name': 'x'},
                        {'enroll_key': GLOBAL_KEY, 'client_name': 'x'},
                        {'enroll_key': 'nx2.7.3.curta', 'client_name': 'x'},
                        {'enroll_key': 123, 'client_name': 'x'}):
            with self.panel(payload):
                self.assertEqual(nextec.client_key('7'), ('', ''), payload)

    def test_id_do_cliente_invalido_nunca_vai_ao_painel(self):
        with patch.object(nextec, '_panel_get_json') as fake:
            for bad in ('', '0', '-1', 'abc', '7;1', '1' * 11, ' '):
                self.assertEqual(nextec.client_key(bad), ('', ''))
            fake.assert_not_called()

    def test_seletor_lista_clientes_sem_caracteres_perigosos(self):
        with self.panel(None):
            choices = nextec.panel_clients(use_cache=False)
            form = GenerateForm()
        self.assertEqual(choices, [('3', 'Acme'), ('7', 'Cliente A b')])
        self.assertEqual([value for value, _ in form.fields['client_id'].choices], ['', '3', '7'])

    def test_cliente_inexistente_no_formulario_e_recusado(self):
        with self.panel(None):
            _, errors = validate_generate_params({'exename': 'Cliente', 'client_id': '999'})
            self.assertIn('client_id', errors)
            cleaned, errors = validate_generate_params({'exename': 'Cliente', 'client_id': '3'})
            self.assertEqual(errors, {})
            self.assertEqual(cleaned['client_id'], '3')

    def test_formato_do_build_aceita_so_as_duas_credenciais(self):
        validate_build_inputs({'enroll_key': CLIENT_KEY})
        validate_build_inputs({'enroll_key': GLOBAL_KEY})
        for bad in ('nx2.7.3.' + 'AB12' * 16, 'nx2.7.' + 'ab12' * 16, 'nx3.7.3.' + 'ab12' * 16, 'nx2.7.3.' + 'ab12' * 16 + ';'):
            with self.assertRaises(ValueError):
                validate_build_inputs({'enroll_key': bad})

    def test_link_do_painel_preseleciona_o_cliente(self):
        with self.panel(None):
            response = self.client.get('/', {'cliente': '7'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['form'].initial.get('client_id'), '7')
        with self.panel(None):
            response = self.client.get('/', {'cliente': '7; drop'})
        self.assertNotEqual(response.context['form'].initial.get('client_id'), '7; drop')
