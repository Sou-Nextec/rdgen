"""Chave de inscricao global (NX_ENROLL_KEY): vai so no pacote cifrado do build, nunca em banco, modelo, resposta ou log."""
import io
import json
import os
import tempfile
import threading
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

import pyzipper
from django.test import TestCase, override_settings

from . import nextec
from .build_inputs import validate_build_inputs
from .models import GithubRun, SavedModel
from .views import generate_custom_client

KEY = 'nx1.1790000000.AbCdEf0123456789_-AbCdEf0123456789'
PANEL = 'https://painel-remoto.nex.tec.br'


@override_settings(GHBEARER='t', GHUSER='u', ZIP_PASSWORD='test-only-zip', SH_SECRET='outra-forte', GENURL='https://generator.example')
class EnrollmentTests(TestCase):
    def setUp(self):
        self.old = os.getcwd()
        self.tmp = tempfile.TemporaryDirectory()
        os.chdir(self.tmp.name)
        self.addCleanup(self.cleanup)
        nextec._fetch_cache.update(at=0.0, key='', ok=False)

    def cleanup(self):
        os.chdir(self.old)
        self.tmp.cleanup()

    def env(self, **values):
        base = {'NX_SERVER_HOST': 'remoto.nex.tec.br', 'NX_KEY': 'CHAVEPUBLICA=', 'NX_KEY_FILE': '',
                'NX_API_SERVER': PANEL, 'NX_ENROLL_KEY': '', 'NX_PANEL_INTERNAL_URL': ''}
        base.update(values)
        return patch.dict(os.environ, base)

    def generate(self):
        response = Mock(status_code=200)
        response.json.return_value = {'workflow_run_id': 321, 'html_url': 'https://github.com/test/actions/runs/321'}
        out, err = io.StringIO(), io.StringIO()
        with patch('rdgenerator.views.requests.post', return_value=response) as post, redirect_stdout(out), redirect_stderr(err):
            result = generate_custom_client({'exename': 'Cliente', 'appname': 'Nextec-Connect'}, 'https://generator.example')
        return result, post, out.getvalue() + err.getvalue()

    def zip_inputs(self, result):
        with pyzipper.AESZipFile(Path('temp_zips') / ('secrets_' + result['uuid'] + '.zip')) as zf:
            zf.setpassword(b'test-only-zip')
            return json.loads(zf.read('secrets.json'))

    def test_chave_vai_no_zip_com_painel_e_sem_aviso(self):
        with self.env(NX_ENROLL_KEY=KEY):
            result, post, output = self.generate()
        self.assertTrue(result['success'], result)
        self.assertTrue(result['enrollment'])
        self.assertEqual(result['avisos'], [])
        inputs = self.zip_inputs(result)
        self.assertEqual(inputs['enroll_key'], KEY)
        self.assertEqual(inputs['enroll_panel'], PANEL)
        validate_build_inputs(inputs)

    def test_chave_nao_aparece_em_resposta_banco_logs_nem_requisicao_ao_github(self):
        with self.env(NX_ENROLL_KEY=KEY):
            result, post, output = self.generate()
            self.assertNotIn(KEY, json.dumps(result))
            self.assertNotIn(KEY, output)
            self.assertNotIn(KEY, json.dumps(post.call_args.kwargs['json']))
            run = GithubRun.objects.get(uuid=result['uuid'])
            for field in run._meta.fields:
                self.assertNotIn(KEY, str(getattr(run, field.attname)))
            self.assertFalse(SavedModel.objects.filter(settings__icontains=KEY).exists())
            # nem a pagina do formulario nem a de espera exibem a chave
            self.assertNotIn(KEY, self.client.get('/').content.decode())

    def test_modelo_salvo_nao_carrega_a_chave(self):
        with self.env(NX_ENROLL_KEY=KEY):
            headers = {'HTTP_CF_ACCESS_AUTHENTICATED_USER_EMAIL': 'ana@nex.tec.br'}
            body = {'name': 'Padrão', 'settings': {'exename': 'Cliente', 'enroll_key': KEY, 'chave': KEY}}
            self.client.post('/nextec/modelos/', data=json.dumps(body), content_type='application/json', **headers)
            self.assertFalse(SavedModel.objects.filter(settings__icontains=KEY).exists())

    def test_sem_chave_gera_com_aviso_e_sem_campos_de_inscricao(self):
        with self.env(NX_ENROLL_KEY=''):
            result, post, output = self.generate()
            html = self.client.get('/').content.decode()
        self.assertTrue(result['success'], result)
        self.assertFalse(result['enrollment'])
        self.assertTrue(any('NX_ENROLL_KEY' in aviso for aviso in result['avisos']))
        inputs = self.zip_inputs(result)
        self.assertNotIn('enroll_key', inputs)
        self.assertNotIn('enroll_panel', inputs)
        self.assertIn('NX_ENROLL_KEY', html)

    def test_chave_malformada_nao_e_embutida_nem_repetida_no_aviso(self):
        bad = 'nx1.123.curta;echo'
        with self.env(NX_ENROLL_KEY=bad):
            result, post, output = self.generate()
        self.assertTrue(result['success'], result)
        self.assertNotIn('enroll_key', self.zip_inputs(result))
        self.assertNotIn(bad, json.dumps(result))
        self.assertTrue(result['avisos'])

    @staticmethod
    def fake_panel(status=200, key=KEY, secret='outra-forte'):
        """Servidor falso do painel: confere o cabecalho do segredo e devolve a chave."""
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get('X-Nextec-Gen-Secret')))
                if self.headers.get('X-Nextec-Gen-Secret') != secret:
                    code, body = 401, {'error': 'gen_secret_invalid'}
                else:
                    code, body = status, ({'enroll_key': key, 'epoch': 3} if status == 200 else {'error': 'x'})
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *args):
                pass

        server = HTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, seen, 'http://127.0.0.1:%d' % server.server_address[1]

    def test_busca_automatica_no_painel_embute_a_chave_sem_vazar(self):
        server, seen, url = self.fake_panel()
        self.addCleanup(server.shutdown)
        with self.env(NX_PANEL_INTERNAL_URL=url):
            result, post, output = self.generate()
            self.assertNotIn(KEY, json.dumps(result))
            self.assertNotIn(KEY, output)
            self.assertNotIn('outra-forte', output)
        self.assertTrue(result['success'], result)
        self.assertEqual(result['avisos'], [])
        self.assertEqual(self.zip_inputs(result)['enroll_key'], KEY)
        self.assertEqual(seen[0], ('/api/nextec/gen/enroll-key', 'outra-forte'))
        self.assertFalse(SavedModel.objects.filter(settings__icontains=KEY).exists())

    def test_painel_vence_o_override_do_ambiente(self):
        server, seen, url = self.fake_panel()
        self.addCleanup(server.shutdown)
        old = 'nx1.1.ZzZzZz0123456789_-ZzZzZz0123456789'
        with self.env(NX_PANEL_INTERNAL_URL=url, NX_ENROLL_KEY=old):
            result, post, output = self.generate()
        self.assertEqual(self.zip_inputs(result)['enroll_key'], KEY)

    def test_rede_falha_cai_no_override_do_ambiente(self):
        server, seen, url = self.fake_panel()
        url = url  # porta fechada logo abaixo
        server.shutdown()
        server.server_close()
        with self.env(NX_PANEL_INTERNAL_URL=url, NX_ENROLL_KEY=KEY):
            result, post, output = self.generate()
        self.assertTrue(result['success'], result)
        self.assertEqual(self.zip_inputs(result)['enroll_key'], KEY)
        self.assertNotIn(KEY, output)

    def test_rede_falha_sem_override_avisa_e_gera_sem_inscricao(self):
        server, seen, url = self.fake_panel()
        server.shutdown()
        server.server_close()
        with self.env(NX_PANEL_INTERNAL_URL=url):
            result, post, output = self.generate()
        self.assertTrue(result['success'], result)
        self.assertFalse(result['enrollment'])
        self.assertTrue(result['avisos'])
        self.assertNotIn('enroll_key', self.zip_inputs(result))

    def test_segredo_errado_no_painel_cai_no_override_e_nao_vaza(self):
        server, seen, url = self.fake_panel(secret='outro-segredo')
        self.addCleanup(server.shutdown)
        with self.env(NX_PANEL_INTERNAL_URL=url, NX_ENROLL_KEY=KEY):
            result, post, output = self.generate()
        self.assertEqual(self.zip_inputs(result)['enroll_key'], KEY)
        self.assertIn('HTTP 401', output)
        self.assertNotIn('outra-forte', output)

    def test_resposta_do_painel_com_chave_malformada_e_ignorada(self):
        server, seen, url = self.fake_panel(key='nx1.1.curta;echo')
        self.addCleanup(server.shutdown)
        with self.env(NX_PANEL_INTERNAL_URL=url):
            result, post, output = self.generate()
        self.assertNotIn('enroll_key', self.zip_inputs(result))

    def test_sem_servidor_nextec_o_gerador_original_nao_avisa(self):
        with self.env(NX_SERVER_HOST='', NX_KEY='', NX_API_SERVER='', NX_ENROLL_KEY=''):
            result, post, output = self.generate()
        self.assertTrue(result['success'], result)
        self.assertEqual(result['avisos'], [])

    def test_validacao_do_runner_recusa_chave_adulterada(self):
        for value in (KEY + ';x', 'nx1.abc.' + 'a' * 20, 'x' + KEY, KEY + '\nPATH=x'):
            with self.subTest(value=value), self.assertRaises(ValueError) as caught:
                validate_build_inputs({'enroll_key': value})
            self.assertNotIn(value, str(caught.exception))
        validate_build_inputs({'enroll_key': KEY, 'enroll_panel': PANEL})

    def test_painel_cai_para_api_server_http(self):
        with self.env(NX_API_SERVER=''):
            self.assertEqual(nextec.enroll_panel('https://p.exemplo/'), 'https://p.exemplo')
            self.assertEqual(nextec.enroll_panel('remoto.exemplo:21114'), '')
