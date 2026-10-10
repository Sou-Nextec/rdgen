import json
import os
from django.test import TestCase

# Create your tests here.


class CallbackHardeningTests(TestCase):
    """Rotas chamadas pelo GitHub Actions (liberadas no Access): token por build, uuid inteiro, nomes exatos."""

    def setUp(self):
        import tempfile
        self._old = os.getcwd()
        self._tmp = tempfile.mkdtemp()
        os.chdir(self._tmp)
        os.makedirs('temp_zips', exist_ok=True)
        self.uuid = '11111111-2222-3333-4444-555555555555'

    def tearDown(self):
        os.chdir(self._old)

    def _upload(self, token=None, name='cliente.exe', uuid=None, size=10):
        from django.core.files.uploadedfile import SimpleUploadedFile
        extra = {}
        if token is not None:
            extra['HTTP_AUTHORIZATION'] = 'Bearer ' + token
        return self.client.post('/save_custom_client', {'file': SimpleUploadedFile(name, b'x' * size), 'uuid': uuid or self.uuid}, **extra)

    def test_upload_sem_token_e_recusado(self):
        self.assertEqual(self._upload().status_code, 403)
        self.assertFalse(os.path.exists(f'exe/{self.uuid}'))

    def test_upload_com_token_de_outro_build_e_recusado(self):
        from . import views
        self.assertEqual(self._upload(token=views.build_token('99999999-2222-3333-4444-555555555555')).status_code, 403)

    def test_upload_com_token_do_build_e_aceito(self):
        from . import views
        r = self._upload(token=views.build_token(self.uuid))
        self.assertEqual(r.status_code, 200)
        self.assertTrue(os.path.exists(f'exe/{self.uuid}/cliente.exe'))

    def test_upload_acima_do_limite_e_recusado(self):
        from . import views
        old = views.MAX_CLIENT_BYTES
        views.MAX_CLIENT_BYTES = 5
        try:
            self.assertEqual(self._upload(token=views.build_token(self.uuid), size=10).status_code, 403)
        finally:
            views.MAX_CLIENT_BYTES = old

    def test_cleanzip_com_pedaco_nao_apaga_nada(self):
        for u in ('aaaaaaaa-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000002'):
            open(f'temp_zips/secrets_{u}.zip', 'wb').close()
        r = self.client.post('/cleanzip', data=json.dumps({'uuid': '-'}), content_type='application/json')
        self.assertEqual(r.status_code, 400)
        self.assertEqual(len(os.listdir('temp_zips')), 2)

    def test_cleanzip_apaga_so_o_pacote_do_uuid(self):
        a, b = 'aaaaaaaa-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000002'
        for u in (a, b):
            open(f'temp_zips/secrets_{u}.zip', 'wb').close()
        r = self.client.post('/cleanzip', data=json.dumps({'uuid': a}), content_type='application/json')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(os.listdir('temp_zips'), [f'secrets_{b}.zip'])

    def test_get_zip_so_aceita_nome_de_pacote(self):
        open('temp_zips/secrets_%s.zip' % self.uuid, 'wb').close()
        open('temp_zips/outro.txt', 'wb').close()
        self.assertEqual(self.client.get('/get_zip', {'filename': 'secrets_%s.zip' % self.uuid}).status_code, 200)
        self.assertEqual(self.client.get('/get_zip', {'filename': 'outro.txt'}).status_code, 403)
        self.assertEqual(self.client.get('/get_zip', {'filename': '../manage.py'}).status_code, 403)
        self.assertEqual(self.client.get('/get_zip').status_code, 403)


class ConfigClaraTests(TestCase):
    def test_sem_variaveis_mostra_o_que_falta(self):
        from django.test import override_settings
        with override_settings(GHBEARER='', GHUSER='', ZIP_PASSWORD='', SH_SECRET=''):
            r = self.client.get('/')
        self.assertEqual(r.status_code, 503)
        body = r.content.decode()
        for nome in ('GHBEARER', 'GHUSER', 'ZIP_PASSWORD', 'SH_SECRET'):
            self.assertIn(nome, body)

    def test_com_variaveis_abre_o_formulario(self):
        from django.test import override_settings
        with override_settings(GHBEARER='t', GHUSER='u', ZIP_PASSWORD='senha-forte', SH_SECRET='outra-forte'):
            r = self.client.get('/')
        self.assertEqual(r.status_code, 200)

    def test_senhas_padrao_do_projeto_original_sao_recusadas(self):
        from django.test import override_settings
        with override_settings(GHBEARER='t', GHUSER='u', ZIP_PASSWORD='insecure', SH_SECRET='secret'):
            r = self.client.get('/')
        self.assertEqual(r.status_code, 503)
