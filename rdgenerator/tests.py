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


class AutorizadosTests(TestCase):
    EMAIL = 'HTTP_CF_ACCESS_AUTHENTICATED_USER_EMAIL'

    def _cfg(self):
        from django.test import override_settings
        return override_settings(GHBEARER='t', GHUSER='u', ZIP_PASSWORD='senha-forte', SH_SECRET='outra-forte')

    def test_sem_lista_quem_passa_pelo_access_usa(self):
        with self._cfg():
            r = self.client.get('/', **{self.EMAIL: 'qualquer@nex.tec.br'})
        self.assertEqual(r.status_code, 200)

    def test_com_lista_pessoa_fora_e_barrada(self):
        os.environ['NX_ALLOWED_EMAILS'] = 'admin@nex.tec.br, tecnico@nex.tec.br'
        try:
            with self._cfg():
                r = self.client.get('/', REMOTE_ADDR='172.18.0.5', **{self.EMAIL: 'outro@nex.tec.br'})
                semcab = self.client.get('/', REMOTE_ADDR='172.18.0.5')
        finally:
            del os.environ['NX_ALLOWED_EMAILS']
        self.assertEqual(r.status_code, 403)
        self.assertIn('outro@nex.tec.br', r.content.decode())
        self.assertEqual(semcab.status_code, 403)

    def test_com_lista_pessoa_autorizada_entra_sem_diferenciar_maiusculas(self):
        os.environ['NX_ALLOWED_EMAILS'] = 'admin@nex.tec.br'
        try:
            with self._cfg():
                r = self.client.get('/', REMOTE_ADDR='172.18.0.5', **{self.EMAIL: 'Admin@Nex.Tec.br'})
        finally:
            del os.environ['NX_ALLOWED_EMAILS']
        self.assertEqual(r.status_code, 200)

    def test_rotas_do_github_nao_exigem_pessoa(self):
        os.environ['NX_ALLOWED_EMAILS'] = 'admin@nex.tec.br'
        try:
            r = self.client.get('/get_zip', {'filename': 'x'}, REMOTE_ADDR='172.18.0.5')
        finally:
            del os.environ['NX_ALLOWED_EMAILS']
        self.assertEqual(r.status_code, 403)  # 403 do próprio get_zip (nome inválido), não a tela de autorização
        self.assertNotIn('autorizado a gerar', r.content.decode())

    def test_verificacao_de_saude_local_passa(self):
        os.environ['NX_ALLOWED_EMAILS'] = 'admin@nex.tec.br'
        try:
            with self._cfg():
                r = self.client.get('/', REMOTE_ADDR='127.0.0.1')
        finally:
            del os.environ['NX_ALLOWED_EMAILS']
        self.assertEqual(r.status_code, 200)


class ChaveTests(TestCase):
    def _env(self, **kw):
        import contextlib

        @contextlib.contextmanager
        def ctx():
            old = {k: os.environ.get(k) for k in kw}
            os.environ.update(kw)
            try:
                yield
            finally:
                for k, v in old.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
        return ctx()

    def test_chave_do_arquivo_trava_o_campo(self):
        import tempfile
        d = tempfile.mkdtemp()
        p = os.path.join(d, 'k.pub')
        open(p, 'w').write('CHAVEPUBLICA=' + chr(10))
        with self._env(NX_SERVER_HOST='remoto.exemplo', NX_KEY_FILE=p, NX_KEY=''):
            from . import nextec
            self.assertEqual(nextec.server_defaults()['key'], 'CHAVEPUBLICA=')
            self.assertIn('key', nextec.locked_fields())

    def test_arquivo_ilegivel_deixa_o_campo_editavel_e_obrigatorio(self):
        import tempfile
        d = tempfile.mkdtemp()  # um diretorio no lugar do arquivo (o que o Docker cria)
        with self._env(NX_SERVER_HOST='remoto.exemplo', NX_KEY_FILE=d, NX_KEY=''):
            from . import nextec
            from .forms import GenerateForm
            self.assertNotIn('key', nextec.server_defaults())
            self.assertNotIn('key', nextec.locked_fields())
            form = GenerateForm(initial=nextec.initial())
            self.assertNotIn('readonly', form.fields['key'].widget.attrs)
            r = nextec.apply({'key': ''})
            self.assertEqual(r['key'], '')
            bound = GenerateForm({'platform': 'windows', 'version': '1.5.0', 'exename': 'x', 'key': ''})
            bound.is_valid()
            self.assertIn('key', bound.errors)

    def test_sem_servidor_nextec_nada_muda(self):
        with self._env(NX_SERVER_HOST='', NX_KEY='', NX_KEY_FILE=''):
            from .forms import GenerateForm
            bound = GenerateForm({'platform': 'windows', 'version': '1.5.0', 'exename': 'x', 'key': ''})
            bound.is_valid()
            self.assertNotIn('key', bound.errors)


class ModeloEChaveTests(TestCase):
    def test_modelo_com_porta_recusada_nao_trava_o_formulario(self):
        os.environ['NX_SERVER_HOST'] = 'remoto.exemplo'
        os.environ['NX_KEY'] = 'CHAVEPUBLICA='
        try:
            from .forms import GenerateForm
            form = GenerateForm({'platform': 'windows', 'version': '1.5.0', 'exename': 'x',
                                 'direction': 'both', 'installation': 'installationY', 'settings': 'settingsY',
                                 'theme': 'system', 'themeDorO': 'default', 'passApproveMode': 'password-click',
                                 'permissionsDorO': 'default', 'permissionsType': 'custom',
                                 'serverIP': 'outro.host', 'serverPort': '21117', 'key': 'ZZZ'})
            self.assertTrue(form.is_valid(), form.errors)
            self.assertEqual(form.cleaned_data['serverPort'], '')
            self.assertEqual(form.cleaned_data['serverIP'], 'remoto.exemplo')
            self.assertEqual(form.cleaned_data['key'], 'CHAVEPUBLICA=')
        finally:
            del os.environ['NX_SERVER_HOST']
            del os.environ['NX_KEY']

    def test_chave_aparece_como_senha_no_formulario(self):
        os.environ['NX_SERVER_HOST'] = 'remoto.exemplo'
        os.environ['NX_KEY'] = 'CHAVEPUBLICA='
        try:
            from django.test import override_settings
            with override_settings(GHBEARER='t', GHUSER='u', ZIP_PASSWORD='senha-forte', SH_SECRET='outra-forte'):
                html = self.client.get('/').content.decode()
        finally:
            del os.environ['NX_SERVER_HOST']
            del os.environ['NX_KEY']
        import re
        campo = re.search(r'<input[^>]*name="key"[^>]*>', html).group(0)
        self.assertIn('type="password"', campo)
        self.assertIn('readonly', campo)
