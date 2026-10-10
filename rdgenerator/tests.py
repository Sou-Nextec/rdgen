import json
import os
import io
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch
from django.test import TestCase
from django.core.files.uploadedfile import SimpleUploadedFile
from PIL import Image

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


class BuildOutputsTests(TestCase):
    def setUp(self):
        import tempfile
        from pathlib import Path
        from .models import GithubRun
        self.old = os.getcwd()
        self.tmp = tempfile.TemporaryDirectory()
        os.chdir(self.tmp.name)
        self.uuid = '11111111-2222-3333-4444-555555555555'
        self.directory = Path('exe') / self.uuid
        self.directory.mkdir(parents=True)
        GithubRun.objects.create(uuid=self.uuid, github_run_id='1', status='success', filename='Nextec-Connect', platform='windows')

    def tearDown(self):
        os.chdir(self.old)
        self.tmp.cleanup()

    def test_success_requires_received_exe_and_msi(self):
        from .views import _get_run_status
        (self.directory / 'Nextec-Connect.exe').write_bytes(b'exe')
        result = _get_run_status(self.uuid)
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual(result['missing_files'], ['Nextec-Connect.msi'])
        self.assertEqual(len(result['files']), 1)
        (self.directory / 'Nextec-Connect.msi').write_bytes(b'msi')
        self.assertEqual(_get_run_status(self.uuid)['status'], 'success')

    def test_empty_or_unrelated_files_do_not_count(self):
        from .views import _get_run_status
        (self.directory / 'Nextec-Connect.msi').touch()
        (self.directory / 'other.exe').write_bytes(b'exe')
        result = _get_run_status(self.uuid, 'other', 'linux')
        self.assertEqual(result['files'], [])
        self.assertEqual(result['status'], 'incomplete')

    def test_html_does_not_offer_missing_msi(self):
        from django.template.loader import render_to_string
        html = render_to_string('failure.html', {'files': [{'name': 'Nextec-Connect.exe', 'url': 'download?filename=Nextec-Connect.exe'}], 'missing_files': ['Nextec-Connect.msi']})
        self.assertIn('download?filename=Nextec-Connect.exe', html)
        self.assertNotIn('download?filename=Nextec-Connect.msi', html)


class BrandingAssetsTests(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        old_cwd = os.getcwd()
        os.chdir(self.temp.name)
        self.addCleanup(os.chdir, old_cwd)
        self.branding = Path(self.temp.name) / 'branding'
        self.branding_env = patch.dict(os.environ, {'NX_BRANDING_DIR': str(self.branding)})
        self.branding_env.start()
        self.addCleanup(self.branding_env.stop)
        self.allowed = patch.dict(os.environ, {'NX_ALLOWED_EMAILS': ''})
        self.allowed.start()
        self.addCleanup(self.allowed.stop)

    @staticmethod
    def image_file(name, size, fmt):
        stream = io.BytesIO()
        Image.new('RGB', size, '#1479d1').save(stream, format=fmt)
        return SimpleUploadedFile(name, stream.getvalue(), content_type=f'image/{fmt.lower()}')

    def test_manager_translated_and_shows_version_and_asset_specs(self):
        response = self.client.get('/nextec/imagens/')
        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        self.assertIn('Gerador 2.0.1', body)
        self.assertIn('Identidade visual', body)
        self.assertIn('<a href="../../">Gerar cliente</a>', body)
        self.assertIn('<form method="post" enctype="multipart/form-data">', body)
        from .branding import ASSETS
        self.assertEqual(set(ASSETS), {'icon', 'logo', 'privacy'})

    def test_generator_uses_relative_paths_behind_url_prefix(self):
        with patch('rdgenerator.nextec.config_problems', return_value=[]):
            response = self.client.get('/', SCRIPT_NAME='/gerador')
        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        self.assertIn('action="generator"', body)
        self.assertIn('href="nextec/imagens/"', body)

    def test_midia_persistida_pode_ser_visualizada_por_nome_fixo(self):
        self.client.post('/nextec/imagens/', {
            'asset': 'icon', 'action': 'upload',
            'image': self.image_file('icon.png', (64, 64), 'PNG'),
        })
        response = self.client.get('/get_artwork/icon')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'image/png')
        response.close()

    def test_upload_de_identidade_visual_exige_csrf(self):
        from django.test import Client
        client = Client(enforce_csrf_checks=True)
        response = client.post('/nextec/imagens/', {'asset': 'icon', 'action': 'upload'})
        self.assertEqual(response.status_code, 403)

    def test_geracao_usa_tela_de_privacidade_salva_como_padrao(self):
        from . import nextec, views

        uploaded = self.image_file('privacy.png', (96, 54), 'PNG')
        from .branding import save_upload
        managed_path = save_upload('privacy', uploaded)
        expected = managed_path.read_bytes()

        response = Mock(status_code=200)
        response.json.return_value = {'workflow_run_id': 123, 'html_url': 'https://github.com/example/run/123'}
        with (
            patch.object(nextec, 'config_problems', return_value=[]),
            patch.object(nextec, 'is_configured', return_value=False),
            patch.object(views, 'validate_generate_params', side_effect=lambda params: (params, {})),
            patch.object(views, 'validate_build_inputs'),
            patch.object(views, 'save_png', return_value=('false', 'false', 'false')) as save_png,
            patch.object(views.requests, 'post', return_value=response),
        ):
            result = views.generate_custom_client({'exename': 'Nextec-Connect'}, 'https://gerador.example')

        self.assertTrue(result['success'])
        self.assertEqual(save_png.call_args_list[2].args[0].read(), expected)

    def test_upload_de_tela_de_privacidade_rejeita_altura_acima_do_limite(self):
        from .branding import save_upload

        image = self.image_file('privacy.png', (100, 1200), 'PNG')
        with self.assertRaisesRegex(ValueError, '1920 × 1080'):
            save_upload('privacy', image)

