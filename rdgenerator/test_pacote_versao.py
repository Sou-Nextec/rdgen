"""A versao do pacote e a do gerador, e o conteudo empacotado so muda junto com a versao."""
import io
import json
import os
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock
from unittest.mock import Mock, patch

import pyzipper
from django.test import SimpleTestCase, TestCase, override_settings

from . import nextec
from .build_inputs import validate_build_inputs
from .forms import GenerateForm
from .views import generate_custom_client
from .models import GithubRun


class PackageVersionSource(SimpleTestCase):
    def test_package_version_is_generator_version(self):
        raw = Path(nextec.__file__).with_name('VERSION').read_text().strip()
        self.assertEqual(nextec.package_version(), raw)
        self.assertEqual(nextec.package_version(), nextec.product_version())

    def test_version_beyond_msi_limits_is_refused(self):
        for bad in ('256.0.0', '2.256.0', '2.3.65536'):
            with mock.patch.object(nextec, 'product_version', return_value=bad):
                with self.assertRaises(ValueError):
                    nextec.package_version()

    def test_old_agents_stay_upgradable(self):
        # 2.0.x instalados continuam atualizaveis: a versao nova e maior em cada parte comparada numericamente.
        new = tuple(int(x) for x in nextec.package_version().split('.'))
        self.assertGreater(new, (2, 0, 9))

    def test_form_field_is_hidden_compat(self):
        self.assertEqual(GenerateForm().fields['package_version'].widget.input_type, 'hidden')


class PackageLock(SimpleTestCase):
    def test_lock_matches_content_and_version(self):
        lock = json.loads(nextec.PACKAGE_LOCK.read_text(encoding='utf-8'))
        digest, _files = nextec.package_content_hash()
        version = nextec.package_version()
        cmd = 'python manage.py atualizar_lock_pacote'
        if digest != lock['hash'] and lock['versao'] == version:
            self.fail(f'conteudo do pacote mudou: suba a versao do gerador (rdgenerator/VERSION, hoje {version}) '
                      f'e rode {cmd}')
        self.assertEqual(lock['hash'], digest, f'versao subiu mas o lock esta desatualizado: rode {cmd}')
        self.assertEqual(lock['versao'], version, f'lock de outra versao: rode {cmd}')
        self.assertEqual(lock['agente_hash'], nextec.agent_set_hash())

    def test_content_change_without_bump_is_detected(self):
        import shutil
        import tempfile
        root = Path(nextec.__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as tmp:
            for rel in nextec.PACKAGE_FILES:
                dest = Path(tmp) / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(root / rel, dest)
            before, _ = nextec.package_content_hash(tmp)
            with (Path(tmp) / '.github/scripts/build-msi.ps1').open('ab') as handle:
                handle.write(b'\n# alterado\n')
            after, _ = nextec.package_content_hash(tmp)
            self.assertNotEqual(before, after)

    def test_hash_ignores_line_endings(self):
        import shutil
        import tempfile
        root = Path(nextec.__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as tmp:
            for rel in nextec.PACKAGE_FILES:
                dest = Path(tmp) / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                data = (root / rel).read_bytes()
                if not rel.endswith('.bmp'):
                    data = data.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
                dest.write_bytes(data)
            self.assertEqual(nextec.package_content_hash(tmp)[0], nextec.package_content_hash()[0])


@override_settings(GHBEARER='t', GHUSER='u', ZIP_PASSWORD='test-only-zip', SH_SECRET='outra-forte', GENURL='https://generator.example')
class ManualVersionIgnored(TestCase):
    def setUp(self):
        self.old = os.getcwd()
        self.tmp = tempfile.TemporaryDirectory()
        os.chdir(self.tmp.name)
        self.addCleanup(lambda: (os.chdir(self.old), self.tmp.cleanup()))

    def test_manual_value_is_replaced_by_generator_version(self):
        response = Mock(status_code=200)
        response.json.return_value = {'workflow_run_id': 7, 'html_url': 'https://github.com/test/actions/runs/7'}
        with patch('rdgenerator.views.requests.post', return_value=response),                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            result = generate_custom_client({'exename': 'Cliente', 'package_version': '2.0.9'}, 'https://generator.example')
        self.assertTrue(result['success'], result)
        with pyzipper.AESZipFile(Path('temp_zips') / ('secrets_' + result['uuid'] + '.zip')) as zf:
            zf.setpassword(b'test-only-zip')
            inputs = json.loads(zf.read('secrets.json'))
        validate_build_inputs(inputs)
        self.assertEqual(inputs['package_version'], nextec.package_version())
        self.assertNotEqual(inputs['package_version'], '2.0.9')
        run = GithubRun.objects.get(uuid=result['uuid'])
        self.assertEqual(run.package_version, nextec.package_version())
        self.assertEqual(run.generator_version, nextec.product_version())
