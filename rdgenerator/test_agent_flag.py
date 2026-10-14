"""Flag nx_agent: o agente Nextec entra no pacote por decisao explicita do build, nunca pelo nome do app."""
import io
import json
import os
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

import pyzipper
from django.test import SimpleTestCase, TestCase, override_settings

from . import nextec
from .build_inputs import validate_build_inputs
from .forms import GenerateForm
from .views import generate_custom_client

NAMES = ['XPTO', 'Client-Nextec-Connect', 'Nextec-Connect', 'Suporte-Qualquer-Nome', 'rustdesk']


class AgentEnabledTests(SimpleTestCase):
    def test_nome_nunca_decide(self):
        for name in NAMES:
            with self.subTest(appname=name):
                self.assertTrue(nextec.agent_enabled({'appname': name}))
                self.assertTrue(nextec.agent_enabled({'appname': name, 'nx_agent': 'true'}))
                self.assertFalse(nextec.agent_enabled({'appname': name, 'nx_agent': 'false'}))

    def test_padrao_ligado_e_suporte_avulso_desligado(self):
        self.assertTrue(nextec.agent_enabled({}))
        self.assertTrue(nextec.agent_enabled({'nx_agent': ''}))
        self.assertTrue(nextec.agent_enabled({'nx_agent': True}))
        self.assertFalse(nextec.agent_enabled({'nx_agent': False}))
        self.assertFalse(nextec.agent_enabled({'installation': 'installationN'}))
        # explicito vence o derivado
        self.assertTrue(nextec.agent_enabled({'installation': 'installationN', 'nx_agent': 'true'}))

    def test_validacao_do_build_aceita_so_booleano(self):
        validate_build_inputs({'nx_agent': 'true'})
        validate_build_inputs({'nx_agent': 'false'})
        with self.assertRaises(ValueError):
            validate_build_inputs({'nx_agent': 'talvez'})

    def test_formulario_sem_o_campo_nao_desliga_o_agente(self):
        self.assertEqual(GenerateForm().fields['nx_agent'].initial, None)
        self.assertFalse(GenerateForm().fields['nx_agent'].required)


@override_settings(GHBEARER='t', GHUSER='u', ZIP_PASSWORD='test-only-zip', SH_SECRET='outra-forte', GENURL='https://generator.example')
class AgentFlagInBuildTests(TestCase):
    def setUp(self):
        self.old = os.getcwd()
        self.tmp = tempfile.TemporaryDirectory()
        os.chdir(self.tmp.name)
        self.addCleanup(lambda: (os.chdir(self.old), self.tmp.cleanup()))

    def build(self, **params):
        response = Mock(status_code=200)
        response.json.return_value = {'workflow_run_id': 7, 'html_url': 'https://github.com/test/actions/runs/7'}
        base = {'exename': 'Cliente'}
        base.update(params)
        with patch('rdgenerator.views.requests.post', return_value=response), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            result = generate_custom_client(base, 'https://generator.example')
        self.assertTrue(result['success'], result)
        with pyzipper.AESZipFile(Path('temp_zips') / ('secrets_' + result['uuid'] + '.zip')) as zf:
            zf.setpassword(b'test-only-zip')
            inputs = json.loads(zf.read('secrets.json'))
        validate_build_inputs(inputs)
        return inputs

    def test_flag_segue_o_pedido_e_nao_o_nome(self):
        for name in NAMES:
            with self.subTest(appname=name):
                self.assertEqual(self.build(appname=name)['nx_agent'], 'true')
                self.assertEqual(self.build(appname=name, nx_agent='true')['nx_agent'], 'true')
                self.assertEqual(self.build(appname=name, nx_agent='false')['nx_agent'], 'false')

    def test_suporte_avulso_por_instalacao_desativada(self):
        self.assertEqual(self.build(appname='XPTO', installation='installationN')['nx_agent'], 'false')
