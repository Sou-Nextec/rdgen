"""Pacote DEB com inscricao global: o arquivo vai para onde o coordenador Linux realmente le e e consumido por ele.

Roda quando NEXTEC_TEST_DEB aponta para um .deb ja processado por `inscricao-linux.sh incorporar`
(NEXTEC_TEST_KEY e a chave de teste usada); sem isso (ou sem dpkg-deb) os testes sao ignorados.
O CI do MSI (nextec-msi.yml) monta o .deb de teste e exporta as duas variaveis.
"""
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

DEB = os.environ.get("NEXTEC_TEST_DEB", "")
KEY = os.environ.get("NEXTEC_TEST_KEY", "")
PANEL = "https://painel-remoto.nex.tec.br"
LIB = Path("usr/lib/nextec-connect")


class AgentStub:
    @staticmethod
    def validate_secure_path(path, expected_uid=0, anchor=Path("/")):
        return Path(path)


@unittest.skipUnless(DEB and KEY and shutil.which("dpkg-deb"), "NEXTEC_TEST_DEB, NEXTEC_TEST_KEY e dpkg-deb necessarios")
class DebEnrollmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name) / "root"
        subprocess.run(["dpkg-deb", "-R", DEB, str(cls.root)], check=True)
        source = cls.root / LIB / "coordenador-agente-nextec-linux.py"
        spec = importlib.util.spec_from_file_location("nextec_coordinator_deb_under_test", str(source))
        cls.coordinator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.coordinator)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_arquivo_fica_ao_lado_do_coordenador_e_nao_em_etc(self):
        installed = self.root / LIB / "inscricao.json"
        self.assertTrue(installed.is_file())
        self.assertEqual(stat.S_IMODE(installed.stat().st_mode), 0o600)
        self.assertFalse((self.root / "etc/nextec/inscricao.json").exists())
        self.assertEqual(json.loads(installed.read_text("utf-8")), {"v": 1, "painel": PANEL, "chave": KEY})

    def test_coordenador_instalado_le_exatamente_esse_caminho(self):
        installed = (self.root / LIB / "inscricao.json").resolve()
        self.assertEqual(Path(self.coordinator.INSCRICAO_SOURCE).resolve(), installed)
        value = self.coordinator.read_enrollment_source(AgentStub, expected_uid=os.getuid())
        self.assertEqual(value, {"v": 1, "painel": PANEL, "chave": KEY})


if __name__ == "__main__":
    unittest.main()
