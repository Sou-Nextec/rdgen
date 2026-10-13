"""O painel dos componentes Linux vem do build (inscricao.json), nunca de dominio fixo nem da rede.

Cada modulo e copiado para uma pasta propria com um inscricao.json, como o pacote .deb instala.
Qualquer nome de host serve (o dono pode usar o dominio que quiser); so https do painel configurado e aceito.
"""
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

try:
    import fcntl  # noqa: F401
except ImportError:  # execucao local em Windows: o modulo so existe no Linux
    sys.modules["fcntl"] = types.ModuleType("fcntl")

HERE = Path(__file__).resolve().parent
MODULES = {
    "atualizador": "atualizador-linux.py",
    "agente": "agente-senha-linux.py",
    "coordenador": "coordenador-agente-nextec-linux.py",
}
_real_lstat = os.lstat


def _owned_private_file(path, *args, **kwargs):
    """Em Windows o st_mode nao tem permissoes POSIX; simula root:root 0600 so para o inscricao.json."""
    if str(path).endswith("inscricao.json"):
        return types.SimpleNamespace(st_mode=0o100600, st_uid=0)
    return _real_lstat(path, *args, **kwargs)


class PanelFromBuildTests(unittest.TestCase):
    def setUp(self):
        if os.name == "nt":
            for patch in (mock.patch.object(os, "lstat", _owned_private_file), mock.patch.object(os, "geteuid", lambda: 0, create=True)):
                patch.start()
                self.addCleanup(patch.stop)

    def load(self, key, inscricao=None, mode=0o600):
        folder = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(folder, ignore_errors=True))
        target = folder / MODULES[key]
        target.write_bytes((HERE / MODULES[key]).read_bytes())
        if inscricao is not None:
            file = folder / "inscricao.json"
            file.write_text(inscricao if isinstance(inscricao, str) else json.dumps(inscricao), "utf-8")
            os.chmod(file, mode)
        spec = importlib.util.spec_from_file_location("nx_" + key, str(target))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_qualquer_host_https_do_build_e_usado(self):
        for host in ("painel.xpto.example", "suporte.cliente-teste.com.br", "10-0-0-5.exemplo.test"):
            painel = {"v": 1, "painel": f"https://{host}", "chave": "nx1.1.AbCdEf0123456789AbCdEf0123456789"}
            with self.subTest(host=host):
                updater = self.load("atualizador", painel)
                self.assertEqual(updater.PANEL, f"https://{host}")
                self.assertEqual(updater.PANEL_HOST, host)
                self.assertEqual(updater.BASE_URL, f"https://{host}/api/nextec/update")
                self.assertEqual(self.load("agente", painel).PANEL_HOST, host)
                coordinator = self.load("coordenador", painel)
                self.assertEqual(coordinator.PANEL, f"https://{host}")
                self.assertEqual(coordinator.PANEL_HOST, host)

    def test_sem_arquivo_nao_ha_painel_nem_dominio_embutido(self):
        for key in MODULES:
            source = (HERE / MODULES[key]).read_text("utf-8")
            self.assertNotIn("nex.tec.br", source)
        updater = self.load("atualizador")
        self.assertEqual(updater.PANEL, "")
        self.assertEqual(self.load("coordenador").PANEL, "")
        self.assertEqual(self.load("agente").PANEL_HOST, "")

    def test_painel_invalido_e_recusado(self):
        invalidos = ["http://painel.xpto.example", "https://user:senha@painel.xpto.example", "https://painel.xpto.example/api?x=1",
                     "https://painel.xpto.example:8443", "ftp://painel.xpto.example", "https://", "painel.xpto.example", 7]
        for painel in invalidos:
            with self.subTest(painel=painel):
                self.assertEqual(self.load("atualizador", {"v": 1, "painel": painel}).PANEL, "")
        self.assertEqual(self.load("atualizador", "{nao e json").PANEL, "")

    def test_arquivo_gravavel_por_outros_e_recusado(self):
        if os.name == "nt":
            self.skipTest("bits de permissao POSIX")
        self.assertEqual(self.load("atualizador", {"v": 1, "painel": "https://painel.xpto.example"}, mode=0o666).PANEL, "")

    def test_atualizador_recusa_url_fora_do_painel_configurado(self):
        updater = self.load("atualizador", {"v": 1, "painel": "https://painel.xpto.example"})
        with self.assertRaises(ValueError):
            updater.request_bytes("https://painel-remoto.outro.example/api/nextec/update/versao.json", 10)
        with self.assertRaises(ValueError):
            updater.request_bytes("https://painel.xpto.example.atacante.test/x", 10)


if __name__ == "__main__":
    unittest.main()
