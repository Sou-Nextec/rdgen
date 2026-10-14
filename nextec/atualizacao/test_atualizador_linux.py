import importlib.util
import json
import os
import tempfile
import sys
import types
import unittest
from pathlib import Path

sys.modules.setdefault("fcntl", types.ModuleType("fcntl"))  # so existe em POSIX
SOURCE = Path(__file__).with_name("atualizador-linux.py")
SPEC = importlib.util.spec_from_file_location("nextec_atualizador_test", str(SOURCE))
updater = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(updater)

PEER = "536822159"


class Result:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr


class PeerIdDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def marker(self, app, code=None):
        path = self.root / "nextec-marker.json"
        path.write_text(json.dumps({"v": 1, "app": app, "upgrade_code": code or app.lower()}), encoding="utf-8")
        return [path]

    def binary(self, *parts):
        path = self.root.joinpath(*parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\n", encoding="utf-8")
        os.chmod(path, 0o755)
        return str(path)

    def runner_for(self, exe):
        def runner(command, **kwargs):
            if command[0] == exe and command[1] == "--get-id":
                return Result(PEER + "\n")
            return Result("", 1)
        return runner

    def check(self, app, *rel):
        exe = self.binary(*rel)
        found = updater.get_peer_id(self.runner_for(exe), self.marker(app), [str(self.root / "usr" / "bin"), str(self.root / "opt")])
        self.assertEqual(found, PEER)

    def test_free_app_name_xpto(self):
        self.check("XPTO", "usr", "bin", "xpto")

    def test_client_nextec_connect_in_opt_folder(self):
        self.check("Client-Nextec-Connect", "opt", "client-nextec-connect", "client-nextec-connect")

    def test_nextec_connect_legacy_name_still_works(self):
        self.check("Nextec-Connect", "usr", "bin", "nextec-connect")

    def test_systemd_execstart_points_to_binary(self):
        exe = self.binary("srv", "xpto")

        def runner(command, **kwargs):
            if command[:2] == ["systemctl", "list-units"]:
                return Result("qualquer.service loaded active running X\n")
            if command[:2] == ["systemctl", "show"]:
                return Result("path=%s ; argv[]=%s --service" % (exe, exe))
            if command[0] == exe:
                return Result(PEER)
            return Result("", 1)
        self.assertEqual(updater.get_peer_id(runner, self.marker("XPTO"), [str(self.root / "vazio")]), PEER)

    def test_failure_is_explicit_never_empty(self):
        with self.assertRaisesRegex(RuntimeError, "procurado:.*xpto"):
            updater.get_peer_id(lambda *a, **k: Result("", 1), self.marker("XPTO"), [str(self.root / "vazio")])


if __name__ == "__main__":
    unittest.main()
