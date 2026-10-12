import datetime
import importlib.util
import json
import os
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path


SOURCE = Path(__file__).with_name("coordenador-agente-nextec-linux.py")
SPEC = importlib.util.spec_from_file_location("nextec_coordinator_test", str(SOURCE))
coordinator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(coordinator)


class AgentError(Exception):
    pass


class AgentStub:
    AgentError = AgentError

    @staticmethod
    def _execstart_path(value):
        if not value.startswith("path="):
            raise AgentError("service_execstart_unavailable")
        return value[5:].split(";", 1)[0]

    @staticmethod
    def validate_secure_path(path, expected_uid=0, anchor=Path("/"), file_mode=None, executable=False):
        return Path(path)


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=str(SOURCE.parent))
        self.root = Path(self.temp.name)
        self.bootstrap = self.root / "bootstrap.json"
        self.journal = self.root / "provisionamento-agente.json"
        self.config = self.root / "agent-config.json"
        self.now = datetime.datetime(2026, 10, 12, 12, 0, tzinfo=datetime.timezone.utc)
        self.authorization = {
            "painel": coordinator.PANEL,
            "id": "536822159",
            "uuid": "device-uuid-1",
            "bootstrap": "B" * 40,
        }
        self.store = {}
        self.writes = []
        self.removals = []

    def tearDown(self):
        self.temp.cleanup()

    def put_authorization(self, value=None):
        value = value or self.authorization
        self.bootstrap.write_text(json.dumps(value), encoding="utf-8")
        if os.name == "posix":
            os.chmod(self.bootstrap, 0o600)
        self.store[str(self.bootstrap)] = value

    def secure_read(self, path):
        path = str(path)
        if path in self.store:
            return self.store[path]
        return json.loads(Path(path).read_text(encoding="utf-8"))

    def atomic_write(self, path, value):
        path = Path(path)
        self.writes.append((str(path), dict(value)))
        self.store[str(path)] = dict(value)
        path.write_text(json.dumps(value), encoding="utf-8")
        if os.name == "posix":
            os.chmod(path, 0o600)

    def secure_remove(self, path):
        path = str(path)
        self.removals.append(path)
        self.store.pop(path, None)
        Path(path).unlink(missing_ok=True)

    def discovery(self, agent=None):
        return {"service_name": "rustdesk.service", "exe_path": "/usr/bin/rustdesk", "id": "536822159"}

    def cycle(self, **kwargs):
        args = {
            "agent": AgentStub(),
            "bootstrap_path": self.bootstrap,
            "journal_path": self.journal,
            "config_path": self.config,
            "expected_uid": 0,
            "anchor": Path("/"),
            "now": self.now,
            "discover": self.discovery,
            "secure_read": self.secure_read,
            "atomic_write": self.atomic_write,
            "secure_remove": self.secure_remove,
        }
        args.setdefault("authorization_read", lambda path: self.store[str(path)])
        args.update(kwargs)
        return coordinator.run_cycle(**args)

    def test_discovery_uses_systemd_execstart_and_only_clean_cli_identity(self):
        calls = []

        def runner(command, **kwargs):
            calls.append(command)
            if command[1:3] == ["list-units", "--all"]:
                return type("Result", (), {"returncode": 0, "stderr": "", "stdout": "rustdesk.service loaded active running RustDesk\n"})()
            if command[1] == "show":
                return type("Result", (), {"returncode": 0, "stderr": "", "stdout": "path=/usr/bin/rustdesk; argv[]=/usr/bin/rustdesk --service"})()
            return type("Result", (), {"returncode": 0, "stderr": "", "stdout": "536822159\n"})()

        result = coordinator.discover_local_identity(AgentStub(), runner=runner)
        self.assertEqual(result["id"], "536822159")
        self.assertEqual(result["service_name"], "rustdesk.service")
        self.assertEqual(calls[-1], ["/usr/bin/rustdesk", "--get-id"])

    def test_discovery_rejects_id_embedded_in_cli_error(self):
        def runner(command, **kwargs):
            if command[1:3] == ["list-units", "--all"]:
                stdout = "rustdesk.service loaded active running RustDesk\n"
            elif command[1] == "show":
                stdout = "path=/usr/bin/rustdesk;"
            else:
                stdout = "error: last id was 536822159"
            return type("Result", (), {"returncode": 0, "stderr": "", "stdout": stdout})()

        with self.assertRaisesRegex(coordinator.CoordinatorError, "service_identity_unavailable"):
            coordinator.discover_local_identity(AgentStub(), runner=runner)

    def test_bootstrap_route_uses_fixed_panel_endpoint_and_shared_agent_http_client(self):
        calls = []

        class RoutedAgent:
            @staticmethod
            def post_json(panel, route, payload):
                calls.append((panel, route, payload))
                return {"token": payload["proposed_token"]}

        payload = {"bootstrap": "B" * 40, "id": "536822159", "uuid": "uuid", "proposed_token": "A" * 43}
        self.assertEqual(coordinator.post_bootstrap(RoutedAgent(), payload), {"token": "A" * 43})
        self.assertEqual(calls, [("https://painel-remoto.nex.tec.br", "/api/nextec/agent/bootstrap", payload)])

    def test_systemd_unit_creates_writable_state_directory_before_first_run(self):
        unit = SOURCE.with_name("nextec-agent-bootstrap.service").read_text(encoding="utf-8")
        self.assertIn("StateDirectory=nextec-connect", unit)
        self.assertIn("StateDirectoryMode=0755", unit)
        self.assertIn("ReadWritePaths=/var/lib/nextec-connect", unit)
        self.assertIn("PrivateTmp=no", unit)
        self.assertIn("compartilhar o IPC RustDesk em /tmp", unit)

    def test_bootstrap_persists_token_before_post_and_saves_acknowledged_config(self):
        self.put_authorization()
        calls = []

        def post(payload):
            calls.append(dict(payload))
            self.assertEqual(self.writes[0][0], str(self.journal))
            return {"token": payload["proposed_token"]}

        result = self.cycle(post=post, token_factory=lambda: "A" * 43)
        self.assertEqual(result, "complete")
        self.assertEqual(calls[0]["id"], self.authorization["id"])
        self.assertEqual(calls[0]["uuid"], self.authorization["uuid"])
        self.assertEqual(calls[0]["proposed_token"], "A" * 43)
        self.assertEqual(self.store[str(self.config)]["token"], "A" * 43)
        self.assertFalse(self.journal.exists())
        self.assertFalse(self.bootstrap.exists())

    def test_network_retry_reuses_persisted_bootstrap_and_token(self):
        self.put_authorization()
        sent = []

        def fail(payload):
            sent.append(dict(payload))
            raise AgentError("api_request_failed")

        with self.assertRaisesRegex(coordinator.CoordinatorError, "network_retry"):
            self.cycle(post=fail, token_factory=lambda: "B" * 43)
        journal_before = dict(self.store[str(self.journal)])
        self.now += datetime.timedelta(minutes=4)
        result = self.cycle(post=lambda payload: sent.append(dict(payload)) or {"token": payload["proposed_token"]},
                            token_factory=lambda: self.fail("must not generate a second token"))
        self.assertEqual(result, "complete")
        self.assertEqual(sent[0], sent[1])
        self.assertEqual(journal_before["proposed_token"], sent[1]["proposed_token"])

    def test_expired_authorization_stops_retry_without_api_call(self):
        self.put_authorization()
        self.atomic_write(self.journal, {
            "painel": coordinator.PANEL,
            "id": "536822159",
            "uuid": "device-uuid-1",
            "bootstrap": "B" * 40,
            "proposed_token": "C" * 43,
            "created_utc": (self.now - datetime.timedelta(minutes=16)).isoformat().replace("+00:00", "Z"),
            "state": "pending",
        })
        calls = []
        with self.assertRaisesRegex(coordinator.CoordinatorError, "manual_authorization_required"):
            self.cycle(post=lambda payload: calls.append(payload), token_factory=lambda: self.fail("must not generate"))
        self.assertEqual(calls, [])
        self.assertEqual(self.store[str(self.journal)]["state"], "manual")

    def test_http_conflict_requires_manual_authorization_and_does_not_reenroll(self):
        self.put_authorization()
        with self.assertRaisesRegex(coordinator.CoordinatorError, "manual_authorization_required"):
            self.cycle(post=lambda _: (_ for _ in ()).throw(AgentError("api_http_409")),
                       token_factory=lambda: "D" * 43)
        calls = []
        with self.assertRaisesRegex(coordinator.CoordinatorError, "manual_authorization_required"):
            self.cycle(post=lambda payload: calls.append(payload), token_factory=lambda: self.fail("must not reenroll"))
        self.assertEqual(calls, [])

    def test_expired_journal_accepts_only_an_explicit_replacement_code(self):
        replacement = dict(self.authorization, bootstrap="C" * 40)
        self.put_authorization(replacement)
        self.atomic_write(self.journal, {
            "painel": coordinator.PANEL,
            "id": "536822159",
            "uuid": "device-uuid-1",
            "bootstrap": "B" * 40,
            "proposed_token": "D" * 43,
            "created_utc": (self.now - datetime.timedelta(minutes=16)).isoformat().replace("+00:00", "Z"),
            "state": "pending",
        })
        result = self.cycle(post=lambda payload: {"token": payload["proposed_token"]},
                            token_factory=lambda: "E" * 43)
        self.assertEqual(result, "complete")
        self.assertEqual(self.store[str(self.config)]["token"], "E" * 43)
        self.assertEqual(self.writes[-2][1]["bootstrap"], "C" * 40)

    def test_identity_mismatch_and_existing_config_never_reach_bootstrap(self):
        self.put_authorization()
        calls = []
        with self.assertRaisesRegex(coordinator.CoordinatorError, "identity_conflict"):
            self.cycle(discover=lambda _: {"id": "111111", "service_name": "rustdesk.service", "exe_path": "/bin/rustdesk"}, post=lambda p: calls.append(p))
        self.assertEqual(calls, [])
        self.put_authorization()
        self.atomic_write(self.config, {"panel": coordinator.PANEL, "id": "536822159", "token": "E" * 43})
        with self.assertRaisesRegex(coordinator.CoordinatorError, "already_enrolled"):
            self.cycle(post=lambda p: calls.append(p))
        self.assertEqual(calls, [])

    def test_valid_existing_config_is_not_reenrolled_and_can_repair_timer(self):
        self.atomic_write(self.config, {
            "panel": coordinator.PANEL,
            "id": "536822159",
            "token": "E" * 43,
            "exe_path": "/usr/bin/rustdesk",
            "service_name": "rustdesk.service",
        })
        calls = []
        result = self.cycle(post=lambda payload: calls.append(payload))
        self.assertEqual(result, "already_configured")
        self.assertEqual(calls, [])
        self.assertFalse(self.journal.exists())
        systemctl_calls = []

        def runner(command, **kwargs):
            systemctl_calls.append(command)
            return type("Result", (), {"returncode": 0, "stderr": "", "stdout": ""})()

        output = StringIO()
        with patch.object(coordinator.os, "geteuid", lambda: 0, create=True), redirect_stdout(output):
            self.assertEqual(coordinator.main(cycle=lambda: result, runner=runner), 0)
        self.assertEqual(systemctl_calls, [["systemctl", "enable", "--now", "nextec-connect-agent.timer"]])

    def test_timer_registration_failure_is_reported_without_touching_config(self):
        with self.assertRaisesRegex(coordinator.CoordinatorError, "agent_timer_registration_failed"):
            coordinator.activate_password_agent_timer(
                runner=lambda *_args, **_kwargs: type("Result", (), {"returncode": 1, "stderr": "", "stdout": ""})()
            )

    def test_mismatched_ack_does_not_write_agent_config(self):
        self.put_authorization()
        with self.assertRaisesRegex(coordinator.CoordinatorError, "protocol_error"):
            self.cycle(post=lambda _: {"token": "F" * 43}, token_factory=lambda: "G" * 43)
        self.assertFalse(self.config.exists())

    def test_authorization_parser_rejects_wrong_panel_and_duplicate_fields(self):
        wrong_panel = dict(self.authorization, painel="http://attacker.invalid")
        with self.assertRaisesRegex(coordinator.CoordinatorError, "invalid_panel"):
            coordinator.parse_authorization(json.dumps(wrong_panel).encode("utf-8"))
        duplicate = ('{"painel":"https://painel-remoto.nex.tec.br","id":"536822159","uuid":"a","bootstrap":"'
                    + "H" * 40 + '","id":"536822159"}')
        with self.assertRaisesRegex(coordinator.CoordinatorError, "invalid_input"):
            coordinator.parse_authorization(duplicate.encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
