import importlib.util
import sys
import types
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest import mock


try:
    import fcntl  # noqa: F401
except ImportError:  # execucao local em Windows: o modulo so existe no Linux
    sys.modules['fcntl'] = types.ModuleType('fcntl')

MODULE_PATH = Path(__file__).with_name("agente-senha-linux.py")
SPEC = importlib.util.spec_from_file_location("nextec_linux_agent", MODULE_PATH)
agent_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent_module)
# O painel vem do build (inscricao.json); nos testes o valor e fixado explicitamente, com host de exemplo.
agent_module.PANEL_HOST = "painel-remoto.nex.tec.br"


PEER_ID = "123456789"
TOKEN = "a" * 64
OPERATION_ID = "b" * 64
PASSWORD = "Z" * 24


def state(operation=None, managed=True, rotate=True, recovery=False):
    result = {
        "managed": managed,
        "rotate": rotate,
        "interval_minutes": 15,
        "approve_mode": "password",
        "verification_method": "use-permanent-password",
        "transaction_v1": True,
        "upgrade_required": False,
        "recovery": recovery,
    }
    if operation is not None:
        result["operation"] = operation
    return result


def operation(password=""):
    return {"operation_id": OPERATION_ID, "pending_version": 4, "pending_password": password}


class FakeRunner:
    def __init__(self, exe_path, peer_id=PEER_ID, password_result=None, service_path=None,
                 initial_options=None, option_write_stdout="", option_write_stderr="",
                 option_updates=True):
        self.exe_path = str(exe_path)
        self.peer_id = peer_id
        self.password_result = password_result or (0, "Done!\n", "")
        self.service_path = service_path or self.exe_path
        self.options = dict(initial_options or {})
        self.option_write_stdout = option_write_stdout
        self.option_write_stderr = option_write_stderr
        self.option_updates = option_updates
        self.calls = []

    def __call__(self, command, **kwargs):
        self.calls.append((list(command), kwargs))
        if command[0] == "systemctl":
            output = "ExecStart={ path=" + self.service_path + "; argv[0]=" + self.service_path + " --service ; }\n"
            return CompletedProcess(command, 0, output, "")
        if command[-1] == "--get-id":
            return CompletedProcess(command, 0, self.peer_id + "\n", "")
        if len(command) >= 3 and command[1] == "--option":
            if len(command) == 4:
                if self.option_updates:
                    self.options[command[2]] = command[3]
                return CompletedProcess(command, 0, self.option_write_stdout, self.option_write_stderr)
            if len(command) == 3:
                return CompletedProcess(command, 0, self.options.get(command[2], "") + "\n", "")
        if "--password" in command:
            code, stdout, stderr = self.password_result
            return CompletedProcess(command, code, stdout, stderr)
        raise AssertionError("unexpected process invocation")

    @property
    def password_calls(self):
        return [call for call in self.calls if "--password" in call[0]]


class ApiStub:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, panel, route, payload):
        self.calls.append((panel, route, dict(payload)))
        if not self.responses:
            raise AssertionError("unexpected API request: " + route)
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class PasswordAgentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="nextec-agent-")
        self.root = Path(self.temp.name)
        os.chmod(self.root, 0o700)
        self.data = self.root / "var" / "lib" / "nextec-connect"
        self.data.mkdir(parents=True, mode=0o700)
        os.chmod(self.data, 0o700)
        self.exe = self.root / "usr" / "bin" / "Nextec-Connect"
        self.exe.parent.mkdir(parents=True, mode=0o755)
        self.exe.write_text("fixture", encoding="utf-8")
        os.chmod(self.exe, 0o755)
        self.config_path = self.data / "agent-config.json"
        self.journal_path = self.data / "agent-applied.json"
        self.lock_path = self.data / "agent.lock"
        self.write_config()
        self.uid = os.geteuid()

    def test_default_lock_is_inside_the_protected_state_directory(self):
        self.assertEqual(agent_module.LOCK_PATH, Path("/var/lib/nextec-connect/agent.lock"))
        self.assertNotIn("/run/lock", str(agent_module.LOCK_PATH))

    def tearDown(self):
        self.temp.cleanup()

    def write_config(self, **changes):
        config = {
            "panel": "https://painel-remoto.nex.tec.br",
            "id": PEER_ID,
            "token": TOKEN,
            "exe_path": str(self.exe),
            "service_name": "nextec-connect.service",
        }
        config.update(changes)
        self.config_path.write_text(json.dumps(config), encoding="utf-8")
        os.chmod(self.config_path, 0o600)

    def make_agent(self, runner=None, api=None, password_factory=None):
        return agent_module.NextecPasswordAgent(
            config_path=self.config_path,
            journal_path=self.journal_path,
            lock_path=self.lock_path,
            expected_uid=self.uid,
            trusted_anchor=self.root,
            runner=runner or FakeRunner(self.exe),
            api_post=api or ApiStub([]),
            password_factory=password_factory or (lambda: "A" * 24),
        )

    def test_bad_peer_id_stops_before_api_or_password(self):
        runner = FakeRunner(self.exe, peer_id="erro 123456789")
        api = ApiStub([state(operation())])
        with self.assertRaisesRegex(agent_module.AgentError, "peer_id_mismatch"):
            self.make_agent(runner, api).cycle()
        self.assertEqual(api.calls, [])
        self.assertEqual(runner.password_calls, [])

    def test_cli_requires_zero_exit_and_exact_done_acknowledgment(self):
        results = [
            (0, "Changing permanent password is disabled!\n", ""),
            (0, "IPC error\n", ""),
            (0, "", ""),
            (7, "Done!\n", ""),
            (0, "Done! \n", ""),
        ]
        for result in results:
            with self.subTest(result=result):
                runner = FakeRunner(self.exe, password_result=result)
                api = ApiStub([state(operation(PASSWORD))])
                with self.assertRaisesRegex(agent_module.AgentError, "password_apply_failed"):
                    self.make_agent(runner, api).cycle()
                self.assertEqual([call[1] for call in api.calls], ["/api/nextec/agent/sync"])
                self.assertFalse(self.journal_path.exists())

    def test_proposal_ack_must_match_operation_before_password_cli(self):
        runner = FakeRunner(self.exe)
        api = ApiStub([
            state(operation()),
            {"ok": True, "operation_id": "c" * 64, "pending_version": 4},
        ])
        with self.assertRaisesRegex(agent_module.AgentError, "proposal_failed"):
            self.make_agent(runner, api).cycle()
        self.assertEqual(runner.password_calls, [])
        self.assertFalse(self.journal_path.exists())

    def test_sync_requires_full_transaction_contract(self):
        runner = FakeRunner(self.exe)
        incomplete = state(operation())
        del incomplete["recovery"]
        api = ApiStub([incomplete])
        with self.assertRaisesRegex(agent_module.AgentError, "invalid_sync_state"):
            self.make_agent(runner, api).cycle()
        self.assertEqual(runner.password_calls, [])

    def test_done_ack_line_must_be_exact(self):
        runner = FakeRunner(self.exe, password_result=(0, "Done! \n", ""))
        api = ApiStub([
            state(operation()),
            {"ok": True, "operation_id": OPERATION_ID, "pending_version": 4},
        ])
        with self.assertRaisesRegex(agent_module.AgentError, "password_apply_failed"):
            self.make_agent(runner, api).cycle()
        self.assertFalse(self.journal_path.exists())

    def test_disabled_policy_never_proposes_or_applies(self):
        runner = FakeRunner(self.exe)
        api = ApiStub([state(operation(), managed=False, rotate=False)])
        self.make_agent(runner, api).cycle()
        self.assertEqual([call[1] for call in api.calls], ["/api/nextec/agent/sync"])
        self.assertEqual(runner.password_calls, [])
        self.assertFalse(self.journal_path.exists())

    def test_unmanaged_without_policy_accepts_zero_interval(self):
        runner = FakeRunner(self.exe)
        no_policy = state(operation(), managed=False, rotate=False)
        no_policy['interval_minutes'] = 0
        self.make_agent(runner, ApiStub([no_policy])).cycle()
        self.assertEqual(runner.password_calls, [])

    def test_access_options_are_applied_and_verified_before_password(self):
        runner = FakeRunner(self.exe)
        api = ApiStub([
            state(operation(PASSWORD)),
            {"ok": True, "active_version": 4},
        ])
        self.make_agent(runner, api).cycle()
        commands = [call[0][1:] for call in runner.calls if "--option" in call[0] or "--password" in call[0]]
        self.assertEqual(commands, [
            ["--option", "approve-mode", "password"],
            ["--option", "approve-mode"],
            ["--option", "verification-method", "use-permanent-password"],
            ["--option", "verification-method"],
            ["--password", PASSWORD],
        ])

    def test_wrong_access_option_readback_stops_before_proposal_and_password(self):
        runner = FakeRunner(self.exe, initial_options={"approve-mode": "click"}, option_updates=False)
        api = ApiStub([state(operation())])
        with self.assertRaisesRegex(agent_module.AgentError, "access_option_verification_failed"):
            self.make_agent(runner, api).cycle()
        self.assertEqual([call[1] for call in api.calls], ["/api/nextec/agent/sync"])
        self.assertEqual(runner.password_calls, [])
        self.assertFalse(self.journal_path.exists())

    def test_disabled_option_cli_stops_before_proposal_and_password(self):
        runner = FakeRunner(self.exe, option_write_stdout="Settings are disabled!\n")
        api = ApiStub([state(operation())])
        with self.assertRaisesRegex(agent_module.AgentError, "access_option_apply_failed"):
            self.make_agent(runner, api).cycle()
        self.assertEqual([call[1] for call in api.calls], ["/api/nextec/agent/sync"])
        self.assertEqual(runner.password_calls, [])
        self.assertFalse(self.journal_path.exists())

    def test_confirm_timeout_recovers_from_applied_id_version_journal(self):
        runner = FakeRunner(self.exe)
        first_api = ApiStub([
            state(operation()),
            {"ok": True, "operation_id": OPERATION_ID, "pending_version": 4},
            agent_module.AgentError("api_timeout"),
        ])
        with self.assertRaisesRegex(agent_module.AgentError, "api_timeout"):
            self.make_agent(runner, first_api).cycle()
        saved = json.loads(self.journal_path.read_text(encoding="utf-8"))
        self.assertEqual(saved, {"operation_id": OPERATION_ID, "pending_version": 4})
        self.assertNotIn("password", saved)

        recovery_api = ApiStub([
            state(operation(PASSWORD), recovery=True),
            {"ok": True, "active_version": 4},
        ])
        self.make_agent(runner, recovery_api).cycle()
        self.assertEqual(len(runner.password_calls), 1)
        self.assertFalse(self.journal_path.exists())
        self.assertEqual(recovery_api.calls[-1][1], "/api/nextec/agent/confirm")

    def test_timed_out_proposal_uses_canonical_pending_password_on_next_sync(self):
        runner = FakeRunner(self.exe)
        first_api = ApiStub([state(operation()), agent_module.AgentError("api_timeout")])
        with self.assertRaisesRegex(agent_module.AgentError, "api_timeout"):
            self.make_agent(runner, first_api).cycle()
        self.assertFalse(self.journal_path.exists())
        self.assertEqual(runner.password_calls, [])

        next_api = ApiStub([
            state(operation(PASSWORD), recovery=True),
            {"ok": True, "active_version": 4},
        ])
        self.make_agent(runner, next_api).cycle()
        self.assertEqual(runner.password_calls[0][0][-1], PASSWORD)
        self.assertEqual([call[1] for call in next_api.calls], ["/api/nextec/agent/sync", "/api/nextec/agent/confirm"])

    def test_revoked_token_never_calls_password_cli(self):
        runner = FakeRunner(self.exe)
        api = ApiStub([agent_module.AgentError("api_http_401")])
        with self.assertRaisesRegex(agent_module.AgentError, "api_http_401"):
            self.make_agent(runner, api).cycle()
        self.assertEqual(runner.password_calls, [])
        self.assertFalse(self.journal_path.exists())

    def test_protocol_downgrade_stops_before_mutation(self):
        runner = FakeRunner(self.exe)
        # Legacy API shape before transaction_v1 was added.
        api = ApiStub([{"managed": True, "rotate": True, "interval_minutes": 15}])
        with self.assertRaisesRegex(agent_module.AgentError, "transaction_protocol_required"):
            self.make_agent(runner, api).cycle()
        self.assertEqual(runner.password_calls, [])

    def test_redirect_response_is_rejected(self):
        class RedirectResponse:
            status = 200
            headers = {"Content-Length": "2"}

            def geturl(self):
                return "https://attacker.example/collect"

            def read(self, amount):
                return b"{}"

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        class RedirectOpener:
            def open(self, request, timeout):
                self.request = request
                self.timeout = timeout
                return RedirectResponse()

        opener = RedirectOpener()
        with self.assertRaisesRegex(agent_module.AgentError, "api_redirect_rejected"):
            agent_module.post_json(
                "https://painel-remoto.nex.tec.br", "/api/nextec/agent/sync", {"token": TOKEN},
                opener_factory=lambda *_handlers: opener,
            )
        self.assertEqual(opener.request.get_header("User-agent"), "Nextec-Connect-Agent/1")
        self.assertEqual(opener.timeout, 15)

    def test_config_rejects_symlink_and_group_world_writable_permissions(self):
        target = self.data / "trusted-config.json"
        target.write_text(self.config_path.read_text(encoding="utf-8"), encoding="utf-8")
        os.chmod(target, 0o600)
        self.config_path.unlink()
        self.config_path.symlink_to(target)
        with self.assertRaisesRegex(agent_module.AgentError, "insecure_path_symlink"):
            agent_module.load_config(self.config_path, self.uid, self.root, self.root)

        self.config_path.unlink()
        self.write_config()
        os.chmod(self.config_path, 0o640)
        with self.assertRaisesRegex(agent_module.AgentError, "insecure_file_permissions"):
            agent_module.load_config(self.config_path, self.uid, self.root, self.root)

        os.chmod(self.config_path, 0o600)
        os.chmod(self.data, 0o770)
        with self.assertRaisesRegex(agent_module.AgentError, "insecure_path_permissions"):
            agent_module.load_config(self.config_path, self.uid, self.root, self.root)

    def test_untrusted_service_executable_or_mismatched_execstart_is_rejected(self):
        os.chmod(self.exe, 0o775)
        with self.assertRaisesRegex(agent_module.AgentError, "insecure_path_permissions"):
            agent_module.load_config(self.config_path, self.uid, self.root, self.root)
        os.chmod(self.exe, 0o755)
        runner = FakeRunner(self.exe, service_path=str(self.exe) + ".other")
        with self.assertRaisesRegex(agent_module.AgentError, "service_executable_mismatch"):
            agent_module.validate_service_and_peer(agent_module.load_config(self.config_path, self.uid, self.root, self.root), runner)

    def test_confirm_requires_matching_applied_journal(self):
        runner = FakeRunner(self.exe)
        api = ApiStub([state(operation(), managed=False, rotate=False)])
        self.make_agent(runner, api).cycle()
        self.assertEqual([call[1] for call in api.calls], ["/api/nextec/agent/sync"])
        self.assertEqual(runner.password_calls, [])

        self.journal_path.write_text(json.dumps({"operation_id": OPERATION_ID, "pending_version": 4}), encoding="utf-8")
        os.chmod(self.journal_path, 0o600)
        api = ApiStub([state(operation(), managed=False, rotate=False), {"ok": True, "active_version": 4}])
        self.make_agent(runner, api).cycle()
        self.assertEqual(api.calls[-1][1], "/api/nextec/agent/confirm")
        self.assertFalse(self.journal_path.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
