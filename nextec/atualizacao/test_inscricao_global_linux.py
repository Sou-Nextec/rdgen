import base64
import datetime
import importlib.util
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


SOURCE = Path(__file__).with_name("coordenador-agente-nextec-linux.py")
SPEC = importlib.util.spec_from_file_location("nextec_coordinator_self_enroll_test", str(SOURCE))
coordinator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(coordinator)

KEY = "ChaveGlobalDeTesteNaoSecreta0123456789"
PROPOSED = "A" * 43
REPLIES = {
    "404": (404, {"error": "peer_not_registered"}),
    "429": (429, {"error": "pending_limit"}),
    "403": (403, {"error": "blocked"}),
    "401": (401, {"error": "enroll_key_invalid"}),
    "409": (409, {"error": "already_enrolled"}),
    "400": (400, {"error": "bad_request"}),
}


class AgentError(Exception):
    pass


class FakePanel(BaseHTTPRequestHandler):
    bodies = []
    mode = {"status": None}

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length).decode("utf-8"))
        type(self).bodies.append((self.path, body))
        status, payload = 200, {"token": body["proposed_token"], "state": "pending"}
        override = type(self).mode["status"]
        if override:
            status, payload = REPLIES[override]
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class AgentStub:
    """post_json mirrors the real agent contract: parsed JSON or AgentError('api_http_NNN')."""
    AgentError = AgentError
    origin = ""

    @classmethod
    def post_json(cls, panel, route, payload):
        assert panel == coordinator.PANEL
        request = urllib.request.Request(cls.origin + route, data=json.dumps(payload).encode("utf-8"),
                                         headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise AgentError("api_http_%d" % exc.code) from exc
        except urllib.error.URLError as exc:
            raise AgentError("api_request_failed") from exc

    @staticmethod
    def _execstart_path(value):
        return value

    @staticmethod
    def validate_secure_path(path, expected_uid=0, anchor=Path("/"), file_mode=None, executable=False):
        return Path(path)


class SelfEnrollTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), FakePanel)
        AgentStub.origin = "http://127.0.0.1:%d" % cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        FakePanel.bodies = []
        FakePanel.mode["status"] = None
        self.temp = tempfile.TemporaryDirectory(dir=str(SOURCE.parent))
        self.root = Path(self.temp.name)
        self.now = datetime.datetime(2026, 10, 12, 12, 0, tzinfo=datetime.timezone.utc)
        self.enrollment = {"v": 1, "painel": coordinator.PANEL, "chave": KEY}
        self.paths = {
            "bootstrap_path": self.root / "bootstrap.json",
            "journal_path": self.root / "provisionamento-agente.json",
            "config_path": self.root / "agent-config.json",
            "enrollment_path": self.root / "inscricao.json",
            "self_state_path": self.root / "inscricao-estado.json",
        }
        self.tokens = ["B" * 43, "C" * 43]

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def secure_read(path):
        return json.loads(Path(path).read_text(encoding="utf-8"))

    @staticmethod
    def atomic_write(path, value):
        Path(path).write_text(json.dumps(value), encoding="utf-8")

    def cycle(self, status=None, enrollment="default", **kwargs):
        FakePanel.mode["status"] = status
        enrollment = self.enrollment if enrollment == "default" else enrollment
        args = dict(self.paths)
        args.update({
            "agent": AgentStub,
            "now": self.now,
            "discover": lambda agent: {"service_name": "rustdesk.service", "exe_path": "/usr/bin/rustdesk",
                                       "id": "536822159"},
            "secure_read": self.secure_read,
            "atomic_write": self.atomic_write,
            "secure_remove": lambda path: Path(path).unlink(missing_ok=True),
            "authorization_read": lambda path: self.secure_read(path),
            "enrollment_read": lambda path: enrollment,
            "uuid_reader": lambda: "TUFDSElORS1HVUlE",
            "token_factory": lambda: self.tokens.pop(0),
        })
        args.update(kwargs)
        return coordinator.run_cycle(**args)

    def state(self):
        return self.secure_read(self.paths["self_state_path"])

    def test_uuid_matches_client_formula(self):
        machine = self.root / "machine-id"
        machine.write_text("  0123456789abcdef0123456789abcdef\n", encoding="utf-8")
        expected = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode("ascii")
        self.assertEqual(coordinator.machine_uuid(paths=[self.root / "absent", machine]), expected)
        self.assertEqual(expected, "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
        with self.assertRaisesRegex(coordinator.CoordinatorError, "service_identity_unavailable"):
            coordinator.machine_uuid(paths=[self.root / "absent"])

    def test_enrollment_ok_saves_token_and_copy_without_bootstrap(self):
        self.assertEqual(self.cycle(), "complete")
        self.assertEqual(len(FakePanel.bodies), 1)
        route, body = FakePanel.bodies[0]
        self.assertEqual(route, "/api/nextec/agent/self-enroll")
        self.assertEqual(body, {"enroll_key": KEY, "id": "536822159", "uuid": "TUFDSElORS1HVUlE",
                                "proposed_token": "B" * 43})
        config = self.secure_read(self.paths["config_path"])
        self.assertEqual(config["token"], "B" * 43)
        self.assertEqual(config["id"], "536822159")
        self.assertEqual(set(config), {"panel", "id", "token", "exe_path", "service_name"})
        self.assertEqual(self.secure_read(self.paths["enrollment_path"]), self.enrollment)
        self.assertEqual(self.state()["state"], "self")
        self.assertEqual(self.state()["proposed_token"], "")

    def test_404_and_429_retry_with_backoff_and_same_token(self):
        for status in ("404", "429"):
            FakePanel.bodies = []
            for name in ("config_path", "self_state_path"):
                self.paths[name].unlink(missing_ok=True)
            self.tokens = ["B" * 43]
            with self.assertRaises(coordinator.CoordinatorError) as first:
                self.cycle(status)
            self.assertEqual(str(first.exception), {"404": "peer_not_registered", "429": "rate_limited"}[status])
            with self.assertRaisesRegex(coordinator.CoordinatorError, "self_backoff"):
                self.cycle(None, now=self.now + datetime.timedelta(minutes=2))
            self.assertEqual(len(FakePanel.bodies), 1)
            with self.assertRaises(coordinator.CoordinatorError):
                self.cycle(status, now=self.now + datetime.timedelta(minutes=5))
            with self.assertRaisesRegex(coordinator.CoordinatorError, "self_backoff"):
                self.cycle(None, now=self.now + datetime.timedelta(minutes=10))
            self.assertEqual(self.cycle(None, now=self.now + datetime.timedelta(minutes=16)), "complete")
            self.assertEqual([b["proposed_token"] for _, b in FakePanel.bodies], ["B" * 43] * 3)

    def test_401_and_409_require_manual_authorization_and_do_not_insist(self):
        for status in ("401", "409"):
            FakePanel.bodies = []
            self.paths["self_state_path"].unlink(missing_ok=True)
            self.tokens = ["B" * 43]
            with self.assertRaisesRegex(coordinator.CoordinatorError, "manual_authorization_required"):
                self.cycle(status)
            with self.assertRaisesRegex(coordinator.CoordinatorError, "manual_authorization_required"):
                self.cycle(None, now=self.now + datetime.timedelta(hours=5))
            self.assertEqual(len(FakePanel.bodies), 1)
            self.assertFalse(self.paths["config_path"].exists())
        # A different global key (new MSI) re-enables the attempt.
        self.tokens = ["C" * 43]
        replaced = dict(self.enrollment, chave="OutraChaveGlobalDeTeste9876543210")
        self.assertEqual(self.cycle(None, enrollment=replaced), "complete")

    def test_403_stops_for_24_hours(self):
        with self.assertRaisesRegex(coordinator.CoordinatorError, "self_blocked"):
            self.cycle("403")
        with self.assertRaisesRegex(coordinator.CoordinatorError, "self_blocked"):
            self.cycle(None, now=self.now + datetime.timedelta(hours=23))
        self.assertEqual(len(FakePanel.bodies), 1)
        self.assertEqual(self.cycle(None, now=self.now + datetime.timedelta(hours=25)), "complete")
        self.assertEqual(len(FakePanel.bodies), 2)

    def test_replay_after_network_loss_is_idempotent(self):
        AgentStub.origin, real = "http://127.0.0.1:9", AgentStub.origin  # closed port: connection refused
        try:
            with self.assertRaisesRegex(coordinator.CoordinatorError, "network_retry"):
                self.cycle()
        finally:
            AgentStub.origin = real
        pending = self.state()
        self.assertEqual(pending["proposed_token"], "B" * 43)
        self.assertEqual(self.cycle(None, now=self.now + datetime.timedelta(minutes=6)), "complete")
        self.assertEqual(FakePanel.bodies[0][1]["proposed_token"], "B" * 43)
        self.assertEqual(self.tokens, ["C" * 43])
        # Once configured the machine is never enrolled again.
        calls = len(FakePanel.bodies)
        result = self.cycle(None, discover=lambda agent: {"service_name": "rustdesk.service",
                                                          "exe_path": "/usr/bin/rustdesk", "id": "536822159"})
        self.assertEqual(result, "already_configured")
        self.assertEqual(len(FakePanel.bodies), calls)

    def test_interrupted_completion_drops_the_proposed_token_without_second_post(self):
        self.atomic_write(self.paths["config_path"], {
            "panel": coordinator.PANEL, "id": "536822159", "token": "B" * 43,
            "exe_path": "/usr/bin/rustdesk", "service_name": "rustdesk.service"})
        self.atomic_write(self.paths["self_state_path"], {
            "state": "self", "chave_sha256": "x", "proposed_token": "B" * 43, "attempts": 0,
            "next_try_utc": "", "blocked_until_utc": ""})
        self.assertEqual(self.cycle(), "already_configured")
        self.assertEqual(self.state()["proposed_token"], "")
        self.assertEqual(FakePanel.bodies, [])

    def test_unexpected_ack_does_not_write_config(self):
        class WrongAck(AgentStub):
            @classmethod
            def post_json(cls, panel, route, payload):
                return {"token": "Z" * 43, "state": "pending"}

        with self.assertRaisesRegex(coordinator.CoordinatorError, "protocol_error"):
            self.cycle(agent=WrongAck)
        self.assertFalse(self.paths["config_path"].exists())

    def test_without_enrollment_file_keeps_previous_manual_behavior(self):
        with self.assertRaisesRegex(coordinator.CoordinatorError, "manual_authorization_required"):
            self.cycle(enrollment=None)
        self.assertEqual(FakePanel.bodies, [])

    def test_legacy_bootstrap_flow_is_untouched_and_never_self_enrolls(self):
        self.atomic_write(self.paths["bootstrap_path"], {
            "painel": coordinator.PANEL, "id": "536822159", "uuid": "device-uuid-1", "bootstrap": "B" * 40})
        sent = []

        def legacy_post(payload):
            sent.append(dict(payload))
            return {"token": payload["proposed_token"]}

        result = self.cycle(post=legacy_post, self_post=lambda payload: self.fail("self-enroll used"))
        self.assertEqual(result, "complete")
        self.assertEqual(sent[0]["bootstrap"], "B" * 40)
        self.assertEqual(sent[0]["uuid"], "device-uuid-1")
        self.assertEqual(set(sent[0]), {"bootstrap", "id", "uuid", "proposed_token"})
        self.assertEqual(FakePanel.bodies, [])
        self.assertFalse(self.paths["self_state_path"].exists())

    def test_enrollment_parser_is_strict(self):
        good = json.dumps(self.enrollment).encode("utf-8")
        self.assertEqual(coordinator.parse_enrollment(good), self.enrollment)
        for bad in (dict(self.enrollment, v=2), dict(self.enrollment, painel="https://outro.invalid"),
                    dict(self.enrollment, extra=1), dict(self.enrollment, chave="curta")):
            with self.assertRaises(coordinator.CoordinatorError):
                coordinator.parse_enrollment(json.dumps(bad).encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
