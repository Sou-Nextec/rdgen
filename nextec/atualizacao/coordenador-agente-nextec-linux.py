#!/usr/bin/python3
"""One-shot Linux bootstrap coordinator for the Nextec RustDesk agent."""
import argparse
import datetime
import importlib.util
import json
import os
import re
import secrets
import stat
import subprocess
import sys
from pathlib import Path


PANEL = "https://painel-remoto.nex.tec.br"
PANEL_HOST = "painel-remoto.nex.tec.br"
BOOTSTRAP_PATH = Path("/var/lib/nextec-connect/bootstrap.json")
JOURNAL_PATH = Path("/var/lib/nextec-connect/provisionamento-agente.json")
CONFIG_PATH = Path("/var/lib/nextec-connect/agent-config.json")
AGENT_PATH = Path(__file__).resolve().with_name("agente-senha-linux.py")
MAX_BOOTSTRAP_BYTES = 4096
BOOTSTRAP_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
ID_RE = re.compile(r"^[0-9]{6,64}$")
UUID_MAX = 128
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,180}\.service$")
JOURNAL_FIELDS = {"painel", "id", "uuid", "bootstrap", "proposed_token", "created_utc", "state"}


class CoordinatorError(RuntimeError):
    """Safe status code; never includes a credential or response body."""


def load_agent_module(path=AGENT_PATH):
    path = Path(os.path.abspath(path))
    current = Path(path.anchor)
    chain = [current]
    for part in path.parts[1:]:
        current = current / part
        chain.append(current)
    try:
        for component in chain:
            info = os.lstat(str(component))
            if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise CoordinatorError("insecure_agent_component")
        if not stat.S_ISREG(os.lstat(str(path)).st_mode):
            raise CoordinatorError("agent_component_missing")
    except OSError as exc:
        raise CoordinatorError("agent_component_missing") from exc
    if not path.is_file():
        raise CoordinatorError("agent_component_missing")
    spec = importlib.util.spec_from_file_location("nextec_linux_agent", str(path))
    if spec is None or spec.loader is None:
        raise CoordinatorError("agent_component_missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _duplicate_rejector(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CoordinatorError("invalid_input")
        result[key] = value
    return result


def parse_authorization(raw):
    if len(raw) > MAX_BOOTSTRAP_BYTES:
        raise CoordinatorError("invalid_input")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_duplicate_rejector)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CoordinatorError("invalid_input") from exc
    if not isinstance(value, dict) or set(value) != {"painel", "id", "uuid", "bootstrap"}:
        raise CoordinatorError("invalid_input")
    if any(not isinstance(item, str) for item in value.values()):
        raise CoordinatorError("invalid_input")
    if value["painel"] != PANEL:
        raise CoordinatorError("invalid_panel")
    if not ID_RE.fullmatch(value["id"]):
        raise CoordinatorError("invalid_identity")
    if not value["uuid"].strip() or len(value["uuid"]) > UUID_MAX:
        raise CoordinatorError("invalid_identity")
    if not BOOTSTRAP_RE.fullmatch(value["bootstrap"]):
        raise CoordinatorError("invalid_bootstrap")
    return value


def read_authorization(agent, path=BOOTSTRAP_PATH, expected_uid=0, anchor=Path("/")):
    agent.validate_secure_path(path, expected_uid, anchor, file_mode=0o600)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(str(path), flags)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise CoordinatorError("unsafe_authorization_file")
            raw = stream.read(MAX_BOOTSTRAP_BYTES + 1)
    except OSError as exc:
        raise CoordinatorError("authorization_read_failed") from exc
    return parse_authorization(raw)


def _read_secure_json(agent, path, expected_uid, anchor):
    try:
        return agent._read_secure_json(path, expected_uid, anchor, 0o600)
    except agent.AgentError as exc:
        raise CoordinatorError(str(exc)) from exc


def _atomic_json(agent, path, value, expected_uid, anchor):
    try:
        agent._atomic_write_json(path, value, expected_uid, anchor)
    except agent.AgentError as exc:
        raise CoordinatorError(str(exc)) from exc


def _remove_secure(agent, path, expected_uid, anchor):
    try:
        agent._remove_journal(path, expected_uid, anchor)
    except agent.AgentError as exc:
        raise CoordinatorError(str(exc)) from exc


def post_bootstrap(agent, payload):
    """Use the agent's bounded HTTPS client, which rejects redirects."""
    return agent.post_json(PANEL, "/api/nextec/agent/bootstrap", payload)


def _validate_journal(value):
    if not isinstance(value, dict) or set(value) != JOURNAL_FIELDS:
        raise CoordinatorError("invalid_journal")
    if (value["painel"] != PANEL or not isinstance(value["id"], str) or not ID_RE.fullmatch(value["id"])
            or not isinstance(value["uuid"], str) or not value["uuid"] or len(value["uuid"]) > UUID_MAX
            or not isinstance(value["bootstrap"], str) or not BOOTSTRAP_RE.fullmatch(value["bootstrap"])
            or not isinstance(value["proposed_token"], str) or not TOKEN_RE.fullmatch(value["proposed_token"])
            or not isinstance(value["created_utc"], str) or value["state"] not in ("pending", "manual")):
        raise CoordinatorError("invalid_journal")
    try:
        datetime.datetime.fromisoformat(value["created_utc"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise CoordinatorError("invalid_journal") from exc
    return value


def discover_local_identity(agent, runner=subprocess.run, timeout=10):
    """Find one installed RustDesk client service and query its actual local ID."""
    try:
        units = runner(
            ["systemctl", "list-units", "--all", "--type=service", "--no-legend", "--no-pager"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CoordinatorError("service_discovery_failed") from exc
    if units.returncode != 0 or units.stderr.strip():
        raise CoordinatorError("service_discovery_failed")
    candidate_names = set()
    for line in units.stdout.splitlines():
        fields = line.split()
        if not fields:
            continue
        name = fields[0]
        if SERVICE_RE.fullmatch(name) and re.search(r"rustdesk|rdclient", name, re.IGNORECASE):
            candidate_names.add(name)
    identities = []
    for service_name in sorted(candidate_names):
        try:
            service = runner(
                ["systemctl", "show", "--system", service_name, "--property=ExecStart", "--value"],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
            if service.returncode != 0 or service.stderr.strip():
                continue
            executable = agent._execstart_path(service.stdout)
            agent.validate_secure_path(executable, 0, Path("/"), executable=True)
            peer = runner([executable, "--get-id"], capture_output=True, text=True, timeout=timeout, check=False)
        except (agent.AgentError, CoordinatorError, OSError, subprocess.SubprocessError, ValueError):
            continue
        # Accept only a clean, exact ID response. Never parse IDs out of diagnostics.
        value = peer.stdout.strip()
        if peer.returncode == 0 and not peer.stderr.strip() and ID_RE.fullmatch(value):
            identities.append({"service_name": service_name, "exe_path": executable, "id": value})
    if len(identities) != 1:
        raise CoordinatorError("service_identity_ambiguous" if identities else "service_identity_unavailable")
    return identities[0]


def _age_seconds(created_utc, now):
    created = datetime.datetime.fromisoformat(created_utc.replace("Z", "+00:00"))
    if created.tzinfo is None:
        raise CoordinatorError("invalid_journal")
    return (now - created.astimezone(datetime.timezone.utc)).total_seconds()


def run_cycle(*, agent=None, bootstrap_path=BOOTSTRAP_PATH, journal_path=JOURNAL_PATH,
              config_path=CONFIG_PATH, expected_uid=0, anchor=Path("/"), now=None,
              discover=discover_local_identity, post=None, token_factory=None,
              secure_read=None, atomic_write=None, secure_remove=None, authorization_read=None):
    agent = agent or load_agent_module()
    now = now or datetime.datetime.now(datetime.timezone.utc)
    secure_read = secure_read or (lambda path: _read_secure_json(agent, path, expected_uid, anchor))
    atomic_write = atomic_write or (lambda path, value: _atomic_json(agent, path, value, expected_uid, anchor))
    secure_remove = secure_remove or (lambda path: _remove_secure(agent, path, expected_uid, anchor))
    authorization_read = authorization_read or (lambda path: read_authorization(agent, path, expected_uid, anchor))
    post = post or (lambda payload: post_bootstrap(agent, payload))
    token_factory = token_factory or (lambda: secrets.token_urlsafe(32))

    identity = discover(agent)
    if not ID_RE.fullmatch(identity.get("id", "")):
        raise CoordinatorError("service_identity_unavailable")
    if os.path.lexists(config_path):
        config = secure_read(config_path)
        journal = _validate_journal(secure_read(journal_path)) if os.path.lexists(journal_path) else None
        if (journal and config.get("id") == journal["id"] and config.get("token") == journal["proposed_token"]
                and journal["id"] == identity["id"]):
            secure_remove(journal_path)
            if os.path.lexists(bootstrap_path):
                secure_remove(bootstrap_path)
            return "complete"
        if (set(config) == {"panel", "id", "token", "exe_path", "service_name"}
                and config.get("panel") == PANEL and config.get("id") == identity["id"]
                and config.get("exe_path") == identity["exe_path"]
                and config.get("service_name") == identity["service_name"]
                and isinstance(config.get("token"), str)
                and getattr(agent, "TOKEN_PATTERN", TOKEN_RE).fullmatch(config["token"])):
            return "already_configured"
        raise CoordinatorError("already_enrolled")

    journal = _validate_journal(secure_read(journal_path)) if os.path.lexists(journal_path) else None
    authorization = None
    if os.path.lexists(bootstrap_path):
        authorization = authorization_read(bootstrap_path)

    if journal and authorization:
        same_auth = (authorization["id"] == journal["id"] and authorization["uuid"] == journal["uuid"]
                     and authorization["bootstrap"] == journal["bootstrap"])
        if not same_auth:
            prior_age = _age_seconds(journal["created_utc"], now.astimezone(datetime.timezone.utc))
            expired = prior_age >= 900 or prior_age < -60
            if journal["state"] != "manual" and not expired:
                raise CoordinatorError("pending_authorization")
            # A replacement code only counts as a new authorization when an admin
            # placed a different code in the protected input file.
            if authorization["id"] != identity["id"]:
                raise CoordinatorError("identity_conflict")
            journal = None
        else:
            secure_remove(bootstrap_path)

    if journal is None:
        if authorization is None:
            raise CoordinatorError("manual_authorization_required")
        if authorization["id"] != identity["id"]:
            raise CoordinatorError("identity_conflict")
        proposed = token_factory()
        if not isinstance(proposed, str) or not TOKEN_RE.fullmatch(proposed):
            raise CoordinatorError("token_generation_failed")
        journal = {
            "painel": PANEL,
            "id": authorization["id"],
            "uuid": authorization["uuid"],
            "bootstrap": authorization["bootstrap"],
            "proposed_token": proposed,
            "created_utc": now.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "state": "pending",
        }
        atomic_write(journal_path, journal)
        secure_remove(bootstrap_path)

    if journal["state"] == "manual":
        raise CoordinatorError("manual_authorization_required")
    if journal["painel"] != PANEL or journal["id"] != identity["id"]:
        raise CoordinatorError("identity_conflict")
    age = _age_seconds(journal["created_utc"], now.astimezone(datetime.timezone.utc))
    if age >= 900 or age < -60:
        journal["state"] = "manual"
        atomic_write(journal_path, journal)
        raise CoordinatorError("manual_authorization_required")

    payload = {
        "bootstrap": journal["bootstrap"],
        "id": journal["id"],
        "uuid": journal["uuid"],
        "proposed_token": journal["proposed_token"],
    }
    try:
        response = post(payload)
    except agent.AgentError as exc:
        code = str(exc)
        match = re.fullmatch(r"api_http_([0-9]{3})", code)
        status = int(match.group(1)) if match else None
        if status in (408, 425, 429) or (status is not None and 500 <= status <= 599):
            raise CoordinatorError("network_retry") from exc
        if status is not None and 400 <= status < 500:
            journal["state"] = "manual"
            atomic_write(journal_path, journal)
            raise CoordinatorError("manual_authorization_required") from exc
        if code == "api_request_failed":
            raise CoordinatorError("network_retry") from exc
        raise CoordinatorError("protocol_error") from exc
    if not isinstance(response, dict) or set(response) != {"token"} or response.get("token") != journal["proposed_token"]:
        raise CoordinatorError("protocol_error")
    if os.path.lexists(config_path):
        raise CoordinatorError("already_enrolled")
    atomic_write(config_path, {
        "panel": PANEL,
        "id": journal["id"],
        "token": journal["proposed_token"],
        "exe_path": identity["exe_path"],
        "service_name": identity["service_name"],
    })
    secure_remove(journal_path)
    return "complete"


def activate_password_agent_timer(runner=subprocess.run):
    """Repair/enable the password agent timer without changing credentials."""
    try:
        result = runner(
            ["systemctl", "enable", "--now", "nextec-connect-agent.timer"],
            capture_output=True, text=True, timeout=20, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CoordinatorError("agent_timer_registration_failed") from exc
    if result.returncode != 0:
        raise CoordinatorError("agent_timer_registration_failed")


def main(cycle=run_cycle, runner=subprocess.run):
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        print("Nextec Connect coordinator: root_required", file=sys.stderr)
        return 1
    try:
        status = cycle()
        if status in ("complete", "already_configured"):
            activate_password_agent_timer(runner)
        print("Nextec Connect coordinator: " + status)
        return 0
    except CoordinatorError as exc:
        # Only fixed status codes reach the journal/log stream.
        code = str(exc)
        if not re.fullmatch(r"[a-z0-9_]{1,64}", code):
            code = "protocol_error"
        print("Nextec Connect coordinator: " + code, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
