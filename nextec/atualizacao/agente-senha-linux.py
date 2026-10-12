#!/usr/bin/python3
"""Rotator Linux Nextec; requires an explicitly provisioned root-only config."""
import fcntl
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


CONFIG_PATH = Path("/var/lib/nextec-connect/agent-config.json")
JOURNAL_PATH = Path("/var/lib/nextec-connect/agent-applied.json")
LOCK_PATH = Path("/var/lib/nextec-connect/agent.lock")
PANEL_HOST = "painel-remoto.nex.tec.br"
MAX_HTTP_BYTES = 32 * 1024
HTTP_TIMEOUT_SECONDS = 15
ID_PATTERN = re.compile(r"^[0-9]{6,32}$")
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9._~-]{16,4096}$")
PASSWORD_PATTERN = re.compile(r"^[A-Za-z0-9]{24,64}$")
OPERATION_PATTERN = re.compile(r"^[a-f0-9]{64}$")
SERVICE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,180}\.service$")
PASSWORD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


class AgentError(RuntimeError):
    """Safe-to-log agent failure; never carries a token, password, or response body."""


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _inside(path, root):
    try:
        return os.path.commonpath((os.path.abspath(path), os.path.abspath(root))) == os.path.abspath(root)
    except ValueError:
        return False


def validate_secure_path(path, expected_uid=0, anchor=Path("/"), file_mode=None, executable=False):
    """Reject symlinks and non-root or group/world-writable path components."""
    path = Path(os.path.abspath(path))
    anchor = Path(os.path.abspath(anchor))
    if not _inside(path, anchor):
        raise AgentError("insecure_path")
    relative = path.relative_to(anchor)
    components = [anchor]
    current = anchor
    for part in relative.parts:
        current = current / part
        components.append(current)
    final = None
    for index, component in enumerate(components):
        try:
            info = os.lstat(component)
        except OSError as exc:
            raise AgentError("insecure_path") from exc
        if stat.S_ISLNK(info.st_mode):
            raise AgentError("insecure_path_symlink")
        if info.st_uid != expected_uid or info.st_mode & 0o022:
            raise AgentError("insecure_path_permissions")
        is_final = index == len(components) - 1
        if not is_final and not stat.S_ISDIR(info.st_mode):
            raise AgentError("insecure_path_parent")
        if is_final:
            final = info
    if final is None:
        raise AgentError("insecure_path")
    if file_mode is not None:
        if not stat.S_ISREG(final.st_mode) or stat.S_IMODE(final.st_mode) != file_mode:
            raise AgentError("insecure_file_permissions")
    if executable and (not stat.S_ISREG(final.st_mode) or not final.st_mode & 0o111):
        raise AgentError("insecure_executable")
    return path


def _read_secure_json(path, expected_uid, anchor, required_mode):
    validate_secure_path(path, expected_uid, anchor, file_mode=required_mode)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(str(path), flags)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != required_mode:
                raise AgentError("insecure_file_permissions")
            raw = stream.read(MAX_HTTP_BYTES + 1)
    except OSError as exc:
        raise AgentError("config_read_failed") from exc
    if len(raw) > MAX_HTTP_BYTES:
        raise AgentError("config_too_large")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentError("invalid_json") from exc
    if not isinstance(value, dict):
        raise AgentError("invalid_config")
    return value


def load_config(path=CONFIG_PATH, expected_uid=0, anchor=Path("/"), executable_anchor=Path("/")):
    config = _read_secure_json(path, expected_uid, anchor, 0o600)
    if set(config) != {"panel", "id", "token", "exe_path", "service_name"}:
        raise AgentError("invalid_config_fields")
    panel = config.get("panel")
    if not isinstance(panel, str):
        raise AgentError("invalid_panel")
    parsed = urllib.parse.urlsplit(panel)
    try:
        port = parsed.port
    except ValueError as exc:
        raise AgentError("invalid_panel") from exc
    if (parsed.scheme != "https" or parsed.hostname != PANEL_HOST or port not in (None, 443)
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in ("", "/")):
        raise AgentError("invalid_panel")
    peer_id = config.get("id")
    if not isinstance(peer_id, str) or not ID_PATTERN.fullmatch(peer_id):
        raise AgentError("invalid_peer_id")
    token = config.get("token")
    if not isinstance(token, str) or not TOKEN_PATTERN.fullmatch(token):
        raise AgentError("invalid_token")
    service_name = config.get("service_name")
    if not isinstance(service_name, str) or not SERVICE_PATTERN.fullmatch(service_name):
        raise AgentError("invalid_service_name")
    exe_value = config.get("exe_path")
    if not isinstance(exe_value, str) or not os.path.isabs(exe_value):
        raise AgentError("invalid_executable_path")
    exe_path = validate_secure_path(exe_value, expected_uid, executable_anchor, executable=True)
    if not os.access(exe_path, os.X_OK):
        raise AgentError("insecure_executable")
    return {
        "panel": "https://" + PANEL_HOST,
        "id": peer_id,
        "token": token,
        "exe_path": str(exe_path),
        "service_name": service_name,
    }


def _execstart_path(output):
    match = re.search(r"(?:^|\{\s*)path=([^;\r\n]+)\s*;", output)
    if not match:
        raise AgentError("service_execstart_unavailable")
    return match.group(1).strip()


def validate_service_and_peer(config, runner=subprocess.run, timeout=10):
    try:
        service = runner(
            ["systemctl", "show", "--system", config["service_name"], "--property=ExecStart", "--value"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AgentError("service_query_failed") from exc
    if service.returncode != 0 or service.stderr.strip():
        raise AgentError("service_query_failed")
    if os.path.abspath(_execstart_path(service.stdout)) != os.path.abspath(config["exe_path"]):
        raise AgentError("service_executable_mismatch")
    try:
        result = runner(
            [config["exe_path"], "--get-id"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AgentError("peer_id_query_failed") from exc
    value = result.stdout.strip()
    if result.returncode != 0 or result.stderr.strip() or not ID_PATTERN.fullmatch(value) or value != config["id"]:
        raise AgentError("peer_id_mismatch")


def _validate_response_url(response, requested_url):
    final_url = response.geturl()
    if final_url != requested_url:
        raise AgentError("api_redirect_rejected")
    final = urllib.parse.urlsplit(final_url)
    if final.scheme != "https" or final.hostname != PANEL_HOST:
        raise AgentError("api_url_rejected")


def post_json(panel, route, payload, opener_factory=urllib.request.build_opener):
    url = panel.rstrip("/") + route
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != PANEL_HOST or parsed.port not in (None, 443):
        raise AgentError("api_url_rejected")
    try:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AgentError("api_request_invalid") from exc
    if len(body) > MAX_HTTP_BYTES:
        raise AgentError("api_request_too_large")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "Nextec-Connect-Agent/1", "Cache-Control": "no-store"},
        method="POST",
    )
    try:
        opener = opener_factory(NoRedirectHandler())
        with opener.open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            _validate_response_url(response, url)
            if response.status not in (200, 204):
                raise AgentError("api_http_error")
            if response.status == 204:
                return {}
            length = response.headers.get("Content-Length")
            if length and int(length) > MAX_HTTP_BYTES:
                raise AgentError("api_response_too_large")
            raw = response.read(MAX_HTTP_BYTES + 1)
    except AgentError:
        raise
    except urllib.error.HTTPError as exc:
        # Do not forward the body; it may contain sensitive request state.
        raise AgentError("api_http_" + str(exc.code)) from exc
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
        raise AgentError("api_request_failed") from exc
    if len(raw) > MAX_HTTP_BYTES:
        raise AgentError("api_response_too_large")
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentError("api_response_invalid") from exc
    if not isinstance(result, dict):
        raise AgentError("api_response_invalid")
    return result


def _operation_fields(operation):
    if not isinstance(operation, dict) or set(operation) != {"operation_id", "pending_version", "pending_password"}:
        raise AgentError("invalid_operation")
    operation_id = operation.get("operation_id")
    version = operation.get("pending_version")
    password = operation.get("pending_password")
    if not isinstance(operation_id, str) or not OPERATION_PATTERN.fullmatch(operation_id):
        raise AgentError("invalid_operation_id")
    if type(version) is not int or version < 1:
        raise AgentError("invalid_pending_version")
    if password is not None and (not isinstance(password, str) or (password and not PASSWORD_PATTERN.fullmatch(password))):
        raise AgentError("invalid_pending_password")
    return {"operation_id": operation_id, "pending_version": version, "pending_password": password or ""}


def generate_password():
    return "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(24))


def _read_journal(path, expected_uid, anchor):
    if not os.path.lexists(path):
        return None
    journal = _read_secure_json(path, expected_uid, anchor, 0o600)
    if set(journal) != {"operation_id", "pending_version"}:
        raise AgentError("invalid_journal")
    operation_id = journal.get("operation_id")
    version = journal.get("pending_version")
    if not isinstance(operation_id, str) or not OPERATION_PATTERN.fullmatch(operation_id) or type(version) is not int or version < 1:
        raise AgentError("invalid_journal")
    return journal


def _atomic_write_json(path, value, expected_uid, anchor):
    path = Path(path)
    validate_secure_path(path.parent, expected_uid, anchor)
    if os.path.lexists(path):
        validate_secure_path(path, expected_uid, anchor, file_mode=0o600)
    data = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(data) > MAX_HTTP_BYTES:
        raise AgentError("journal_too_large")
    descriptor = None
    temporary = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".agent-state-", dir=str(path.parent))
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        info = os.stat(temporary, follow_symlinks=False)
        if info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o600 or not stat.S_ISREG(info.st_mode):
            raise AgentError("journal_write_permissions")
        os.replace(temporary, path)
        temporary = None
        directory_fd = os.open(str(path.parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise AgentError("journal_write_failed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def _remove_journal(path, expected_uid, anchor):
    if not os.path.lexists(path):
        return
    validate_secure_path(path, expected_uid, anchor, file_mode=0o600)
    os.unlink(path)
    directory_fd = os.open(str(Path(path).parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _password_applied(result):
    if result.returncode != 0:
        return False
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    return bool(lines) and lines[-1] == "Done!"


def _run_checked(runner, command, timeout, error_code):
    try:
        return runner(command, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise AgentError(error_code) from exc


def apply_access_options(config, runner=subprocess.run):
    """Use RustDesk's installed-client CLI and verify each setting through its read command."""
    for key, value in (
        ("approve-mode", "password"),
        ("verification-method", "use-permanent-password"),
    ):
        applied = _run_checked(
            runner, [config["exe_path"], "--option", key, value], 15, "access_option_apply_failed",
        )
        # RustDesk 1.5.0/master emits no stdout on --option writes; disabled or
        # uninstalled CLI paths print a message but may still return exit code 0.
        if applied.returncode != 0 or applied.stderr.strip() or applied.stdout:
            raise AgentError("access_option_apply_failed")
        observed = _run_checked(
            runner, [config["exe_path"], "--option", key], 15, "access_option_query_failed",
        )
        if observed.returncode != 0 or observed.stderr.strip() or observed.stdout.splitlines() != [value]:
            raise AgentError("access_option_verification_failed")


class NextecPasswordAgent:
    def __init__(self, config_path=CONFIG_PATH, journal_path=JOURNAL_PATH, lock_path=LOCK_PATH,
                 expected_uid=0, trusted_anchor=Path("/"), runner=subprocess.run,
                 api_post=post_json, password_factory=generate_password):
        self.config_path = Path(config_path)
        self.journal_path = Path(journal_path)
        self.lock_path = Path(lock_path)
        self.expected_uid = expected_uid
        self.trusted_anchor = Path(trusted_anchor)
        self.runner = runner
        self.api_post = api_post
        self.password_factory = password_factory

    def _post(self, config, route, extra):
        payload = {"id": config["id"], "token": config["token"]}
        payload.update(extra)
        return self.api_post(config["panel"], route, payload)

    def _confirm(self, config, operation):
        result = self._post(config, "/api/nextec/agent/confirm", {
            "operation_id": operation["operation_id"],
            "pending_version": operation["pending_version"],
        })
        if (set(result) != {"ok", "active_version"} or result.get("ok") is not True
                or type(result.get("active_version")) is not int
                or result["active_version"] != operation["pending_version"]):
            raise AgentError("confirmation_failed")
        _remove_journal(self.journal_path, self.expected_uid, self.trusted_anchor)

    def cycle(self):
        validate_secure_path(self.lock_path.parent, self.expected_uid, self.trusted_anchor)
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        try:
            lock_fd = os.open(str(self.lock_path), flags, 0o600)
        except OSError as exc:
            raise AgentError("lock_open_failed") from exc
        try:
            info = os.fstat(lock_fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.expected_uid
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise AgentError("lock_permissions")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            config = load_config(self.config_path, self.expected_uid, self.trusted_anchor, self.trusted_anchor)
            validate_service_and_peer(config, runner=self.runner)
            journal = _read_journal(self.journal_path, self.expected_uid, self.trusted_anchor)
            state = self._post(config, "/api/nextec/agent/sync", {"capabilities": ["transaction_v1"]})
            # Servers without transaction_v1 return the legacy shape (or false); stop
            # explicitly before validating v1-only fields or attempting any mutation.
            if not isinstance(state, dict) or state.get("transaction_v1") is not True:
                raise AgentError("transaction_protocol_required")
            required_state = {
                "managed", "rotate", "interval_minutes", "approve_mode", "verification_method",
                "transaction_v1", "upgrade_required", "recovery",
            }
            if (not isinstance(state, dict) or not required_state.issubset(state)
                    or set(state) - required_state - {"operation"}):
                raise AgentError("invalid_sync_state")
            if type(state.get("managed")) is not bool or type(state.get("rotate")) is not bool:
                raise AgentError("invalid_policy_state")
            if (type(state.get("interval_minutes")) is not int or state["interval_minutes"] < 0
                    or (state["managed"] and state["interval_minutes"] < 1)
                    or state.get("approve_mode") != "password"
                    or state.get("verification_method") != "use-permanent-password"):
                raise AgentError("unsupported_policy")
            if type(state.get("upgrade_required")) is not bool:
                raise AgentError("invalid_upgrade_state")
            if state["upgrade_required"]:
                raise AgentError("upgrade_required")
            recovery = state["recovery"]
            if type(recovery) is not bool:
                raise AgentError("invalid_recovery_state")
            operation = _operation_fields(state["operation"]) if "operation" in state else None
            if not state["managed"] and state["rotate"]:
                raise AgentError("invalid_policy_state")
            if recovery and not operation:
                raise AgentError("recovery_operation_missing")
            if recovery and state["managed"] and not state["rotate"]:
                raise AgentError("invalid_policy_state")

            if not state["managed"]:
                if operation and journal and journal["operation_id"] == operation["operation_id"] and journal["pending_version"] == operation["pending_version"]:
                    self._confirm(config, operation)
                return
            apply_access_options(config, runner=self.runner)
            if not state["rotate"]:
                return
            if not operation:
                raise AgentError("operation_missing")
            already_applied = bool(journal and journal["operation_id"] == operation["operation_id"] and journal["pending_version"] == operation["pending_version"])
            if already_applied:
                self._confirm(config, operation)
                return

            password = operation["pending_password"]
            if not password:
                password = self.password_factory()
                if not isinstance(password, str) or not re.fullmatch(r"[A-Za-z0-9]{24}", password):
                    raise AgentError("generated_password_invalid")
                proposed = self._post(config, "/api/nextec/agent/password", {
                    "operation_id": operation["operation_id"],
                    "pending_version": operation["pending_version"],
                    "password": password,
                })
                if (set(proposed) != {"ok", "operation_id", "pending_version"}
                        or proposed.get("ok") is not True or proposed.get("operation_id") != operation["operation_id"]
                        or type(proposed.get("pending_version")) is not int
                        or proposed["pending_version"] != operation["pending_version"]):
                    raise AgentError("proposal_failed")

            result = _run_checked(
                self.runner, [config["exe_path"], "--password", password], 20, "password_apply_failed",
            )
            if not _password_applied(result):
                raise AgentError("password_apply_failed")

            # This journal is the local proof required before a confirm; it never contains the password.
            _atomic_write_json(self.journal_path, {
                "operation_id": operation["operation_id"],
                "pending_version": operation["pending_version"],
            }, self.expected_uid, self.trusted_anchor)
            self._confirm(config, operation)
        finally:
            os.close(lock_fd)


def main():
    if os.geteuid() != 0:
        print("Nextec Connect agent: root_required", file=sys.stderr)
        return 1
    try:
        NextecPasswordAgent().cycle()
        return 0
    except AgentError as exc:
        print("Nextec Connect agent: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
