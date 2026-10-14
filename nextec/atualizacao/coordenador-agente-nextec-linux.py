#!/usr/bin/python3
"""One-shot Linux bootstrap coordinator for the Nextec RustDesk agent."""
import argparse
import base64
import datetime
import hashlib
import importlib.util
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import urllib.parse
from pathlib import Path


def _configured_panel(paths):
    """Painel https gravado no build em inscricao.json (instalado pelo pacote, dono root, sem escrita de grupo/outros).

    Nunca vem da rede nem de variavel de ambiente. Vazio = painel nao configurado (o componente nao age)."""
    for path in paths:
        try:
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
                continue
            with open(path, "r", encoding="utf-8") as handle:
                raw = handle.read(4097)
            if len(raw) > 4096:
                continue
            value = json.loads(raw)
            panel = value.get("painel") if isinstance(value, dict) else None
            if not isinstance(panel, str):
                continue
            parsed = urllib.parse.urlsplit(panel)
            if (parsed.scheme != "https" or parsed.port not in (None, 443) or parsed.username or parsed.password
                    or parsed.query or parsed.fragment or parsed.path not in ("", "/")
                    or not re.fullmatch(r"[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?", parsed.hostname or "")):
                continue
            return "https://" + parsed.hostname
        except (OSError, ValueError, UnicodeError, AttributeError):
            continue
    return ""


_PANEL_SOURCES = (Path(__file__).resolve().with_name("inscricao.json"), Path("/var/lib/nextec-connect/inscricao.json"))


PANEL = _configured_panel(_PANEL_SOURCES)
PANEL_HOST = urllib.parse.urlsplit(PANEL).hostname or ""
BOOTSTRAP_PATH = Path("/var/lib/nextec-connect/bootstrap.json")
JOURNAL_PATH = Path("/var/lib/nextec-connect/provisionamento-agente.json")
CONFIG_PATH = Path("/var/lib/nextec-connect/agent-config.json")
AGENT_PATH = Path(__file__).resolve().with_name("agente-senha-linux.py")
# Inscricao global: o pacote instala inscricao.json ao lado deste script; o coordenador
# guarda uma copia 0600 no diretorio de estado e mantem o diario da inscricao propria.
INSCRICAO_SOURCE = Path(__file__).resolve().with_name("inscricao.json")
INSCRICAO_PATH = Path("/var/lib/nextec-connect/inscricao.json")
SELF_STATE_PATH = Path("/var/lib/nextec-connect/inscricao-estado.json")
MACHINE_ID_PATHS = (Path("/var/lib/dbus/machine-id"), Path("/etc/machine-id"))
ENROLL_KEY_RE = re.compile(r"^[\x21-\x7e]{16,256}$")
SELF_STATE_FIELDS = {"state", "chave_sha256", "proposed_token", "attempts", "next_try_utc", "blocked_until_utc"}
SELF_BACKOFF_BASE = 300
SELF_BACKOFF_MAX = 3600
SELF_BLOCK_SECONDS = 24 * 3600
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


MARKER_PATHS = (Path(__file__).resolve().with_name("nextec-marker.json"), Path("/usr/lib/nextec-connect/nextec-marker.json"))
APP_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SCAN_DIRS = ("/usr/bin", "/opt", "/usr/lib", "/usr/share")


def marker_names(marker_paths=None):
    """Nomes do app gravados no marcador de instalacao (app e upgrade_code), em minusculas e sem repeticao.

    O nome do app e livre; nada aqui assume um nome fixo. Marcador ausente = lista vazia."""
    names = []
    for path in (MARKER_PATHS if marker_paths is None else marker_paths):
        try:
            with open(path, "r", encoding="utf-8-sig") as handle:
                raw = handle.read(4097)
            value = json.loads(raw) if len(raw) <= 4096 else None
        except (OSError, ValueError, UnicodeError):
            continue
        if not isinstance(value, dict):
            continue
        for key in ("app", "upgrade_code"):
            item = value.get(key)
            if isinstance(item, str) and APP_NAME_RE.fullmatch(item) and item.lower() not in names:
                names.append(item.lower())
    return names


def _name_matches(candidate, names):
    stem = candidate[:-8] if candidate.endswith(".service") else candidate
    return stem.lower() in names


def _clean_peer_id(runner, executable, timeout):
    try:
        peer = runner([executable, "--get-id"], capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    value = peer.stdout.strip()
    if peer.returncode == 0 and not peer.stderr.strip() and ID_RE.fullmatch(value):
        return value
    return ""


def _scan_binaries(names, scan_dirs, limit=400):
    """(3) Varredura limitada: binario cujo nome e o do app, direto no diretorio ou em <dir>/<app>/."""
    found = []
    seen = 0
    for base in scan_dirs:
        roots = [base]
        try:
            roots += [os.path.join(base, entry) for entry in sorted(os.listdir(base)) if entry.lower() in names]
        except OSError:
            continue
        for root in roots:
            try:
                entries = sorted(os.listdir(root))
            except OSError:
                continue
            for entry in entries:
                seen += 1
                if seen > limit:
                    return found
                path = os.path.join(root, entry)
                if entry.lower() in names and os.path.isfile(path) and os.access(path, os.X_OK) and path not in found:
                    found.append(path)
    return found


def discover_local_identity(agent, runner=subprocess.run, timeout=10, marker_paths=None, scan_dirs=None):
    """Descobre o cliente instalado sem depender do nome do app.

    Ordem: (1) marcador nextec-marker.json define os nomes (app/upgrade_code); (2) servico systemd cujo nome ou
    cujo ExecStart corresponde a esses nomes; (3) varredura limitada de /usr/bin, /opt, /usr/lib e /usr/share por
    binario com esse nome que responda --get-id. Falha explicita informando o que foi procurado."""
    names = marker_names(marker_paths)
    searched = []
    try:
        units = runner(
            ["systemctl", "list-units", "--all", "--type=service", "--no-legend", "--no-pager"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CoordinatorError("service_discovery_failed") from exc
    if units.returncode != 0 or units.stderr.strip():
        raise CoordinatorError("service_discovery_failed")
    all_services = []
    for line in units.stdout.splitlines():
        fields = line.split()
        if fields and SERVICE_RE.fullmatch(fields[0]):
            all_services.append(fields[0])
    if names:
        by_name = [n for n in all_services if _name_matches(n, names)]
    else:
        by_name = [n for n in all_services if re.search(r"rustdesk|rdclient", n, re.IGNORECASE)]
    searched.append("marcador:" + (",".join(names) if names else "ausente"))
    searched.append("servicos:" + (",".join(sorted(by_name)) or "nenhum"))

    def probe(service_name, require_basename):
        try:
            service = runner(
                ["systemctl", "show", "--system", service_name, "--property=ExecStart", "--value"],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
            if service.returncode != 0 or service.stderr.strip():
                return None
            executable = agent._execstart_path(service.stdout)
            if require_basename and os.path.basename(executable).lower() not in names:
                return None
            agent.validate_secure_path(executable, 0, Path("/"), executable=True)
        except (agent.AgentError, CoordinatorError, OSError, subprocess.SubprocessError, ValueError):
            return None
        value = _clean_peer_id(runner, executable, timeout)
        return {"service_name": service_name, "exe_path": executable, "id": value} if value else None

    identities = []
    for service_name in sorted(by_name):
        found = probe(service_name, False)
        if found:
            identities.append(found)
    if not identities and names:
        # (2b) servico com outro nome, mas cujo ExecStart aponta para o binario do app.
        for service_name in sorted(set(all_services) - set(by_name))[:80]:
            found = probe(service_name, True)
            if found:
                identities.append(found)
    if not identities and names:
        # (3) varredura limitada de diretorios por binario com o nome do app que responda --get-id.
        dirs = SCAN_DIRS if scan_dirs is None else scan_dirs
        paths = _scan_binaries(names, dirs)
        searched.append("binarios:" + (",".join(paths) or "nenhum em " + ",".join(dirs)))
        for path in paths:
            try:
                agent.validate_secure_path(path, 0, Path("/"), executable=True)
            except (agent.AgentError, OSError, ValueError):
                continue
            value = _clean_peer_id(runner, path, timeout)
            if value:
                identities.append({"service_name": os.path.basename(path) + ".service", "exe_path": path, "id": value})
    if len(identities) != 1:
        if identities:
            raise CoordinatorError("service_identity_ambiguous")
        raise CoordinatorError("service_identity_unavailable (procurado: " + "; ".join(searched) + ")")
    return identities[0]


def _age_seconds(created_utc, now):
    created = datetime.datetime.fromisoformat(created_utc.replace("Z", "+00:00"))
    if created.tzinfo is None:
        raise CoordinatorError("invalid_journal")
    return (now - created.astimezone(datetime.timezone.utc)).total_seconds()


def parse_enrollment(raw):
    """Strict inscricao.json {v,painel,chave}; never echoes the key."""
    if len(raw) > MAX_BOOTSTRAP_BYTES:
        raise CoordinatorError("invalid_input")
    try:
        value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_duplicate_rejector)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CoordinatorError("invalid_input") from exc
    if not isinstance(value, dict) or set(value) != {"v", "painel", "chave"}:
        raise CoordinatorError("invalid_input")
    if isinstance(value["v"], bool) or value["v"] != 1:
        raise CoordinatorError("invalid_input")
    if not isinstance(value["painel"], str) or not isinstance(value["chave"], str):
        raise CoordinatorError("invalid_input")
    if value["painel"] != PANEL:
        raise CoordinatorError("invalid_panel")
    if not ENROLL_KEY_RE.fullmatch(value["chave"]):
        raise CoordinatorError("invalid_input")
    return {"v": 1, "painel": PANEL, "chave": value["chave"]}


def read_enrollment_source(agent, path=INSCRICAO_SOURCE, expected_uid=0, anchor=Path("/")):
    """Read the package-owned file, or None when this build has no enrollment file."""
    if not os.path.lexists(path):
        return None
    agent.validate_secure_path(path, expected_uid, anchor)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(str(path), flags)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid or info.st_mode & 0o022:
                raise CoordinatorError("unsafe_authorization_file")
            raw = stream.read(MAX_BOOTSTRAP_BYTES + 1)
    except OSError as exc:
        raise CoordinatorError("authorization_read_failed") from exc
    return parse_enrollment(raw)


def machine_uuid(paths=MACHINE_ID_PATHS):
    """Same uuid the RustDesk client reports: standard base64 of the trimmed machine-id."""
    for path in paths:
        try:
            value = Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value:
            encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
            if len(encoded) <= UUID_MAX:
                return encoded
    raise CoordinatorError("service_identity_unavailable")


def _iso(moment):
    return moment.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(value):
    if not value:
        return None
    parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise CoordinatorError("invalid_journal")
    return parsed.astimezone(datetime.timezone.utc)


def _validate_self_state(value):
    if (not isinstance(value, dict) or set(value) != SELF_STATE_FIELDS
            or value["state"] not in ("self", "manual", "blocked")
            or not isinstance(value["chave_sha256"], str)
            or not isinstance(value["proposed_token"], str)
            or (value["proposed_token"] and not TOKEN_RE.fullmatch(value["proposed_token"]))
            or not isinstance(value["attempts"], int) or isinstance(value["attempts"], bool)
            or not isinstance(value["next_try_utc"], str) or not isinstance(value["blocked_until_utc"], str)):
        raise CoordinatorError("invalid_journal")
    try:
        _parse_iso(value["next_try_utc"])
        _parse_iso(value["blocked_until_utc"])
    except ValueError as exc:
        raise CoordinatorError("invalid_journal") from exc
    return value


def post_self_enroll(agent, payload):
    return agent.post_json(PANEL, "/api/nextec/agent/self-enroll", payload)


def self_enroll_cycle(agent, identity, now, *, enrollment, secure_read, atomic_write, state_path,
                      config_path, post, token_factory, uuid_reader):
    """Self-enrollment with no bootstrap code. Raises fixed status codes, never secrets."""
    if enrollment is None:
        raise CoordinatorError("manual_authorization_required")
    now = now.astimezone(datetime.timezone.utc)
    key_hash = hashlib.sha256(enrollment["chave"].encode("utf-8")).hexdigest()
    state = _validate_self_state(secure_read(state_path)) if os.path.lexists(state_path) else None
    if state and state["chave_sha256"] != key_hash:
        state = None
    if state:
        if state["state"] == "manual":
            raise CoordinatorError("manual_authorization_required")
        blocked_until = _parse_iso(state["blocked_until_utc"])
        if state["state"] == "blocked" and blocked_until and now < blocked_until:
            raise CoordinatorError("self_blocked")
        next_try = _parse_iso(state["next_try_utc"])
        if state["state"] == "self" and state["attempts"] > 0 and next_try and now < next_try:
            raise CoordinatorError("self_backoff")
    if state is None or not state["proposed_token"]:
        proposed = token_factory()
        if not isinstance(proposed, str) or not TOKEN_RE.fullmatch(proposed):
            raise CoordinatorError("token_generation_failed")
        state = {"state": "self", "chave_sha256": key_hash, "proposed_token": proposed,
                 "attempts": 0, "next_try_utc": "", "blocked_until_utc": ""}
    else:
        state = dict(state, state="self")
    # The proposed token is durable before the request: a replay resends the same id/uuid/token.
    atomic_write(state_path, state)

    payload = {"enroll_key": enrollment["chave"], "id": identity["id"],
               "uuid": uuid_reader(), "proposed_token": state["proposed_token"]}
    try:
        response = post(payload)
    except agent.AgentError as exc:
        code = str(exc)
        match = re.fullmatch(r"api_http_([0-9]{3})", code)
        status = int(match.group(1)) if match else None
        if status in (401, 409):
            atomic_write(state_path, dict(state, state="manual"))
            raise CoordinatorError("manual_authorization_required") from exc
        if status == 403:
            until = _iso(now + datetime.timedelta(seconds=SELF_BLOCK_SECONDS))
            atomic_write(state_path, dict(state, state="blocked", blocked_until_utc=until))
            raise CoordinatorError("self_blocked") from exc
        if status is not None or code == "api_request_failed":
            attempts = min(state["attempts"] + 1, 10)
            delay = min(SELF_BACKOFF_MAX, SELF_BACKOFF_BASE * (2 ** (attempts - 1))) - 30
            atomic_write(state_path, dict(state, attempts=attempts,
                                          next_try_utc=_iso(now + datetime.timedelta(seconds=delay))))
            if status == 404:
                raise CoordinatorError("peer_not_registered") from exc
            if status == 429:
                raise CoordinatorError("rate_limited") from exc
            raise CoordinatorError("network_retry") from exc
        raise CoordinatorError("protocol_error") from exc
    if (not isinstance(response, dict) or response.get("token") != state["proposed_token"]
            or response.get("state") not in ("pending", "assigned")):
        raise CoordinatorError("protocol_error")
    if os.path.lexists(config_path):
        raise CoordinatorError("already_enrolled")
    return state


def run_cycle(*, agent=None, bootstrap_path=BOOTSTRAP_PATH, journal_path=JOURNAL_PATH,
              config_path=CONFIG_PATH, expected_uid=0, anchor=Path("/"), now=None,
              discover=discover_local_identity, post=None, token_factory=None,
              secure_read=None, atomic_write=None, secure_remove=None, authorization_read=None,
              enrollment_source=INSCRICAO_SOURCE, enrollment_path=INSCRICAO_PATH,
              self_state_path=SELF_STATE_PATH, enrollment_read=None, uuid_reader=machine_uuid,
              self_post=None):
    if not PANEL:
        raise CoordinatorError("panel_not_configured")
    agent = agent or load_agent_module()
    now = now or datetime.datetime.now(datetime.timezone.utc)
    secure_read = secure_read or (lambda path: _read_secure_json(agent, path, expected_uid, anchor))
    atomic_write = atomic_write or (lambda path, value: _atomic_json(agent, path, value, expected_uid, anchor))
    secure_remove = secure_remove or (lambda path: _remove_secure(agent, path, expected_uid, anchor))
    authorization_read = authorization_read or (lambda path: read_authorization(agent, path, expected_uid, anchor))
    post = post or (lambda payload: post_bootstrap(agent, payload))
    token_factory = token_factory or (lambda: secrets.token_urlsafe(32))
    self_post = self_post or (lambda payload: post_self_enroll(agent, payload))

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
            if os.path.lexists(self_state_path):
                # Self-enrollment finished but was interrupted before the proposed token was dropped.
                try:
                    pending = _validate_self_state(secure_read(self_state_path))
                except CoordinatorError:
                    pending = None
                if pending and pending["proposed_token"] and pending["proposed_token"] == config["token"]:
                    atomic_write(self_state_path, dict(pending, proposed_token="", attempts=0,
                                                       next_try_utc="", blocked_until_utc=""))
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
            # No bootstrap.json and no agent config: global self-enrollment from inscricao.json.
            if enrollment_read is not None:
                enrollment = enrollment_read(enrollment_source)
            else:
                enrollment = read_enrollment_source(agent, enrollment_source, expected_uid, anchor)
            if enrollment is not None:
                try:
                    stored = secure_read(enrollment_path) if os.path.lexists(enrollment_path) else None
                except CoordinatorError:
                    stored = None
                if stored != enrollment:
                    atomic_write(enrollment_path, enrollment)
            state = self_enroll_cycle(
                agent, identity, now, enrollment=enrollment, secure_read=secure_read,
                atomic_write=atomic_write, state_path=self_state_path, config_path=config_path,
                post=self_post, token_factory=token_factory, uuid_reader=uuid_reader)
            atomic_write(config_path, {
                "panel": PANEL,
                "id": identity["id"],
                "token": state["proposed_token"],
                "exe_path": identity["exe_path"],
                "service_name": identity["service_name"],
            })
            atomic_write(self_state_path, dict(state, proposed_token="", attempts=0,
                                               next_try_utc="", blocked_until_utc=""))
            return "complete"
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
