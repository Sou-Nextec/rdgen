#!/usr/bin/python3
"""Atualizador Nextec Connect para pacotes Debian/Ubuntu."""
import base64
import fcntl
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
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
BASE_URL = PANEL + "/api/nextec/update"
PACKAGE = "__PACKAGE_NAME__"
STATE = Path("/var/lib/nextec-connect/update-state.json")
LOCK = Path("/run/lock/nextec-connect-update.lock")
CACHE = Path("/var/cache/nextec-connect")
MAX_PACKAGE = 300 * 1024 * 1024
MAX_MANIFEST = 65536
RSA_N = int("d87a26b54c0a3ca1d1780b5d72b9f81b7bcfcaa37c2b6ac57619e95aed2d6441da58de1133acb8cf7ada60a9d2e5506662b78aac1e8b77e5d170cb4066ae799cddb20dbbfe14919e92a350cbc01b2045d52058bd4975a880d65b8cb9aff4932e7ce1aedb64fe049f2c889105c6086f023d9a30788d523d1b551936a413db547bd53e391ef1a81fa80664f17516addf8ae23ab609b9f4e802baebf8777f6138ec4ff61c951dbbaabaa15fb85469642ff531b49c1a588b6b4870da9f6034c0aeb005a9fe8fa67d9efa7cad26e0057c272c4d6a7cebefc3f5c58bbd8d8c6553ab113c882ebe8d5b68b2a35c4b224b8dc7aa7a920b1b34a332d4763c5e51c4918b19d4894793b8be26ad4ae4d84afee77196692d6a26b44ccb6001e133d43755c5bf2b46e51b3f0b39c5ba4ce4eafbf4967d01b3776bdb8c5b4bc113a3c4ce0d5b12108b2c63225085eed92254b377c53baca735574b50af0a1a1a1cdd3f825b6e74d0a3461d7d4f45c4bb5b29b79631536d2af39ce02bc20b24e72054de5b38678389db8fee83fd48a3e0c6d7bd4caf33f6756c5a7a57293ef1694d8589e0a396b12881438b7933fbf41a7724ad96ebacc65fbd43f80bbe9c9d56a4637552e9cd5b73b7e8cf9be0db09701b5c26d1427dd92b508496e3fddd27013f080d015e712f7139cfd22ec3adcfc0776693a0649e3b1d4de08cd47340502c19b8d77460738b", 16)
RSA_E = 65537
DI_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")


def signed_manifest(envelope):
    raw = base64.b64decode(envelope["manifesto"], validate=True)
    sig = base64.b64decode(envelope["assinatura"], validate=True)
    size = (RSA_N.bit_length() + 7) // 8
    if not 0 < len(raw) <= MAX_MANIFEST or len(sig) != size or int.from_bytes(sig, "big") >= RSA_N:
        raise ValueError("Manifesto ou assinatura inválidos.")
    block = pow(int.from_bytes(sig, "big"), RSA_E, RSA_N).to_bytes(size, "big")
    tail = DI_SHA256 + hashlib.sha256(raw).digest()
    expected = b"\x00\x01" + b"\xff" * (size - len(tail) - 3) + b"\x00" + tail
    if block != expected:
        raise ValueError("Assinatura Nextec não confere.")
    manifest = json.loads(raw.decode("utf-8"))
    if manifest.get("produto") != "nextec-connect" or type(manifest.get("formato")) is not int or manifest["formato"] != 1:
        raise ValueError("Manifesto de outro produto ou formato.")
    if not re.fullmatch(r"\d{1,4}\.\d{1,4}\.\d{1,4}(\.\d{1,4})?", str(manifest.get("versao", ""))):
        raise ValueError("Versão de release inválida.")
    issued = datetime.strptime(manifest["publicado_em"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    expires = datetime.strptime(manifest["valido_ate"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if issued.timestamp() > now.timestamp() + 300 or expires <= now or expires <= issued or (expires - issued).days > 30:
        raise ValueError("Manifesto vencido ou com validade inválida.")
    seq = manifest.get("sequencia")
    if type(seq) is not int or seq < 1 or seq > 9007199254740991:
        raise ValueError("Sequência inválida.")
    return raw, manifest


def arch_name():
    value = subprocess.check_output(["dpkg", "--print-architecture"], text=True, timeout=10).strip()
    if value not in ("amd64", "arm64"):
        raise ValueError("Arquitetura Linux não suportada para atualização.")
    return value


def request_bytes(url, limit):
    if not PANEL or not url.startswith(PANEL + "/"):
        raise ValueError("Servidor de atualização inválido.")
    req = urllib.request.Request(url, headers={"Cache-Control": "no-store", "User-Agent": "Nextec-Connect-Updater/1"})
    with urllib.request.urlopen(req, timeout=30) as response:
        final = urllib.parse.urlsplit(response.geturl())
        if response.status != 200 or final.scheme != "https" or final.hostname != PANEL_HOST or int(response.headers.get("Content-Length", "0") or 0) > limit:
            raise ValueError("Resposta ou tamanho inválido do servidor.")
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Download excedeu o limite permitido.")
    return data


def get_peer_id():
    # O ID é apenas usado pelo painel para aplicar o grupo piloto; não é credencial.
    for path in ("/usr/bin/Nextec-Connect", "/usr/bin/nextec-connect", "/usr/bin/rustdesk", "/usr/lib/Nextec-Connect/rustdesk", "/usr/lib/nextec-connect/rustdesk"):
        if os.path.isfile(path) and os.access(path, os.X_OK):
            try:
                result = subprocess.run([path, "--get-id"], text=True, capture_output=True, timeout=10, check=False)
                match = re.search(r"\b\d{6,}\b", result.stdout + "\n" + result.stderr)
                if match:
                    return match.group(0)
            except (OSError, subprocess.SubprocessError):
                pass
    return ""


def update():
    if os.geteuid() != 0:
        raise PermissionError("O atualizador precisa rodar como root.")
    if not PANEL:
        print("Painel não configurado neste pacote (inscricao.json ausente ou inválido); nada a atualizar.")
        return
    LOCK.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with LOCK.open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("Já existe uma atualização em andamento.")
            return
        arch = arch_name()
        state = json.loads(STATE.read_text()) if STATE.exists() else {"sequencia": 0, "hash": "", "versao": "0.0.0"}
        query = urllib.parse.urlencode({"id": get_peer_id(), "v": state.get("versao", "0.0.0"), "platform": "linux", "arch": arch})
        envelope = json.loads(request_bytes(f"{BASE_URL}/versao.json?{query}", MAX_MANIFEST * 2).decode("utf-8"))
        item = envelope.get("linux")
        if not item:
            print("Nenhuma atualização Linux publicada para esta máquina.")
            return
        raw, manifest = signed_manifest({"manifesto": item["manifesto"], "assinatura": item["assinatura"]})
        asset = manifest.get("linux", {}).get(arch)
        if not isinstance(asset, dict) or asset.get("arquivo") != item.get("arquivo") or asset.get("sha256") != item.get("sha256"):
            raise ValueError("Arquivo Linux não corresponde ao manifesto assinado.")
        if manifest["sequencia"] < int(state.get("sequencia", 0)) or (manifest["sequencia"] == state.get("sequencia") and hashlib.sha256(raw).hexdigest() != state.get("hash")):
            raise ValueError("Manifesto antigo ou divergente.")
        if manifest["versao"] == state.get("versao"):
            print("Já está na versão publicada.")
            return
        name = asset["arquivo"].split("/")[-1]
        if not re.fullmatch(r"nextec-acesso-[0-9.]+-" + re.escape(arch) + r"\.deb", name):
            raise ValueError("Nome do pacote Linux inválido.")
        expected_hash, expected_size = asset.get("sha256", ""), asset.get("tamanho", 0)
        if not re.fullmatch(r"[a-f0-9]{64}", expected_hash) or type(expected_size) is not int or not 8 <= expected_size <= MAX_PACKAGE:
            raise ValueError("Hash ou tamanho do pacote inválido.")
        url = BASE_URL + "/" + asset["arquivo"]
        CACHE.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=CACHE, prefix=".connect-", delete=False) as temp:
            tmp = Path(temp.name)
            digest = hashlib.sha256()
            total = 0
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Nextec-Connect-Updater/1"})
                with urllib.request.urlopen(req, timeout=30) as response:
                    final = urllib.parse.urlsplit(response.geturl())
                    if response.status != 200 or final.scheme != "https" or final.hostname != PANEL_HOST:
                        raise ValueError("Download do pacote falhou.")
                    while True:
                        block = response.read(1024 * 1024)
                        if not block:
                            break
                        total += len(block)
                        if total > MAX_PACKAGE:
                            raise ValueError("Pacote excedeu o limite permitido.")
                        digest.update(block)
                        temp.write(block)
                if total != expected_size or digest.hexdigest() != expected_hash:
                    raise ValueError("Tamanho ou SHA-256 do pacote não confere.")
                info = subprocess.check_output(["dpkg-deb", "--field", str(tmp)], text=True, timeout=30)
                fields = dict(line.split(": ", 1) for line in info.splitlines() if ": " in line)
                if fields.get("Package") != PACKAGE or fields.get("Architecture") != arch:
                    raise ValueError("Pacote não corresponde ao produto ou arquitetura.")
                result = subprocess.run(["dpkg", "-i", str(tmp)], timeout=900, check=False)
                if result.returncode != 0:
                    raise RuntimeError(f"dpkg terminou com código {result.returncode}.")
                STATE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                tmp_state = STATE.with_suffix(".tmp")
                tmp_state.write_text(json.dumps({"versao": manifest["versao"], "sequencia": manifest["sequencia"], "hash": hashlib.sha256(raw).hexdigest()}))
                os.chmod(tmp_state, 0o600)
                os.replace(tmp_state, STATE)
                print(f"Atualizado para {manifest['versao']}.")
            finally:
                try:
                    tmp.unlink()
                except FileNotFoundError:
                    pass


if __name__ == "__main__":
    try:
        update()
    except Exception as exc:
        print(f"Nextec Connect updater: {exc}", file=sys.stderr)
        sys.exit(1)

