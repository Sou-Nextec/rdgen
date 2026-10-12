"""Sign one strictly scoped Nextec Connect release request using a local key."""
import argparse
import base64
import bz2
from contextlib import contextmanager
import hashlib
import io
import json
import lzma
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tarfile
import gzip
from datetime import datetime, timedelta, timezone
from pathlib import Path

from manifest import validate


PRODUCT = "nextec-connect"
APP_NAME = "Nextec-Connect"
VERSION_RE = re.compile(r"\d{1,4}\.\d{1,4}\.\d{1,4}(?:\.\d{1,4})?\Z")
MAX_SEQUENCE = 9007199254740991
MAX_ASSET_SIZE = 300 * 1024 * 1024
MSI_HEADER = bytes.fromhex("d0cf11e0a1b11ae1")
DEB_HEADER = b"!<arch>\n"
MAX_DEB_CONTROL_SIZE = 16 * 1024 * 1024
MAX_CONTROL_TAR_SIZE = 4 * 1024 * 1024


def validate_encrypted_private_key(key_path):
    """Accept only encrypted RSA PEM containers; never return or print key contents."""
    path = Path(key_path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("Chave RSA local não encontrada ou não é um arquivo regular.")
    try:
        with path.open("rb") as stream:
            header = stream.read(8192)
    except OSError as exc:
        raise ValueError("Não foi possível verificar o formato da chave RSA local.") from exc
    first_line = header.splitlines()[0].strip() if header else b""
    if first_line == b"-----BEGIN ENCRYPTED PRIVATE KEY-----":
        return
    if first_line == b"-----BEGIN RSA PRIVATE KEY-----":
        normalized = header.replace(b"\r\n", b"\n")
        pem_header = normalized.split(b"\n\n", 1)[0]
        if b"Proc-Type: 4,ENCRYPTED" in pem_header and b"DEK-Info:" in pem_header:
            return
    raise ValueError("A chave precisa ser um PEM RSA cifrado; chaves privadas em texto claro são recusadas.")


@contextmanager
def _sequence_lock(lock_path):
    """Use an OS-released advisory lock so abrupt process termination cannot leave a stale lock."""
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    stream = lock_path.open("a+b")
    locked = False
    try:
        stream.seek(0, os.SEEK_END)
        if stream.tell() == 0:
            stream.write(b"\0")
            stream.flush()
        stream.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        locked = True
        yield
    except (OSError, BlockingIOError) as exc:
        if not locked:
            raise RuntimeError("Já existe uma assinatura em andamento neste computador.") from exc
        raise
    finally:
        if locked:
            try:
                if os.name == "nt":
                    import msvcrt
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        stream.close()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Pedido contém campo duplicado.")
        result[key] = value
    return result


def parse_request(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 16384:
        raise ValueError("Pedido vazio ou acima do limite.")
    try:
        request = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Pedido JSON inválido.") from exc
    if not isinstance(request, dict) or set(request) - {"produto", "formato", "versao", "sequencia", "windows", "linux"}:
        raise ValueError("Formato de pedido não permitido.")
    if not {"produto", "formato", "versao", "sequencia"}.issubset(request):
        raise ValueError("Campos principais do pedido estão ausentes.")
    if request["produto"] != PRODUCT or type(request["formato"]) is not int or request["formato"] != 1:
        raise ValueError("Pedido não é uma release Connect compatível.")
    version = request["versao"]
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise ValueError("Versão da release inválida.")
    sequence = request["sequencia"]
    if type(sequence) is not int or not 1 <= sequence <= MAX_SEQUENCE:
        raise ValueError("Sequência da release inválida.")
    if "windows" in request:
        windows = request["windows"]
        _validate_request_asset(windows, f"files/nextec-acesso-{version}.msi", "Dados do MSI inválidos.")
    if "linux" in request:
        linux = request["linux"]
        if not isinstance(linux, dict) or not linux or set(linux) - {"amd64", "arm64"}:
            raise ValueError("Dados dos pacotes Linux inválidos.")
        for arch, asset in linux.items():
            _validate_request_asset(asset, f"files/nextec-acesso-{version}-{arch}.deb", "Dados do pacote DEB inválidos.")
    if "windows" not in request and "linux" not in request:
        raise ValueError("O pedido precisa incluir ao menos um pacote Windows ou Linux.")
    return request


def _validate_request_asset(asset, expected_file, message):
    if not isinstance(asset, dict) or set(asset) != {"arquivo", "sha256", "tamanho"}:
        raise ValueError(message)
    if asset["arquivo"] != expected_file:
        raise ValueError("Caminho do pacote não corresponde à versão/arquitetura.")
    if not isinstance(asset["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", asset["sha256"]):
        raise ValueError("Hash SHA-256 inválido.")
    size = asset["tamanho"]
    if type(size) is not int or not 8 <= size <= MAX_ASSET_SIZE:
        raise ValueError("Tamanho do pacote inválido.")


def read_msi_properties(msi_path, *, runner=subprocess.run, powershell=None):
    """Read MSI ProductName and ProductVersion through Windows Installer COM."""
    powershell = powershell or shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        raise RuntimeError("Windows PowerShell não encontrado para inspecionar o MSI.")
    script = r'''
$ErrorActionPreference = 'Stop'
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.OpenDatabase($args[0], 0)
function Read-Property([string]$Name) {
  $view = $database.OpenView("SELECT Value FROM Property WHERE Property='$Name'")
  $view.Execute()
  $record = $view.Fetch()
  if ($record) { return $record.StringData(1) }
  return ''
}
@{ ProductName = (Read-Property 'ProductName'); ProductVersion = (Read-Property 'ProductVersion') } | ConvertTo-Json -Compress
'''
    with tempfile.TemporaryDirectory(prefix="nextec-connect-sign-") as temp:
        script_path = Path(temp) / "read-msi.ps1"
        script_path.write_text(script, encoding="utf-8-sig")
        completed = runner(
            [powershell, "-NoProfile", "-NonInteractive", "-File", str(script_path), str(msi_path)],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    try:
        properties = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise RuntimeError("Não foi possível ler as propriedades do MSI.") from exc
    if not isinstance(properties, dict):
        raise RuntimeError("Propriedades do MSI inválidas.")
    return properties


def inspect_msi(msi_path, request, *, property_reader=read_msi_properties):
    path = Path(msi_path)
    if path.is_symlink() or not path.is_file() or path.suffix.lower() != ".msi":
        raise ValueError("Selecione um arquivo MSI local regular.")
    size = path.stat().st_size
    if not 8 <= size <= MAX_ASSET_SIZE:
        raise ValueError("Tamanho do MSI inválido.")
    with path.open("rb") as file:
        if file.read(len(MSI_HEADER)) != MSI_HEADER:
            raise ValueError("O arquivo selecionado não tem cabeçalho MSI válido.")
        file.seek(0)
        digest = hashlib.sha256()
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    windows = request["windows"]
    if size != windows["tamanho"] or digest.hexdigest() != windows["sha256"]:
        raise ValueError("Hash ou tamanho do MSI local não corresponde ao pedido.")
    properties = property_reader(path)
    if properties.get("ProductName") != APP_NAME:
        raise ValueError("O MSI não é o pacote Nextec-Connect esperado.")
    # WiX generated packages append a zero revision to the semantic release.
    # Accept only that exact representation, never arbitrary version prefixes.
    if properties.get("ProductVersion") not in (request["versao"], request["versao"] + ".0"):
        raise ValueError("ProductVersion do MSI não corresponde à versão pedida.")
    return {"sha256": digest.hexdigest(), "tamanho": size}


def _read_ar_members(path):
    with path.open("rb") as file:
        if file.read(8) != DEB_HEADER:
            raise ValueError("O arquivo selecionado não tem cabeçalho DEB válido.")
        members = {}
        while True:
            header = file.read(60)
            if not header:
                break
            if len(header) != 60 or header[58:60] != b"`\n":
                raise ValueError("Estrutura do arquivo DEB inválida.")
            try:
                name = header[:16].decode("ascii").strip().rstrip("/")
                size = int(header[48:58].decode("ascii").strip())
            except (UnicodeDecodeError, ValueError) as exc:
                raise ValueError("Cabeçalho de membro DEB inválido.") from exc
            if not name or size < 0 or name in members:
                raise ValueError("Membro DEB ausente, duplicado ou inválido.")
            if name == "debian-binary" or name.startswith("control.tar"):
                max_member = 32 if name == "debian-binary" else MAX_DEB_CONTROL_SIZE
                if size > max_member:
                    raise ValueError("Membro de metadados DEB excede o limite seguro.")
                payload = file.read(size)
                if len(payload) != size:
                    raise ValueError("Membro DEB truncado.")
                members[name] = payload
            else:
                file.seek(size, os.SEEK_CUR)
                if file.tell() > path.stat().st_size:
                    raise ValueError("Membro DEB truncado.")
            if size % 2:
                if file.read(1) != b"\n":
                    raise ValueError("Alinhamento de membro DEB inválido.")
        return members


def _bounded_decompress(data, compressor):
    try:
        with compressor(io.BytesIO(data)) as stream:
            output = bytearray()
            while len(output) <= MAX_CONTROL_TAR_SIZE:
                chunk = stream.read(min(65536, MAX_CONTROL_TAR_SIZE + 1 - len(output)))
                if not chunk:
                    return bytes(output)
                output.extend(chunk)
    except (OSError, EOFError, lzma.LZMAError) as exc:
        raise ValueError("Arquivo control do DEB corrompido ou inválido.") from exc
    raise ValueError("Metadados control do DEB excedem o limite seguro.")


def _read_deb_control(data):
    if len(data) > MAX_DEB_CONTROL_SIZE:
        raise ValueError("Metadados control do DEB excedem o limite seguro.")
    if data.startswith(b"\x1f\x8b"):
        tar_bytes = _bounded_decompress(data, lambda stream: gzip.GzipFile(fileobj=stream))
    elif data.startswith(b"\xfd7zXZ\x00"):
        tar_bytes = _bounded_decompress(data, lzma.LZMAFile)
    elif data.startswith(b"BZh"):
        tar_bytes = _bounded_decompress(data, bz2.BZ2File)
    elif data.startswith(bytes.fromhex("28b52ffd")):
        raise ValueError("Compressão zstd do DEB não é suportada por este assinador local.")
    else:
        raise ValueError("Compressão do control do DEB não reconhecida.")
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as archive:
            control = [item for item in archive if item.name in ("./control", "control")]
            if len(control) != 1 or not control[0].isfile() or control[0].size > 65536:
                raise ValueError("Arquivo control do DEB ausente ou inválido.")
            content = archive.extractfile(control[0]).read(65537)
            if len(content) > 65536:
                raise ValueError("Arquivo control do DEB excede o limite seguro.")
    except (tarfile.TarError, OSError) as exc:
        raise ValueError("Tar control do DEB inválido.") from exc
    fields = {}
    current = None
    try:
        for line in content.decode("utf-8").splitlines():
            if line.startswith((" ", "\t")) and current:
                fields[current] += "\n" + line[1:]
            elif ":" in line:
                current, value = line.split(":", 1)
                fields[current] = value.strip()
            elif line:
                raise ValueError("Formato do control DEB inválido.")
    except UnicodeDecodeError as exc:
        raise ValueError("Metadados control do DEB não são UTF-8 válidos.") from exc
    return fields


def inspect_deb(deb_path, request, arch):
    path = Path(deb_path)
    if path.is_symlink() or not path.is_file() or path.suffix.lower() != ".deb":
        raise ValueError(f"Selecione um arquivo DEB local regular para {arch}.")
    asset = request["linux"][arch]
    size = path.stat().st_size
    if not 8 <= size <= MAX_ASSET_SIZE or size != asset["tamanho"]:
        raise ValueError(f"Tamanho do DEB {arch} não corresponde ao pedido.")
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != asset["sha256"]:
        raise ValueError(f"Hash do DEB {arch} não corresponde ao pedido.")
    members = _read_ar_members(path)
    if "debian-binary" not in members or members["debian-binary"].strip() != b"2.0":
        raise ValueError("Versão do formato DEB não suportada.")
    controls = [value for name, value in members.items() if name.startswith("control.tar")]
    if len(controls) != 1:
        raise ValueError("O DEB precisa ter exatamente um arquivo control.")
    fields = _read_deb_control(controls[0])
    if fields.get("Package") != "nextec-connect":
        raise ValueError(f"O DEB {arch} não é o pacote nextec-connect esperado.")
    if fields.get("Version") != request["versao"]:
        raise ValueError(f"Version do DEB {arch} não corresponde à versão pedida.")
    if fields.get("Architecture") != arch:
        raise ValueError(f"Architecture do DEB não corresponde a {arch}.")
    return {"sha256": digest.hexdigest(), "tamanho": size}


def _read_sequence(state_file):
    if not state_file.exists():
        return 0
    try:
        raw = state_file.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise RuntimeError("Não foi possível ler a sequência local.") from exc
    if not re.fullmatch(r"\d+", raw):
        raise RuntimeError("O contador local de sequência está inválido.")
    sequence = int(raw)
    if sequence > MAX_SEQUENCE:
        raise RuntimeError("O contador local de sequência excede o limite.")
    return sequence


def _write_sequence(state_file, sequence):
    state_file.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix="manifest-sequence-", dir=state_file.parent)
    try:
        with os.fdopen(fd, "w", encoding="ascii", newline="\n") as file:
            file.write(f"{sequence}\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp_name, state_file)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def _build_manifest(request, asset, now):
    now = now.astimezone(timezone.utc).replace(microsecond=0)
    version = request["versao"]
    manifest = {
        "produto": PRODUCT,
        "formato": 1,
        "sequencia": request["sequencia"],
        "versao": version,
        "publicado_em": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "valido_ate": (now + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "linux": {
            arch: {
                "arquivo": f"files/nextec-acesso-{version}-{arch}.deb",
                "sha256": item["sha256"],
                "tamanho": item["tamanho"],
            }
            for arch, item in asset.get("linux", {}).items()
        },
    }
    if "windows" in asset:
        manifest["windows"] = {
            "arquivo": f"files/nextec-acesso-{version}.msi",
            "sha256": asset["windows"]["sha256"],
            "tamanho": asset["windows"]["tamanho"],
        }
    return json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_request(request_path, msi_path, key_path, *, state_dir, release_root, openssl=None,
                 deb_amd64=None, deb_arm64=None, property_reader=read_msi_properties,
                 runner=subprocess.run, now=None, passphrase_stdin=False,
                 passphrase_reader=None, temp_root=None):
    request_file = Path(request_path)
    if request_file.is_symlink() or not request_file.is_file() or request_file.stat().st_size > 16384:
        raise ValueError("Pedido local inválido ou acima do limite.")
    raw_request = request_file.read_bytes()
    request = parse_request(raw_request)
    local_debs = {arch: path for arch, path in (("amd64", deb_amd64), ("arm64", deb_arm64)) if path is not None}
    requested_linux = request.get("linux", {})
    if set(local_debs) != set(requested_linux):
        raise ValueError("Selecione exatamente os pacotes Linux pedidos, sem omitir nem acrescentar arquitetura.")
    if ("windows" in request) != (msi_path is not None):
        raise ValueError("Selecione o MSI pedido ou remova o pacote Windows do pedido.")
    asset = {"linux": {}}
    if msi_path is not None:
        asset["windows"] = inspect_msi(msi_path, request, property_reader=property_reader)
    for arch, path in local_debs.items():
        asset["linux"][arch] = inspect_deb(path, request, arch)
    key = Path(key_path)
    validate_encrypted_private_key(key)
    openssl = openssl or shutil.which("openssl.exe") or shutil.which("openssl")
    if not openssl:
        raise RuntimeError("OpenSSL não encontrado. Use o OpenSSL do Git for Windows.")

    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    state_file = state_dir / "manifest-sequence.txt"
    lock_file = state_dir / "manifest-sequence.lock"
    with _sequence_lock(lock_file):
        previous = _read_sequence(state_file)
        if request["sequencia"] <= previous:
            raise ValueError("A sequência pedida já foi usada ou é antiga neste computador.")
        release_root = Path(release_root)
        release_root.mkdir(parents=True, exist_ok=True)
        destination = release_root / f"{request['versao']}-{request['sequencia']}"
        if destination.exists():
            raise FileExistsError("A pasta desta release já existe; ela não será sobrescrita.")
        raw_manifest = _build_manifest(request, asset, now or datetime.now(timezone.utc))
        with tempfile.TemporaryDirectory(prefix="nextec-connect-sign-", dir=temp_root) as temp:
            temp_path = Path(temp)
            payload = temp_path / "manifesto-connect.json"
            signature_path = temp_path / "manifesto-connect.json.sig.bin"
            payload.write_bytes(raw_manifest)
            command = [openssl, "dgst", "-sha256", "-sign", str(key), "-out", str(signature_path), str(payload)]
            if passphrase_stdin:
                command[2:2] = ["-passin", "stdin"]
                secret = (passphrase_reader or _read_passphrase_stdin)()
                if not isinstance(secret, bytearray) or not secret or len(secret) > 4096 or b"\n" in secret or b"\r" in secret:
                    raise ValueError("Senha da chave vazia ou inválida.")
                secret_input = bytearray(secret)
                secret_input.extend(b"\n")
                try:
                    runner(command, check=True, input=secret_input)
                finally:
                    secret[:] = b"\0" * len(secret)
                    secret_input[:] = b"\0" * len(secret_input)
            else:
                # Direct use keeps OpenSSL's own secure prompt for non-session CLI calls.
                runner(command, check=True)
            signature = base64.b64encode(signature_path.read_bytes()) + b"\n"
        validate(raw_manifest, signature)

        staging = Path(tempfile.mkdtemp(prefix=".connect-release-", dir=release_root))
        try:
            (staging / "manifesto-connect.json").write_bytes(raw_manifest)
            (staging / "manifesto-connect.json.sig").write_bytes(signature)
            # Burn the sequence before exposing signed output; a disk failure can waste a number, never reuse one.
            _write_sequence(state_file, request["sequencia"])
            os.rename(staging, destination)
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        return destination


def _read_passphrase_stdin():
    raw = sys.stdin.buffer.readline(4097)
    if len(raw) > 4096 or not raw:
        raise ValueError("Senha da chave não recebida ou acima do limite.")
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if raw.endswith(b"\r"):
        raw = raw[:-1]
    return bytearray(raw)


def _default_paths(release_root=None):
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise RuntimeError("Este publicador deve ser executado no Windows no perfil do operador.")
    state_dir = Path(local_app_data) / "Nextec" / "Connect"
    if release_root is None:
        documents = os.environ.get("USERPROFILE")
        if not documents:
            raise RuntimeError("Pasta Documentos do operador não encontrada.")
        release_root = Path(documents) / "Documents" / "Nextec" / "Connect" / "Releases"
    return state_dir, release_root


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pedido", type=Path, help="JSON restrito recebido do painel.")
    parser.add_argument("--msi", type=Path, help="MSI Connect já salvo localmente, quando incluído no pedido.")
    parser.add_argument("--deb-amd64", type=Path, help="DEB amd64 já salvo localmente, quando incluído no pedido.")
    parser.add_argument("--deb-arm64", type=Path, help="DEB arm64 já salvo localmente, quando incluído no pedido.")
    parser.add_argument("--chave", required=True, type=Path, help="Chave RSA cifrada do monitoramento, mantida localmente.")
    parser.add_argument("--validar-chave", action="store_true", help="Verifica apenas se a chave é um PEM RSA cifrado; não solicita senha.")
    parser.add_argument("--saida-root", type=Path, help="Pasta local de releases; o nome final é derivado da versão e sequência.")
    parser.add_argument("--passphrase-stdin", action="store_true", help="Recebe a senha uma vez por stdin, sem argv/ambiente/arquivo.")
    args = parser.parse_args(argv)
    if args.validar_chave:
        if args.pedido or args.msi or args.deb_amd64 or args.deb_arm64 or args.passphrase_stdin:
            parser.error("--validar-chave não aceita argumentos de assinatura.")
        validate_encrypted_private_key(args.chave)
        print("Formato de chave RSA cifrada confirmado.")
        return
    if not args.pedido:
        parser.error("--pedido é obrigatório para assinar.")
    state_dir, release_root = _default_paths(args.saida_root)
    destination = sign_request(args.pedido, args.msi, args.chave, deb_amd64=args.deb_amd64,
                               deb_arm64=args.deb_arm64, state_dir=state_dir,
                               release_root=release_root, passphrase_stdin=args.passphrase_stdin)
    print(f"Manifesto Connect assinado e validado: {destination}")
    print("A chave privada e a senha permaneceram neste computador.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
