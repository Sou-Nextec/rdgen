import base64
import gzip
import hashlib
import importlib.util
import json
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import tarfile
import io
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("assinar-pedido-connect.py")
SPEC = importlib.util.spec_from_file_location("assinar_pedido_connect", MODULE_PATH)
signer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(signer)


class RequestValidationTests(unittest.TestCase):
    def setUp(self):
        self.msi = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"connect-msi-fixture"
        self.request = {
            "produto": "nextec-connect",
            "formato": 1,
            "versao": "2.0.3",
            "sequencia": 1,
            "windows": {
                "arquivo": "files/nextec-acesso-2.0.3.msi",
                "sha256": hashlib.sha256(self.msi).hexdigest(),
                "tamanho": len(self.msi),
            },
        }

    def test_accepts_only_fixed_release_shape(self):
        self.assertEqual(signer.parse_request(json.dumps(self.request).encode()), self.request)
        linux_only = dict(self.request)
        linux_only.pop("windows")
        linux_only["linux"] = {"amd64": {
            "arquivo": "files/nextec-acesso-2.0.3-amd64.deb", "sha256": "a" * 64, "tamanho": 100
        }}
        self.assertEqual(signer.parse_request(json.dumps(linux_only).encode()), linux_only)
        extra = dict(self.request, expires="2099-01-01T00:00:00Z")
        with self.assertRaisesRegex(ValueError, "não permitido"):
            signer.parse_request(json.dumps(extra).encode())

    def test_rejects_duplicate_keys_and_wrong_product(self):
        with self.assertRaisesRegex(ValueError, "duplicado"):
            signer.parse_request(b'{"produto":"nextec-connect","produto":"other"}')
        wrong = dict(self.request, produto="monitoramento")
        with self.assertRaisesRegex(ValueError, "não é uma release Connect"):
            signer.parse_request(json.dumps(wrong).encode())

    def test_rejects_wrong_asset_path_hash_size_and_sequence(self):
        for mutate in (
            lambda r: r["windows"].update(arquivo="files/other.msi"),
            lambda r: r["windows"].update(sha256="A" * 64),
            lambda r: r["windows"].update(tamanho=True),
            lambda r: r.update(sequencia=True),
        ):
            bad = json.loads(json.dumps(self.request))
            mutate(bad)
            with self.subTest(request=bad), self.assertRaises(ValueError):
                signer.parse_request(json.dumps(bad).encode())

    def test_inspects_local_hash_size_product_name_and_product_version(self):
        with tempfile.TemporaryDirectory(dir=MODULE_PATH.parent) as temp:
            path = Path(temp) / "Nextec-Connect.msi"
            path.write_bytes(self.msi)
            props = lambda _: {"ProductName": "Nextec-Connect", "ProductVersion": "2.0.3"}
            self.assertEqual(signer.inspect_msi(path, self.request, property_reader=props), {
                "sha256": self.request["windows"]["sha256"], "tamanho": len(self.msi)
            })
            with self.assertRaisesRegex(ValueError, "ProductVersion"):
                signer.inspect_msi(path, self.request, property_reader=lambda _: {
                    "ProductName": "Nextec-Connect", "ProductVersion": "2.0.4"
                })
            with self.assertRaisesRegex(ValueError, "pacote Nextec-Connect"):
                signer.inspect_msi(path, self.request, property_reader=lambda _: {
                    "ProductName": "Other-App", "ProductVersion": "2.0.3"
                })
            path.write_bytes(self.msi + b"tampered")
            with self.assertRaisesRegex(ValueError, "Hash ou tamanho"):
                signer.inspect_msi(path, self.request, property_reader=props)


class SigningFlowTests(unittest.TestCase):
    def _fixtures(self, root):
        msi = root / "Nextec-Connect.msi"
        msi_bytes = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"fixture"
        msi.write_bytes(msi_bytes)
        request = {
            "produto": "nextec-connect", "formato": 1, "versao": "2.0.3", "sequencia": 1,
            "windows": {"arquivo": "files/nextec-acesso-2.0.3.msi",
                        "sha256": hashlib.sha256(msi_bytes).hexdigest(), "tamanho": len(msi_bytes)},
        }
        request_file = root / "pedido.json"
        request_file.write_text(json.dumps(request), encoding="utf-8")
        key = root / "encrypted-key.pem"
        key.write_text("-----BEGIN ENCRYPTED PRIVATE KEY-----\nopaque-test-fixture\n-----END ENCRYPTED PRIVATE KEY-----\n", encoding="ascii")
        return msi, request_file, key

    @staticmethod
    def _deb_fixture(path, *, package="nextec-connect", version="2.0.3", architecture="amd64"):
        control = f"Package: {package}\nVersion: {version}\nArchitecture: {architecture}\nDescription: test\n".encode()
        tar_data = io.BytesIO()
        with tarfile.open(fileobj=tar_data, mode="w:") as archive:
            info = tarfile.TarInfo("./control")
            info.size = len(control)
            archive.addfile(info, io.BytesIO(control))
        control_gz = gzip.compress(tar_data.getvalue())
        members = [("debian-binary", b"2.0\n"), ("control.tar.gz", control_gz), ("data.tar.gz", b"fixture")]
        with path.open("wb") as file:
            file.write(b"!<arch>\n")
            for name, payload in members:
                name_field = (name + "/").ljust(16)
                header = (name_field + "0".ljust(12) + "0".ljust(6) + "0".ljust(6) + "100644".ljust(8) + str(len(payload)).ljust(10) + "`\n").encode("ascii")
                file.write(header)
                file.write(payload)
                if len(payload) % 2:
                    file.write(b"\n")
        return path

    def test_validates_deb_architecture_package_version_and_hash(self):
        with tempfile.TemporaryDirectory(dir=MODULE_PATH.parent) as temp:
            root = Path(temp)
            deb = self._deb_fixture(root / "nextec-connect-amd64.deb")
            request = {"versao": "2.0.3", "linux": {"amd64": {
                "arquivo": "files/nextec-acesso-2.0.3-amd64.deb",
                "sha256": hashlib.sha256(deb.read_bytes()).hexdigest(),
                "tamanho": deb.stat().st_size,
            }}}
            self.assertEqual(signer.inspect_deb(deb, request, "amd64"), {
                "sha256": request["linux"]["amd64"]["sha256"], "tamanho": request["linux"]["amd64"]["tamanho"]
            })
            bad_arch = self._deb_fixture(root / "bad-arch.deb", architecture="arm64")
            bad_request = {"versao": "2.0.3", "linux": {"amd64": dict(request["linux"]["amd64"])} }
            bad_request["linux"]["amd64"].update(sha256=hashlib.sha256(bad_arch.read_bytes()).hexdigest(), tamanho=bad_arch.stat().st_size)
            with self.assertRaisesRegex(ValueError, "Architecture"):
                signer.inspect_deb(bad_arch, bad_request, "amd64")
            bad_version = self._deb_fixture(root / "bad-version.deb", version="2.0.4")
            bad_request["linux"]["amd64"].update(sha256=hashlib.sha256(bad_version.read_bytes()).hexdigest(), tamanho=bad_version.stat().st_size)
            with self.assertRaisesRegex(ValueError, "Version"):
                signer.inspect_deb(bad_version, bad_request, "amd64")

    def test_accepts_real_dpkg_built_deb_when_dpkg_is_available(self):
        dpkg_deb = shutil.which("dpkg-deb")
        if not dpkg_deb:
            self.skipTest("dpkg-deb não está instalado")
        with tempfile.TemporaryDirectory(dir=MODULE_PATH.parent) as temp:
            root = Path(temp)
            package_root = root / "package"
            control_dir = package_root / "DEBIAN"
            control_dir.mkdir(parents=True)
            (package_root / "usr" / "share" / "nextec-connect").mkdir(parents=True)
            (package_root / "usr" / "share" / "nextec-connect" / "fixture.txt").write_text("fixture")
            (control_dir / "control").write_text(
                "Package: nextec-connect\nVersion: 2.0.3\nArchitecture: amd64\nDescription: fixture\n",
                encoding="utf-8",
            )
            deb = root / "nextec-connect.deb"
            subprocess.run([dpkg_deb, "--build", "--root-owner-group", "-Zgzip", str(package_root), str(deb)],
                           check=True, capture_output=True)
            request = {"versao": "2.0.3", "linux": {"amd64": {
                "arquivo": "files/nextec-acesso-2.0.3-amd64.deb",
                "sha256": hashlib.sha256(deb.read_bytes()).hexdigest(), "tamanho": deb.stat().st_size,
            }}}
            self.assertEqual(signer.inspect_deb(deb, request, "amd64")["tamanho"], deb.stat().st_size)

    def test_signs_linux_only_request_without_msi(self):
        with tempfile.TemporaryDirectory(dir=MODULE_PATH.parent) as temp:
            root = Path(temp)
            deb = self._deb_fixture(root / "nextec-connect-amd64.deb")
            request = {
                "produto": "nextec-connect", "formato": 1, "versao": "2.0.3", "sequencia": 17,
                "linux": {"amd64": {
                    "arquivo": "files/nextec-acesso-2.0.3-amd64.deb",
                    "sha256": hashlib.sha256(deb.read_bytes()).hexdigest(),
                    "tamanho": deb.stat().st_size,
                }},
            }
            request_file = root / "linux-only-request.json"
            request_file.write_text(json.dumps(request), encoding="utf-8")
            key = root / "encrypted-key.pem"
            key.write_text("-----BEGIN ENCRYPTED PRIVATE KEY-----\nopaque\n-----END ENCRYPTED PRIVATE KEY-----\n", encoding="ascii")
            def fake_run(args, check):
                Path(args[args.index("-out") + 1]).write_bytes(b"signature")
            with patch.object(signer, "validate", return_value=None):
                destination = signer.sign_request(
                    request_file, None, key, deb_amd64=deb, state_dir=root / "state",
                    release_root=root / "releases", openssl="openssl-fixture", runner=fake_run, temp_root=root,
                )
            manifest = json.loads((destination / "manifesto-connect.json").read_text(encoding="utf-8"))
            self.assertNotIn("windows", manifest)
            self.assertEqual(manifest["linux"]["amd64"]["arquivo"], "files/nextec-acesso-2.0.3-amd64.deb")
            self.assertEqual(manifest["sequencia"], 17)

    def test_signs_matching_request_with_fixed_expiry_and_advances_state(self):
        with tempfile.TemporaryDirectory(dir=MODULE_PATH.parent) as temp:
            root = Path(temp)
            msi, request, key = self._fixtures(root)

            def fake_run(args, check):
                signature_path = Path(args[args.index("-out") + 1])
                signature_path.write_bytes(b"test-signature")

            with patch.object(signer, "validate", return_value=None) as validate:
                destination = signer.sign_request(
                    request, msi, key,
                    state_dir=root / "state", release_root=root / "releases", openssl="openssl-fixture",
                    property_reader=lambda _: {"ProductName": "Nextec-Connect", "ProductVersion": "2.0.3"},
                    runner=fake_run,
                    now=datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc),
                    temp_root=root,
                )
            manifest = json.loads((destination / "manifesto-connect.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["produto"], "nextec-connect")
            self.assertEqual(manifest["windows"]["sha256"], json.loads(request.read_text())["windows"]["sha256"])
            self.assertEqual(manifest["valido_ate"], "2026-11-11T12:00:00Z")
            self.assertEqual((destination / "manifesto-connect.json.sig").read_text().strip(), "dGVzdC1zaWduYXR1cmU=")
            self.assertEqual((root / "state" / "manifest-sequence.txt").read_text(), "1\n")
            validate.assert_called_once()

    def test_session_passphrase_is_sent_only_over_stdin_and_zeroed(self):
        with tempfile.TemporaryDirectory(dir=MODULE_PATH.parent) as temp:
            root = Path(temp)
            msi, request, key = self._fixtures(root)
            openssl = shutil.which("openssl")
            if not openssl:
                self.skipTest("OpenSSL não está instalado")
            secret_text = ("Nextec-çã漢字-" + secrets.token_hex(32)).encode("utf-8")
            secret = bytearray(secret_text)
            key.unlink()
            subprocess.run(
                [openssl, "genpkey", "-algorithm", "RSA", "-aes-256-cbc", "-pkeyopt", "rsa_keygen_bits:2048",
                 "-pass", "stdin", "-out", str(key)],
                input=secret_text + b"\n", capture_output=True, check=True,
            )
            public_key = root / "test-public-key.pem"
            subprocess.run(
                [openssl, "pkey", "-in", str(key), "-passin", "stdin", "-pubout", "-out", str(public_key)],
                input=secret_text + b"\n", capture_output=True, check=True,
            )
            self.assertIn(b"ENCRYPTED PRIVATE KEY", key.read_bytes()[:80])
            observed = []

            def fake_run(args, check, input):
                observed.append({"args": list(args), "input": bytes(input)})
                return subprocess.run(args, check=check, input=input, capture_output=True)

            verify_count = [0]
            def verify_with_test_public_key(raw, signature):
                verify_count[0] += 1
                verification_dir = root / f"verification-{verify_count[0]}"
                verification_dir.mkdir()
                payload = verification_dir / "manifest.json"
                signature_file = verification_dir / "manifest.sig"
                payload.write_bytes(raw)
                signature_file.write_bytes(base64.b64decode(signature))
                subprocess.run(
                    [openssl, "dgst", "-sha256", "-verify", str(public_key), "-signature", str(signature_file), str(payload)],
                    capture_output=True, check=True,
                )

            with patch.object(signer, "validate", side_effect=verify_with_test_public_key):
                destination = signer.sign_request(
                    request, msi, key, state_dir=root / "state", release_root=root / "releases",
                    openssl=openssl,
                    property_reader=lambda _: {"ProductName": "Nextec-Connect", "ProductVersion": "2.0.3"},
                    runner=fake_run, passphrase_stdin=True, passphrase_reader=lambda: secret,
                    temp_root=root,
                )
            self.assertIn("-passin", observed[0]["args"])
            self.assertIn("stdin", observed[0]["args"])
            self.assertNotIn(secret_text, b" ".join(arg.encode() for arg in observed[0]["args"]))
            self.assertEqual(observed[0]["input"], secret_text + b"\n")
            self.assertEqual(secret, bytearray(len(secret)))
            self.assertNotIn(secret_text, (destination / "manifesto-connect.json").read_bytes())
            self.assertNotIn(secret_text, (destination / "manifesto-connect.json.sig").read_bytes())

            second_msi = root / "Nextec-Connect-2.0.4.msi"
            second_bytes = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"fixture-next"
            second_msi.write_bytes(second_bytes)
            second_request = root / "pedido-2.0.4.json"
            second_request.write_text(json.dumps({
                "produto": "nextec-connect", "formato": 1, "versao": "2.0.4", "sequencia": 2,
                "windows": {"arquivo": "files/nextec-acesso-2.0.4.msi",
                            "sha256": hashlib.sha256(second_bytes).hexdigest(), "tamanho": len(second_bytes)},
            }), encoding="utf-8")
            with patch.object(signer, "validate", side_effect=verify_with_test_public_key):
                second_destination = signer.sign_request(
                    second_request, second_msi, key, state_dir=root / "state", release_root=root / "releases",
                    openssl=openssl,
                    property_reader=lambda _: {"ProductName": "Nextec-Connect", "ProductVersion": "2.0.4"},
                    runner=fake_run, passphrase_stdin=True,
                    passphrase_reader=lambda: bytearray(secret_text), temp_root=root,
                )
            self.assertEqual(second_destination.name, "2.0.4-2")
            self.assertEqual(observed[1]["input"], secret_text + b"\n")
            self.assertNotIn(secret_text, b" ".join(arg.encode() for arg in observed[1]["args"]))
            self.assertEqual((root / "state" / "manifest-sequence.txt").read_text(), "2\n")
            for file in root.rglob("*"):
                if file.is_file():
                    self.assertNotIn(secret_text, file.read_bytes(), f"senha gravada em {file.name}")

    def test_rejects_replay_and_does_not_rewrite_previous_output(self):
        with tempfile.TemporaryDirectory(dir=MODULE_PATH.parent) as temp:
            root = Path(temp)
            msi, request, key = self._fixtures(root)
            state = root / "state"
            state.mkdir()
            (state / "manifest-sequence.txt").write_text("1\n", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "já foi usada ou é antiga"):
                signer.sign_request(
                    request, msi, key, state_dir=state, release_root=root / "releases",
                    openssl="openssl-fixture",
                    property_reader=lambda _: {"ProductName": "Nextec-Connect", "ProductVersion": "2.0.3"},
                    runner=lambda *_args, **_kwargs: self.fail("replay must be rejected before signing"),
                )
            self.assertEqual((state / "manifest-sequence.txt").read_text(), "1\n")

    def test_accepts_server_reserved_sequence_above_one_without_local_counter(self):
        with tempfile.TemporaryDirectory(dir=MODULE_PATH.parent) as temp:
            root = Path(temp)
            msi, request, key = self._fixtures(root)
            data = json.loads(request.read_text())
            data["sequencia"] = 4
            data["windows"]["arquivo"] = "files/nextec-acesso-2.0.3.msi"
            request.write_text(json.dumps(data), encoding="utf-8")
            def fake_run(args, check):
                Path(args[args.index("-out") + 1]).write_bytes(b"signature")
            with patch.object(signer, "validate", return_value=None):
                destination = signer.sign_request(
                    request, msi, key, state_dir=root / "state", release_root=root / "releases",
                    property_reader=lambda _: {"ProductName": "Nextec-Connect", "ProductVersion": "2.0.3"},
                    runner=fake_run, temp_root=root,
                )
            self.assertEqual(destination.name, "2.0.3-4")
            self.assertEqual((root / "state" / "manifest-sequence.txt").read_text(), "4\n")

    def test_rejects_plaintext_private_key_before_reading_passphrase(self):
        openssl = shutil.which("openssl") or shutil.which("openssl.exe")
        if not openssl:
            self.skipTest("OpenSSL não está instalado")
        with tempfile.TemporaryDirectory(dir=MODULE_PATH.parent) as temp:
            root = Path(temp)
            msi, request, key = self._fixtures(root)
            subprocess.run(
                [openssl, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key)],
                check=True, capture_output=True,
            )
            with self.assertRaisesRegex(ValueError, "PEM RSA cifrado"):
                signer.sign_request(
                    request, msi, key, state_dir=root / "state", release_root=root / "releases",
                    openssl=openssl, property_reader=lambda _: {"ProductName": "Nextec-Connect", "ProductVersion": "2.0.3"},
                    passphrase_stdin=True, passphrase_reader=lambda: self.fail("plain key must be rejected before password read"),
                    runner=lambda *_args, **_kwargs: self.fail("plain key must be rejected before signing"),
                )

    def test_process_kill_releases_sequence_lock_for_next_signer(self):
        with tempfile.TemporaryDirectory(dir=MODULE_PATH.parent) as temp:
            root = Path(temp)
            msi, request, key = self._fixtures(root)
            state = root / "state"
            state.mkdir()
            lock_path = state / "manifest-sequence.lock"
            ready = root / "lock-held"
            child_code = (
                "import importlib.util,sys,time; from pathlib import Path; "
                f"sys.path.insert(0, {str(MODULE_PATH.parent)!r}); "
                f"spec=importlib.util.spec_from_file_location('signer', {str(MODULE_PATH)!r}); "
                "module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); "
                f"lock=Path({str(lock_path)!r}); ready=Path({str(ready)!r}); "
                "ctx=module._sequence_lock(lock); ctx.__enter__(); ready.write_text('ready'); time.sleep(60)"
            )
            process = subprocess.Popen([sys.executable, "-c", child_code], stdout=subprocess.DEVNULL,
                                       stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 10
                while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(ready.exists(), process.stderr.read().decode("utf-8", "replace") if process.poll() is not None else "child did not acquire lock")
                with self.assertRaisesRegex(RuntimeError, "assinatura em andamento"):
                    signer.sign_request(
                        request, msi, key, state_dir=state, release_root=root / "releases",
                        openssl="openssl-fixture",
                        property_reader=lambda _: {"ProductName": "Nextec-Connect", "ProductVersion": "2.0.3"},
                        runner=lambda *_args, **_kwargs: self.fail("contended lock must stop before signing"),
                    )
            finally:
                process.kill()
                process.wait(timeout=10)
                process.stderr.close()
            def fake_run(args, check):
                Path(args[args.index("-out") + 1]).write_bytes(b"test-signature")
            with patch.object(signer, "validate", return_value=None):
                destination = signer.sign_request(
                    request, msi, key, state_dir=state, release_root=root / "releases",
                    openssl="openssl-fixture",
                    property_reader=lambda _: {"ProductName": "Nextec-Connect", "ProductVersion": "2.0.3"},
                    runner=fake_run, temp_root=root,
                )
            self.assertEqual(destination.name, "2.0.3-1")
            self.assertTrue(lock_path.exists(), "OS lock file remains reusable after owner process exits")


if __name__ == "__main__":
    unittest.main()
