# Regressão do generator-linux.yml (run 40411878386, cliente Linux "Cliente-Nextec-Connect" falhou):
#  1. job drm: "convert: command not found" (imagemagick fora do contêiner ubuntu18.04);
#  2. job drm: DRM_SUPPORTED nunca era definido, então libdrmtap e a publicação do deb drm nunca rodavam;
#  3. flatpak: app-id com.Cliente-Nextec-Connect.Cliente-Nextec-Connect recusado
#     ("Only last name segment can contain -").
# Uso: python3 .github/scripts/test_generator_linux.py  (precisa de PyYAML e bash; BASH_BIN troca o bash)
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

RAIZ = Path(__file__).resolve().parents[2]
WORKFLOW = RAIZ / ".github" / "workflows" / "generator-linux.yml"
BASH = os.environ.get("BASH_BIN", "bash")

falhas = []


def checar(cond, msg):
    print(("ok    " if cond else "FALHA ") + msg)
    if not cond:
        falhas.append(msg)


def jobs():
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]


def roda_bash(script, cwd):
    r = subprocess.run([BASH, "-euo", "pipefail", "-c", script], cwd=cwd,
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"bash saiu {r.returncode}: {r.stderr.strip()}")
    return r.stdout


# flatpak common/flatpak-utils.c, flatpak_is_valid_name: >= 3 segmentos, só [A-Za-z0-9_],
# "-" apenas no último segmento, nenhum segmento vazio ou começando com dígito, até 255.
def app_id_valido(app_id):
    if not app_id or len(app_id) > 255:
        return False
    partes = app_id.split(".")
    if len(partes) < 3:
        return False
    for i, p in enumerate(partes):
        ultimo = i == len(partes) - 1
        permitido = r"[A-Za-z_\-][A-Za-z0-9_\-]*" if ultimo else r"[A-Za-z_][A-Za-z0-9_]*"
        if not re.fullmatch(permitido, p):
            return False
    return True


def teste_convert_tem_imagemagick():
    for nome, job in jobs().items():
        for passo in job.get("steps", []):
            w = passo.get("with") or {}
            if "run-on-arch-action" not in str(passo.get("uses", "")):
                continue
            if re.search(r"(^|\s)convert\s", str(w.get("run", ""))):
                checar("imagemagick" in str(w.get("install", "")),
                       f"{nome}/{passo.get('name')}: usa convert e instala imagemagick no contêiner")


def teste_drm_supported_definido():
    job = jobs()["build-rustdesk-linux-drm"]
    passos = job["steps"]
    usa = [p for p in passos if "DRM_SUPPORTED" in str(p.get("if", ""))]
    define = [p for p in passos if re.search(r"DRM_SUPPORTED=\w+.*GITHUB_ENV", str(p.get("run", "")))]
    checar(bool(usa), "job drm condiciona passos a DRM_SUPPORTED")
    checar(bool(define), "job drm define DRM_SUPPORTED no GITHUB_ENV")
    build = next(p for p in passos if p.get("name") == "Build rustdesk")
    checar(build.get("if") == "env.DRM_SUPPORTED == 'true'",
           "Build rustdesk do job drm é pulado quando a versão não tem drm")
    if not define:
        return
    script = define[0]["run"].replace("${{ env.VERSION }}", "1.5.0")
    for corpo, esperado in (("def build_libdrmtap_so():\n    pass\n", "true"), ("def main():\n    pass\n", "false")):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "build.py").write_text(corpo, encoding="utf-8")
            env_file = Path(d, "github_env")
            roda_bash(f'GITHUB_ENV="{env_file.as_posix()}"\n{script}', d)
            valor = env_file.read_text(encoding="utf-8").strip()
            checar(valor == f"DRM_SUPPORTED={esperado}", f"detecção de drm devolve {esperado} ({valor})")


MANIFESTO = """{
  "id": "com.rustdesk.RustDesk",
  "command": "rustdesk",
  "rename-desktop-file": "rustdesk.desktop",
  "rename-icon": "rustdesk",
  "modules": [{"name": "rustdesk", "sources": [
    {"type": "file", "path": "rustdesk.deb"},
    {"type": "file", "path": "com.rustdesk.RustDesk.metainfo.xml"}]}]
}
"""
METAINFO = """<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>com.rustdesk.RustDesk</id>
  <developer id="com.rustdesk">
    <name>RustDesk</name>
  </developer>
  <launchable type="desktop-id">com.rustdesk.RustDesk.desktop</launchable>
  <name>RustDesk</name>
</component>
"""


def bloco_flatpak():
    passo = next(p for p in jobs()["build-flatpak"]["steps"]
                 if str(p.get("name", "")).startswith("Build rustdesk flatpak package"))
    run = passo["with"]["run"]
    ini = run.index('BUNDLE_ID="com.rustdesk.RustDesk"')
    fim = run.index("# disable git safe.directory")
    return run[ini:fim]


def teste_flatpak_app_id():
    bloco = bloco_flatpak()
    for appname in ("Cliente-Nextec-Connect", "Nextec Connect", "9Remoto", "Suporte_Nextec", "MyRustDesk"):
        with tempfile.TemporaryDirectory() as d:
            fp = Path(d, "flatpak")
            fp.mkdir()
            (fp / "rustdesk.json").write_text(MANIFESTO, encoding="utf-8")
            (fp / "com.rustdesk.RustDesk.metainfo.xml").write_text(METAINFO, encoding="utf-8")
            (fp / "rustdesk.deb").write_bytes(b"deb")
            script = bloco.replace("${{ env.appname }}", appname) + '\necho "$BUNDLE_ID"\n'
            app_id = roda_bash(script, d).strip().splitlines()[-1]
            checar(app_id_valido(app_id), f"{appname!r}: app-id {app_id!r} válido para o flatpak")
            manifesto = (fp / "rustdesk.json").read_text(encoding="utf-8")
            checar(f'"id": "{app_id}"' in manifesto, f"{appname!r}: manifesto usa o app-id")
            meta = fp / f"{app_id}.metainfo.xml"
            checar(meta.exists() and f'"path": "{app_id}.metainfo.xml"' in manifesto,
                   f"{appname!r}: metainfo renomeado e referenciado")
            if meta.exists():
                xml = meta.read_text(encoding="utf-8")
                checar(f"<id>{app_id}</id>" in xml, f"{appname!r}: <id> do metainfo igual ao app-id")
                checar(f'<launchable type="desktop-id">{app_id}.desktop</launchable>' in xml,
                       f"{appname!r}: launchable aponta para <app-id>.desktop")
            checar((fp / f"{appname}.deb").exists(), f"{appname!r}: deb com o nome que o manifesto espera")


if __name__ == "__main__":
    teste_convert_tem_imagemagick()
    teste_drm_supported_definido()
    teste_flatpak_app_id()
    if falhas:
        print(f"\n{len(falhas)} falha(s)")
        sys.exit(1)
    print("\ntudo certo")
