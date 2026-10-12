"""Serve the fixed, public-key-only Connect release signer to authenticated admins."""
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from django.http import FileResponse, JsonResponse
from django.views.decorators.http import require_GET

from . import nextec


SIGNER_FILES = (
    "Assinar-Connect.cmd",
    "assinar-pedido-connect.py",
    "assinar-pedido-connect.ps1",
    "Connect-SigningSession.ps1",
    "manifest.py",
    "chaves-publicas.json",
    "README.md",
)
ARCHIVE_NAME = "nextec-connect-local-signing-helper.zip"


def _archive_bytes():
    source_dir = Path(__file__).resolve().parents[1] / "nextec" / "atualizacao"
    files = []
    for name in SIGNER_FILES:
        path = source_dir / name
        if path.is_symlink() or not path.is_file():
            raise OSError("Um arquivo fixo do assinador local está ausente ou inválido.")
        files.append((name, path.read_bytes()))
    output = BytesIO()
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
        for name, content in files:
            archive.writestr(name, content)
    output.seek(0)
    return output


@require_GET
def signing_helper_download(request):
    """Download for a Cloudflare Access-authenticated RDGen administrator."""
    email = nextec.access_user(request)
    if not email:
        return JsonResponse({"error": "Autenticação do Cloudflare Access necessária."}, status=403)
    try:
        response = FileResponse(_archive_bytes(), as_attachment=True, filename=ARCHIVE_NAME,
                                content_type="application/zip")
    except OSError:
        return JsonResponse({"error": "Pacote do assinador local indisponível."}, status=503)
    response["Cache-Control"] = "private, no-store"
    response["X-Content-Type-Options"] = "nosniff"
    return response
