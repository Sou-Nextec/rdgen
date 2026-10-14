"""Server-to-server export; the API secret never reaches the browser."""
import hashlib
import hmac
from pathlib import Path
from django.conf import settings
from django.http import FileResponse, JsonResponse
from django.views.decorators.http import require_GET
from .models import GithubRun
from .views import _received_files, _safe_parts

def authenticated(request):
    token = request.headers.get('Authorization', '')
    return bool(settings.SH_SECRET and settings.SH_SECRET != 'secret' and token.startswith('Bearer ')
                and hmac.compare_digest(token[7:].encode(), settings.SH_SECRET.encode()))

@require_GET
def artifact(request):
    if not authenticated(request):
        return JsonResponse({'error': 'Acesso não autorizado.'}, status=403)
    uuid = request.GET.get('uuid', '')
    run = GithubRun.objects.filter(uuid=uuid).first() if _safe_parts(uuid, 'client.msi') else None
    if not run or run.status != 'success':
        return JsonResponse({'error': 'Geração ainda não concluída.'}, status=409)
    files = _received_files(uuid, run.filename)
    expected = run.filename + '.msi'
    if run.platform != 'windows' or expected not in {item['name'] for item in files} or run.filename + '.exe' not in {item['name'] for item in files}:
        return JsonResponse({'error': 'Instaladores Windows incompletos.'}, status=409)
    path = Path('exe') / uuid / expected
    if path.is_symlink() or path.parent.is_symlink():
        return JsonResponse({'error': 'Arquivo inválido.'}, status=409)
    if request.GET.get('file') == '1':
        from django.utils import timezone
        GithubRun.objects.filter(pk=run.pk).update(imported_at=timezone.now())
        return FileResponse(path.open('rb'), as_attachment=True, filename=expected, content_type='application/octet-stream')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return JsonResponse({'uuid': run.uuid, 'filename': expected, 'package_version': run.package_version,
                         'rustdesk_version': run.rustdesk_version, 'profile': run.profile, 'client_name': run.client_name,
                         'notes': run.notes, 'sha256': digest.hexdigest(), 'size': path.stat().st_size})
