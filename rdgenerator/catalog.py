"""Authenticated, shared read-only catalog of generated client builds."""
from django.core.paginator import EmptyPage, PageNotAnInteger, Paginator
from django.http import Http404, JsonResponse
from django.views.decorators.http import require_GET

from . import nextec
from .models import GithubRun
from .views import _get_run_status, _received_files


PAGE_SIZE_DEFAULT = 20
PAGE_SIZE_MAX = 100


def _item(run, refresh=False):
    status = run.status
    progress = None
    files = _received_files(run.uuid, run.filename) if run.filename else []
    missing_files = []
    if status == 'success':
        names = {item['name'] for item in files}
        if run.platform == 'windows':
            missing_files = [run.filename + ext for ext in ('.exe', '.msi') if run.filename + ext not in names]
        elif not files:
            missing_files = ['arquivo do instalador']
        if missing_files:
            status = 'incomplete'
    log_url = ''

    if refresh and run.github_run_id:
        current = _get_run_status(run.uuid, include_progress=True)
        if current.get('found'):
            status = current['status']
            progress = current.get('progress')
            files = current.get('files', [])
            missing_files = current.get('missing_files', [])
            log_url = current.get('github_log_url', '')
    elif run.github_run_id:
        from django.conf import settings
        log_url = f"https://github.com/{settings.GHUSER}/{settings.REPONAME}/actions/runs/{run.github_run_id}"

    return {
        'uuid': run.uuid,
        'client_name': run.client_name,
        'profile': run.profile,
        'filename': run.filename,
        'platform': run.platform,
        'rustdesk_version': run.rustdesk_version,
        'package_version': run.package_version,
        'generator_version': run.generator_version,
        'notes': run.notes,
        'created_by': run.created_by,
        'created_at': run.created_at.isoformat() if run.created_at else None,
        'status': status,
        'progress': progress,
        'files': files,
        'missing_files': missing_files,
        'log_url': log_url,
        'submission_error': run.submission_error,
    }


def _require_authenticated_user(request):
    """The regular middleware enforces the allowlist; also require a real Access identity here."""
    if not nextec.access_user(request):
        return JsonResponse({'error': 'Autenticação do Cloudflare Access necessária.'}, status=403)
    return None


@require_GET
def generation_catalog(request):
    denied = _require_authenticated_user(request)
    if denied:
        return denied

    try:
        page_size = int(request.GET.get('page_size', PAGE_SIZE_DEFAULT))
    except (TypeError, ValueError):
        return JsonResponse({'error': 'page_size deve ser um número.'}, status=400)
    if not 1 <= page_size <= PAGE_SIZE_MAX:
        return JsonResponse({'error': f'page_size deve estar entre 1 e {PAGE_SIZE_MAX}.'}, status=400)

    runs = GithubRun.objects.all().order_by('-created_at', '-id')
    paginator = Paginator(runs, page_size)
    try:
        page = paginator.page(request.GET.get('page', 1))
    except (PageNotAnInteger, EmptyPage):
        return JsonResponse({'error': 'Página inválida.'}, status=400)

    return JsonResponse({
        'count': paginator.count,
        'page': page.number,
        'page_size': page_size,
        'results': [_item(run) for run in page.object_list],
    })


@require_GET
def generation_detail(request, uuid):
    denied = _require_authenticated_user(request)
    if denied:
        return denied
    run = GithubRun.objects.filter(uuid=uuid).order_by('-id').first()
    if run is None:
        raise Http404('Geração não encontrada.')
    return JsonResponse(_item(run, refresh=True))
