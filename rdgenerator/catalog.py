"""Authenticated, shared read-only catalog of generated client builds."""
import json
import logging
import shutil
from datetime import timedelta
from pathlib import Path

from django.core.paginator import EmptyPage, PageNotAnInteger, Paginator
from django.http import Http404, JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_http_methods

from . import nextec
from .models import GithubRun
from .views import _UUID_RE, _get_run_status, _received_files

audit = logging.getLogger('rdgenerator.audit')


PAGE_SIZE_DEFAULT = 20
PAGE_SIZE_MAX = 100


FAILED = ('failure', 'cancelled', 'timed_out', 'skipped', 'action_required', 'submission_failed', 'submission_unknown')
TERMINAL = ('success',) + FAILED
STALE_AFTER = timedelta(hours=12)
EXPECTED_DIRS = ('exe', 'png')


def _is_stale(run):
    return bool(run.created_at and timezone.now() - run.created_at > STALE_AFTER)


def _is_failed(run):
    """Falha: erro de envio, conclusão com erro, instalador incompleto ou build parado há mais de 12 h."""
    if run.submission_error or run.status in FAILED:
        return True
    if run.status == 'success':
        return _item(run)['status'] == 'incomplete'
    return _is_stale(run)


_IMPORTED_MESSAGE = ('Este instalador já foi enviado para Atualizações. Excluir remove só os arquivos de '
                     'download; a versão preparada no painel não é afetada. Confirme para excluir mesmo assim.')


def _hard_block(run):
    """Bloqueio real (nem com confirmação): None ou (código, mensagem)."""
    if run.status not in TERMINAL and not run.submission_error and not _is_stale(run):
        return ('in_progress', 'A geração ainda está em andamento. Aguarde terminar ou falhar para excluir.')
    return None


def _confirmation(run):
    """Confirmação extra exigida para excluir: None ou (código, mensagem). Não impede a exclusão."""
    if run.imported_at:
        return ('imported', _IMPORTED_MESSAGE)
    return None


def _block_reason(run, force=False):
    """None quando pode excluir agora; senão (código, mensagem em português)."""
    return _hard_block(run) or (None if force else _confirmation(run))


def _inside(base, target):
    try:
        return Path(target).resolve().is_relative_to(Path(base).resolve())
    except (OSError, ValueError):
        return False


def _remove_files(uuid):
    """Apaga somente exe/<uuid>, png/<uuid> e temp_zips/secrets_<uuid>.zip. Devolve quantos itens removeu."""
    if not _UUID_RE.match(uuid or ''):
        raise ValueError('uuid inválido')
    removed = 0
    for base in EXPECTED_DIRS:
        root = Path(base)
        target = root / uuid
        if target.is_symlink():
            target.unlink()  # só o atalho; o destino não é tocado
            removed += 1
        elif target.is_dir():
            if not _inside(root, target) or target.resolve().parent != root.resolve():
                continue  # caminho fora do diretório do item: nunca apaga
            shutil.rmtree(target)
            removed += 1
    zip_path = Path('temp_zips') / f'secrets_{uuid}.zip'
    if zip_path.is_symlink():
        zip_path.unlink()
        removed += 1
    elif zip_path.is_file() and _inside('temp_zips', zip_path):
        zip_path.unlink()
        removed += 1
    return removed


def _delete_one(request, run, force):
    reason = _block_reason(run, force)
    if reason:
        audit.warning('exclusao recusada uuid=%s por=%s motivo=%s', run.uuid, nextec.access_user(request), reason[0])
        return {'uuid': run.uuid, 'code': reason[0], 'reason': reason[1]}
    uuid = run.uuid
    try:
        removed = _remove_files(uuid)
    except (OSError, ValueError) as exc:
        audit.error('exclusao falhou uuid=%s por=%s erro=%s', uuid, nextec.access_user(request), exc)
        return {'uuid': uuid, 'code': 'files', 'reason': 'Não foi possível apagar os arquivos deste item. Tente novamente.'}
    GithubRun.objects.filter(uuid=uuid).delete()
    audit.info('exclusao uuid=%s por=%s status=%s arquivos=%s forcado=%s', uuid, nextec.access_user(request),
               run.status, removed, bool(force and run.imported_at))
    return None


def _guard(request):
    denied = _require_authenticated_user(request)
    if denied:
        return denied
    # Cabeçalho próprio: um formulário de outro site não consegue enviar esta requisição.
    if request.headers.get('X-Nextec-Acao') != 'excluir':
        return JsonResponse({'error': 'Requisição não reconhecida.'}, status=400)
    return None


@csrf_exempt
@require_http_methods(['DELETE'])
def generation_delete(request, uuid):
    denied = _guard(request)
    if denied:
        return denied
    if not _UUID_RE.match(uuid):
        return JsonResponse({'error': 'Identificador inválido.'}, status=400)
    runs = list(GithubRun.objects.filter(uuid=uuid))
    if not runs:
        raise Http404('Geração não encontrada.')
    force = request.GET.get('confirmar') == '1'
    for run in runs:
        problem = _delete_one(request, run, force)
        if problem:
            return JsonResponse({'error': problem['reason'], 'code': problem['code'], 'deleted': []}, status=409)
    return JsonResponse({'deleted': [uuid], 'blocked': []})


@csrf_exempt
@require_http_methods(['POST'])
def generation_delete_many(request):
    denied = _guard(request)
    if denied:
        return denied
    try:
        payload = json.loads(request.body or b'{}')
    except (ValueError, UnicodeDecodeError):
        return JsonResponse({'error': 'JSON inválido.'}, status=400)
    if not isinstance(payload, dict):
        return JsonResponse({'error': 'Dados inválidos.'}, status=400)
    force = payload.get('confirm_imported') is True
    if payload.get('scope') == 'failed':
        runs = [run for run in GithubRun.objects.all() if _is_failed(run)]
    else:
        uuids = payload.get('uuids')
        if (not isinstance(uuids, list) or not uuids or len(uuids) > 100
                or not all(isinstance(item, str) and _UUID_RE.match(item) for item in uuids)):
            return JsonResponse({'error': 'Informe de 1 a 100 itens válidos.'}, status=400)
        runs = list(GithubRun.objects.filter(uuid__in=set(uuids)))
    deleted, blocked = [], []
    for run in runs:
        problem = _delete_one(request, run, force)
        if problem:
            blocked.append(problem)
        else:
            deleted.append(run.uuid)
    return JsonResponse({'deleted': deleted, 'blocked': blocked})


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
        'imported': bool(run.imported_at),
        # deletable: a exclusão é possível (mesmo exigindo confirmação). Só bloqueio real vira false.
        'deletable': _hard_block(run) is None,
        'delete_blocked_reason': (_hard_block(run) or (None, ''))[1],
        'delete_requires_confirmation': _hard_block(run) is None and _confirmation(run) is not None,
        'delete_confirmation': (_confirmation(run) or (None, ''))[0] if _hard_block(run) is None else None,
        'delete_confirmation_message': (_confirmation(run) or (None, ''))[1] if _hard_block(run) is None else '',
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
