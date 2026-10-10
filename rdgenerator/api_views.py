import hmac
import json
from django.http import JsonResponse
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from . import nextec
from .forms import validate_generate_params
from .views import generate_custom_client, _get_run_status


@csrf_exempt
def api_generate(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Use POST.'}, status=405)
    problems = nextec.config_problems()
    if problems:
        return JsonResponse({'success': False, 'error': 'Gerador não configurado.', 'details': problems}, status=503)
    sent = request.headers.get('Authorization', '')
    if not sent.startswith('Bearer ') or not hmac.compare_digest(sent[7:].encode(), settings.SH_SECRET.encode()):
        return JsonResponse({'error': 'Invalid API token.'}, status=403)
    try:
        data = json.loads(request.body)
    except (ValueError, UnicodeDecodeError):
        return JsonResponse({'error': 'Invalid JSON.'}, status=400)
    cleaned, errors = validate_generate_params(data)
    if errors:
        return JsonResponse({'success': False, 'error': 'Validation errors', 'details': errors}, status=400)
    full_url = f"{settings.PROTOCOL}://{request.get_host()}{request.META.get('SCRIPT_NAME', '').rstrip('/')}"
    result = generate_custom_client(cleaned, full_url)
    if result['success']:
        result['status_url'] = f"/api/status?uuid={result['uuid']}&platform={result['platform']}&filename={result['filename']}"
    return JsonResponse(result, status=200 if result['success'] else result.get('status_code', 500))


def api_status(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Use GET.'}, status=405)
    uuid_val = request.GET.get('uuid')
    if not uuid_val:
        return JsonResponse({'error': 'Missing uuid.'}, status=400)
    result = _get_run_status(uuid_val, request.GET.get('filename', ''), request.GET.get('platform', ''))
    if not result['found']:
        return JsonResponse({'error': 'Run not found'}, status=404)
    response_data = {'status': result['status'], 'uuid': uuid_val, 'log_url': result['github_log_url']}
    response_data['files'] = result['files']
    response_data['missing_files'] = result['missing_files']
    for field in ('filename', 'platform'):
        if result.get(field):
            response_data[field] = result[field]
    return JsonResponse(response_data)
