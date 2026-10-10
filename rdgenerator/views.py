import io
from pathlib import Path
from django.http import HttpResponse, JsonResponse, HttpResponseForbidden, FileResponse, Http404
from django.shortcuts import render, get_object_or_404
from django.urls import reverse
from django.core.files.base import ContentFile
import os
import secrets
import re
import requests
import base64
import hashlib
import hmac
import json
import uuid
import pyzipper
from django.conf import settings as _settings
from django.db.models import Q
from .forms import GenerateForm
from . import nextec
from . import branding
from .models import GithubRun
from PIL import Image
from urllib.parse import quote
from django.views.decorators.csrf import csrf_exempt
from .build_inputs import validate_build_inputs
from .forms import validate_generate_params

# get_png, download and save_custom_client build file paths from request values;
# only accept a UUID and a plain file name so "../" or absolute paths cannot escape png/ and exe/.
_UUID_RE = re.compile(r'^[0-9a-fA-F-]{36}$')
# o pacote cifrado com os dados do build chama-se secrets_<uuid do build>.zip (nome conhecido so por quem tem o uuid)
_ZIP_RE = re.compile(r'^secrets_[0-9a-fA-F-]{36}\.zip$')
# limite do arquivo que o GitHub devolve (exe, msi, deb...)
MAX_CLIENT_BYTES = 600 * 1024 * 1024


def build_token(uuid_val):
    # Segredo por build: vai dentro do pacote cifrado (secrets.json) e o workflow o devolve em "Authorization: Bearer".
    # Sem ele, quem nao rodou o build nao consegue gravar arquivo no servidor.
    return hmac.new(_settings.SECRET_KEY.encode(), ('rdgen-build:' + uuid_val).encode(), hashlib.sha256).hexdigest()
_NAME_RE = re.compile(r'^[\w.-]+$')

def _safe_parts(uuid_val, filename):
    if not uuid_val or not _UUID_RE.match(uuid_val):
        return False
    if filename is not None and (not _NAME_RE.match(filename) or filename.startswith('.')):
        return False
    return True


def generate_custom_client(params, full_url):
    """
    Core generation logic shared by web form and JSON API.

    Args:
        params: dict containing all configuration fields (keys match GenerateForm field names)
        full_url: the full URL of this service (protocol + host)

    Returns:
        dict with 'success' key. On success: also includes 'uuid', 'filename', 'platform', 'log_url'.
        On failure: includes 'error' and optionally 'status_code'.
    """
    problems = nextec.config_problems()
    if problems:
        return {'success': False, 'error': ' '.join(problems), 'status_code': 503}
    params, errors = validate_generate_params(params)
    if errors:
        return {'success': False, 'error': 'Invalid generation parameters.', 'status_code': 400}
    if nextec.is_configured() and not (params.get('key') or '').strip():
        return {'success': False, 'error': 'Chave publica do servidor ausente (NX_KEY ou NX_KEY_FILE).', 'status_code': 400}
    user_secret = params.get('sh_secret_field', '')
    selfhosted = (_settings.SH_SECRET == user_secret)
    platform = params.get('platform', 'windows')
    version = params.get('version', '1.5.0')
    delayFix = params.get('delayFix', True)
    xOffline = params.get('xOffline', False)
    hidecm = params.get('hidecm', False)
    removeNewVersionNotif = params.get('removeNewVersionNotif', False)
    server = params.get('serverIP', '')
    serverPort = params.get('serverPort', '')
    key = params.get('key', '')
    apiServer = params.get('apiServer', '')
    urlLink = params.get('urlLink', '')
    downloadLink = params.get('downloadLink', '')
    if not server:
        server = 'rs-ny.rustdesk.com' #default rustdesk server
    if not serverPort:
        serverPort = '21116' #default rustdesk rendezvous port
    if not key:
        key = 'OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw=' #default rustdesk key
    if not apiServer:
        apiServer = server+":21114"
    if not urlLink:
        urlLink = "https://rustdesk.com"
    if not downloadLink:
        downloadLink = "https://rustdesk.com/download"
    direction = params.get('direction', 'both')
    installation = params.get('installation', 'installationY')
    settings = params.get('settings', 'settingsY')
    appname = params.get('appname', '')
    if not appname:
        appname = "rustdesk"
    filename = params.get('exename', 'rustdesk')
    compname = params.get('compname', '')
    if not compname:
        compname = "Purslane Ltd"
    androidappid = params.get('androidappid', '')
    if not androidappid:
        androidappid = "com.carriez.flutter_hbb"
    compname = compname.replace("&","\\&")
    permPass = params.get('permanentPassword', '')
    theme = params.get('theme', 'system')
    themeDorO = params.get('themeDorO', 'default')
    passApproveMode = params.get('passApproveMode', 'password-click')
    denyLan = params.get('denyLan', False)
    enableDirectIP = params.get('enableDirectIP', False)
    autoClose = params.get('autoClose', False)
    permissionsDorO = params.get('permissionsDorO', 'default')
    permissionsType = params.get('permissionsType', 'custom')
    enableKeyboard = params.get('enableKeyboard', True)
    enableClipboard = params.get('enableClipboard', True)
    enableFileTransfer = params.get('enableFileTransfer', True)
    enableAudio = params.get('enableAudio', True)
    enableTCP = params.get('enableTCP', True)
    enableRemoteRestart = params.get('enableRemoteRestart', True)
    enableRecording = params.get('enableRecording', True)
    enableBlockingInput = params.get('enableBlockingInput', True)
    enableRemoteModi = params.get('enableRemoteModi', False)
    removeWallpaper = params.get('removeWallpaper', True)
    defaultManual = params.get('defaultManual', '')
    overrideManual = params.get('overrideManual', '')
    enablePrinter = params.get('enablePrinter', True)
    enableCamera = params.get('enableCamera', True)
    enableTerminal = params.get('enableTerminal', True)

    if all(char.isascii() for char in filename):
        filename = re.sub(r'[^\w\s-]', '_', filename).strip()
        filename = filename.replace(" ","_")
    else:
        filename = "rustdesk"
    if not all(char.isascii() for char in appname):
        appname = "rustdesk"
    myuuid = str(uuid.uuid4())

    try:
        iconfile = params.get('iconfile')
        if not iconfile:
            iconfile = params.get('iconbase64')
        if not iconfile:
            iconfile = nextec.default_image('icon')
        iconlink_url, iconlink_uuid, iconlink_file = save_png(iconfile,myuuid,full_url,"icon.png")
    except:
        print("failed to get icon, using default")
        iconlink_url = "false"
        iconlink_uuid = "false"
        iconlink_file = "false"
    try:
        logofile = params.get('logofile')
        if not logofile:
            logofile = params.get('logobase64')
        if not logofile:
            logofile = nextec.default_image('logo')
        logolink_url, logolink_uuid, logolink_file = save_png(logofile,myuuid,full_url,"logo.png")
    except:
        print("failed to get logo")
        logolink_url = "false"
        logolink_uuid = "false"
        logolink_file = "false"
    try:
        privacyfile = params.get('privacyfile')
        if not privacyfile:
            privacyfile = params.get('privacybase64')
        privacylink_url, privacylink_uuid, privacylink_file = save_png(privacyfile,myuuid,full_url,"privacy.png")
    except:
        print("failed to get logo")
        privacylink_url = "false"
        privacylink_uuid = "false"
        privacylink_file = "false"

    ###create the custom.txt json here and send in as inputs below
    decodedCustom = {}
    if direction != "both":
        decodedCustom['conn-type'] = direction
    if installation == "installationN":
        decodedCustom['disable-installation'] = 'Y'
    if settings == "settingsN":
        decodedCustom['disable-settings'] = 'Y'
    if appname.lower() != "rustdesk":
        decodedCustom['app-name'] = appname
    decodedCustom['override-settings'] = {}
    decodedCustom['default-settings'] = {}
    if permPass != "":
        decodedCustom['password'] = permPass
    if theme != "system":
        if themeDorO == "default":
            if platform == "windows-x86":
                decodedCustom['default-settings']['allow-darktheme'] = 'Y' if theme == "dark" else 'N'
            else:
                decodedCustom['default-settings']['theme'] = theme
        elif themeDorO == "override":
            if platform == "windows-x86":
                decodedCustom['override-settings']['allow-darktheme'] = 'Y' if theme == "dark" else 'N'
            else:
                decodedCustom['override-settings']['theme'] = theme
    decodedCustom['enable-lan-discovery'] = 'N' if denyLan else 'Y'
    #decodedCustom['direct-server'] = 'Y' if enableDirectIP else 'N'
    decodedCustom['allow-auto-disconnect'] = 'Y' if autoClose else 'N'

    if permissionsDorO == "default":
        decodedCustom['default-settings']['access-mode'] = permissionsType
        decodedCustom['default-settings']['enable-keyboard'] = 'Y' if enableKeyboard else 'N'
        decodedCustom['default-settings']['enable-clipboard'] = 'Y' if enableClipboard else 'N'
        decodedCustom['default-settings']['enable-file-transfer'] = 'Y' if enableFileTransfer else 'N'
        decodedCustom['default-settings']['enable-audio'] = 'Y' if enableAudio else 'N'
        decodedCustom['default-settings']['enable-tunnel'] = 'Y' if enableTCP else 'N'
        decodedCustom['default-settings']['enable-remote-restart'] = 'Y' if enableRemoteRestart else 'N'
        decodedCustom['default-settings']['enable-record-session'] = 'Y' if enableRecording else 'N'
        decodedCustom['default-settings']['enable-block-input'] = 'Y' if enableBlockingInput else 'N'
        decodedCustom['default-settings']['allow-remote-config-modification'] = 'Y' if enableRemoteModi else 'N'
        decodedCustom['default-settings']['direct-server'] = 'Y' if enableDirectIP else 'N'
        decodedCustom['default-settings']['verification-method'] = 'use-permanent-password' if hidecm else 'use-both-passwords'
        decodedCustom['default-settings']['approve-mode'] = passApproveMode
        decodedCustom['default-settings']['allow-hide-cm'] = 'Y' if hidecm else 'N'
        decodedCustom['default-settings']['allow-remove-wallpaper'] = 'Y' if removeWallpaper else 'N'
        decodedCustom['default-settings']['enable-remote-printer'] = 'Y' if enablePrinter else 'N'
        decodedCustom['default-settings']['enable-camera'] = 'Y' if enableCamera else 'N'
        decodedCustom['default-settings']['enable-terminal'] = 'Y' if enableTerminal else 'N'
        

    else:
        decodedCustom['override-settings']['access-mode'] = permissionsType
        decodedCustom['override-settings']['enable-keyboard'] = 'Y' if enableKeyboard else 'N'
        decodedCustom['override-settings']['enable-clipboard'] = 'Y' if enableClipboard else 'N'
        decodedCustom['override-settings']['enable-file-transfer'] = 'Y' if enableFileTransfer else 'N'
        decodedCustom['override-settings']['enable-audio'] = 'Y' if enableAudio else 'N'
        decodedCustom['override-settings']['enable-tunnel'] = 'Y' if enableTCP else 'N'
        decodedCustom['override-settings']['enable-remote-restart'] = 'Y' if enableRemoteRestart else 'N'
        decodedCustom['override-settings']['enable-record-session'] = 'Y' if enableRecording else 'N'
        decodedCustom['override-settings']['enable-block-input'] = 'Y' if enableBlockingInput else 'N'
        decodedCustom['override-settings']['allow-remote-config-modification'] = 'Y' if enableRemoteModi else 'N'
        decodedCustom['override-settings']['direct-server'] = 'Y' if enableDirectIP else 'N'
        decodedCustom['override-settings']['verification-method'] = 'use-permanent-password' if hidecm else 'use-both-passwords'
        decodedCustom['override-settings']['approve-mode'] = passApproveMode
        decodedCustom['override-settings']['allow-hide-cm'] = 'Y' if hidecm else 'N'
        decodedCustom['override-settings']['allow-remove-wallpaper'] = 'Y' if removeWallpaper else 'N'
        decodedCustom['override-settings']['enable-remote-printer'] = 'Y' if enablePrinter else 'N'
        decodedCustom['override-settings']['enable-camera'] = 'Y' if enableCamera else 'N'
        decodedCustom['override-settings']['enable-terminal'] = 'Y' if enableTerminal else 'N'
        if direction == 'incoming':
            decodedCustom['override-settings']['custom-rendezvous-server'] = server
            decodedCustom['override-settings']['api-server'] = apiServer

    if defaultManual:
        for line in defaultManual.splitlines():
            if '=' in line:
                k, value = line.split('=', 1)
                decodedCustom['default-settings'][k.strip()] = value.strip()

    if overrideManual:
        for line in overrideManual.splitlines():
            if '=' in line:
                k, value = line.split('=', 1)
                decodedCustom['override-settings'][k.strip()] = value.strip()
    
    decodedCustomJson = json.dumps(decodedCustom)

    string_bytes = decodedCustomJson.encode("ascii")
    base64_bytes = base64.b64encode(string_bytes)
    encodedCustom = base64_bytes.decode("ascii")

    ####from here run the github action, we need user, repo, access token.
    if platform == 'windows':
        url = 'https://api.github.com/repos/'+_settings.GHUSER+'/'+_settings.REPONAME+'/actions/workflows/generator-windows.yml/dispatches'
        if selfhosted:
            url = 'https://api.github.com/repos/'+_settings.GHUSER+'/'+_settings.REPONAME+'/actions/workflows/sh-generator-windows.yml/dispatches'
    if platform == 'windows-x86':
        url = 'https://api.github.com/repos/'+_settings.GHUSER+'/'+_settings.REPONAME+'/actions/workflows/generator-windows-x86.yml/dispatches'
    elif platform == 'linux':
        url = 'https://api.github.com/repos/'+_settings.GHUSER+'/'+_settings.REPONAME+'/actions/workflows/generator-linux.yml/dispatches'
    elif platform == 'android':
        url = 'https://api.github.com/repos/'+_settings.GHUSER+'/'+_settings.REPONAME+'/actions/workflows/generator-android.yml/dispatches'
    elif platform == 'macos':
        url = 'https://api.github.com/repos/'+_settings.GHUSER+'/'+_settings.REPONAME+'/actions/workflows/generator-macos.yml/dispatches'
    else:
        url = 'https://api.github.com/repos/'+_settings.GHUSER+'/'+_settings.REPONAME+'/actions/workflows/generator-windows.yml/dispatches'
        if selfhosted:
            url = 'https://api.github.com/repos/'+_settings.GHUSER+'/'+_settings.REPONAME+'/actions/workflows/sh-generator-windows.yml/dispatches'

    inputs_raw = {
        "server":server,
        "serverPort":serverPort,
        "key":key,
        "apiServer":apiServer,
        "custom":encodedCustom,
        "uuid":myuuid,
        "token":build_token(myuuid),
        "iconlink_url":iconlink_url,
        "iconlink_uuid":iconlink_uuid,
        "iconlink_file":iconlink_file,
        "logolink_url":logolink_url,
        "logolink_uuid":logolink_uuid,
        "logolink_file":logolink_file,
        "privacylink_url":privacylink_url,
        "privacylink_uuid":privacylink_uuid,
        "privacylink_file":privacylink_file,
        "appname":appname,
        "genurl":_settings.GENURL,
        "urlLink":urlLink,
        "downloadLink":downloadLink,
        "delayFix": 'true' if delayFix else 'false',
        "rdgen":'true',
        "xOffline": 'true' if xOffline else 'false',
        "removeNewVersionNotif": 'true' if removeNewVersionNotif else 'false',
        "compname": compname,
        "androidappid":androidappid,
        "filename":filename,
    }

    try:
        validate_build_inputs(inputs_raw)
    except ValueError as exc:
        return {'success': False, 'error': str(exc), 'status_code': 400}

    temp_json_path = f"data_{uuid.uuid4()}.json"
    zip_filename = f"secrets_{myuuid}.zip"
    zip_path = "temp_zips/%s" % (zip_filename)
    Path("temp_zips").mkdir(parents=True, exist_ok=True)

    with open(temp_json_path, "w") as f:
        json.dump(inputs_raw, f)

    with pyzipper.AESZipFile(zip_path, 'w', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(_settings.ZIP_PASSWORD.encode())
        zf.write(temp_json_path, arcname="secrets.json")

    if os.path.exists(temp_json_path):
        os.remove(temp_json_path)

    zipJson = {}
    zipJson['url'] = full_url
    zipJson['file'] = zip_filename

    zip_url = json.dumps(zipJson)

    data = {
        "ref":_settings.GHBRANCH,
        "inputs":{
            "version":version,
            "zip_url":zip_url
        },
        "return_run_details": True
    } 
    headers = {
        'Accept':  'application/vnd.github+json',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer '+_settings.GHBEARER,
        'X-GitHub-Api-Version': '2026-03-10'
    }
    new_github_run = GithubRun(
        uuid=myuuid,
        filename=filename,
        platform=platform,
        status="Starting generator...please wait"
    )
    try:
        response = requests.post(url, json=data, headers=headers, timeout=(5, 30))
        if response.status_code == 200:
            github_data = response.json()
            if not github_data.get('workflow_run_id'):
                return {'success': False, 'error': 'GitHub did not return the workflow run ID.', 'status_code': 502}
            new_github_run.github_run_id = github_data.get('workflow_run_id')
            new_github_run.status = "in_progress"
            new_github_run.save()

            return {
                "success": True,
                "uuid": myuuid,
                "filename": filename,
                "platform": platform,
                "log_url": github_data.get('html_url')
            }
        else:
            return {
                "success": False,
                "error": "GitHub rejected the start request",
                "status_code": 500
            }
    except Exception as e:
        return {
            "success": False,
            "error": f"Connection error: {str(e)}",
            "status_code": 500
        }


def _get_run_status(uuid_val, filename='', platform=''):
    """
    Core status-check logic shared by web form and JSON API.

    Args:
        uuid_val: the UUID string of the generation run

    Returns:
        dict with 'found', 'status', 'github_log_url', and optionally 'gh_run'.
        If not found, 'found' is False.
    """
    try:
        gh_run = GithubRun.objects.get(uuid=uuid_val)
    except GithubRun.DoesNotExist:
        return {"found": False}

    github_log_url = f"https://github.com/{_settings.GHUSER}/{_settings.REPONAME}/actions/runs/{gh_run.github_run_id}"

    if gh_run.status not in ['success', 'failure', 'cancelled', 'timed_out', 'skipped']:
        headers = {
            "Authorization": f"Bearer {_settings.GHBEARER}",
            "Accept": "application/vnd.github+json"
        }
        api_url = f"https://api.github.com/repos/{_settings.GHUSER}/{_settings.REPONAME}/actions/runs/{gh_run.github_run_id}"
        
        try:
            gh_response = requests.get(api_url, headers=headers, timeout=(5, 30))
            if gh_response.status_code == 200:
                gh_data = gh_response.json()
                
                if gh_data['status'] == 'completed':
                    gh_run.status = gh_data['conclusion']
                    gh_run.save()
        except Exception as e:
            print(f"Error checking GitHub: {e}")

    filename = gh_run.filename or filename
    platform = gh_run.platform or platform
    files = _received_files(uuid_val, filename) if filename else []
    missing = []
    status = gh_run.status
    if status == 'success' and filename:
        names = {item['name'] for item in files}
        if platform == 'windows':
            missing = [filename + ext for ext in ('.exe', '.msi') if filename + ext not in names]
        elif not files:
            missing = ['arquivo do instalador']
        if missing:
            status = 'incomplete'
    return {
        "found": True,
        "status": status,
        "github_log_url": github_log_url,
        "gh_run": gh_run,
        "filename": filename,
        "platform": platform,
        "files": files,
        "missing_files": missing,
    }


def _received_files(uuid_val, filename):
    from urllib.parse import urlencode
    if not _safe_parts(uuid_val or '', (filename or '') + '.exe'):
        return []
    directory = Path('exe') / uuid_val
    if not directory.is_dir():
        return []
    return [{'name': path.name, 'url': 'download?' + urlencode({'uuid': uuid_val, 'filename': path.name})}
            for path in sorted(directory.iterdir())
            if path.is_file() and path.stat().st_size > 0 and not path.is_symlink()
            and (path.name.startswith(filename + '.') or path.name.startswith(filename + '-'))
            and _safe_parts(uuid_val, path.name)]


def generator_view(request):
    problems = nextec.config_problems()
    if problems:
        # sem token/senhas o build nao funciona: diz o que falta em vez de falhar adiante
        return render(request, 'config_problem.html', {'problems': problems}, status=503)
    if request.method == 'POST':
        form = GenerateForm(request.POST, request.FILES)
        if form.is_valid():
            params = form.cleaned_data
            full_url = f"{_settings.PROTOCOL}://{request.get_host()}{request.META.get('SCRIPT_NAME', '').rstrip('/')}"
            result = generate_custom_client(params, full_url)
            if result['success']:
                return render(request, 'waiting.html', {
                    'filename': result['filename'],
                    'uuid': result['uuid'],
                    'status': "Starting generator...please wait",
                    'platform': result['platform'],
                    'log_url': result['log_url']
                })
            else:
                return JsonResponse({"error": result['error']}, status=result.get('status_code', 500))
    else:
        form = GenerateForm(initial=nextec.initial())
    #return render(request, 'maintenance.html')
    return render(request, 'generator.html', {
        'form': form,
        'product_version': nextec.product_version(),
        'branding_url': reverse('branding'),
    })


def check_for_file(request):
    filename = request.GET.get('filename')
    uuid = request.GET.get('uuid')
    platform = request.GET.get('platform')

    result = _get_run_status(uuid, filename, platform)
    if not result['found']:
        from django.http import Http404
        raise Http404("Run not found")

    gh_run = result['gh_run']
    github_log_url = result['github_log_url']

    filename = result['filename']
    platform = result['platform']
    if result['status'] == "success":
        return render(request, 'generated.html', {
            'filename': filename, 
            'uuid': uuid, 
            'platform': platform,
            'files': result['files'],
        })
        
    elif result['status'] in ['failure', 'cancelled', 'timed_out', 'skipped', 'action_required', 'incomplete']:
        return render(request, 'failure.html', {
            'log_url': github_log_url, 
            'filename': filename, 
            'uuid': uuid, 
            'platform': platform,
            'status': result['status'],
            'files': result['files'],
            'missing_files': result['missing_files'],
        })
        
    else:
        return render(request, 'waiting.html', {
            'filename': filename, 
            'uuid': uuid, 
            'status': gh_run.status, 
            'platform': platform, 
            'log_url': github_log_url
        })

def download(request):
    filename = request.GET.get('filename', '')
    uuid = request.GET.get('uuid', '')
    if not _safe_parts(uuid, filename):
        return HttpResponseForbidden("Invalid filename")
    file_path = os.path.join('exe', uuid, filename)
    try:
        return FileResponse(open(file_path, 'rb'), as_attachment=True, filename=filename,
                            content_type='application/octet-stream')
    except OSError:
        raise Http404('Client file not found')

def get_png(request):
    filename = request.GET.get('filename', '')
    uuid = request.GET.get('uuid', '')
    if not _safe_parts(uuid, filename):
        return HttpResponseForbidden("Invalid filename")
    file_path = os.path.join('png',uuid,filename)
    try:
        return FileResponse(open(file_path, 'rb'), content_type='image/png')
    except OSError:
        raise Http404('Image not found')

def create_github_run(myuuid):
    new_github_run = GithubRun(
        uuid=myuuid,
        status="Starting generator...please wait"
    )
    new_github_run.save()

@csrf_exempt
def update_github_run(request):
    data = json.loads(request.body)
    myuuid = data.get('uuid')
    mystatus = data.get('status')
    GithubRun.objects.filter(Q(uuid=myuuid)).update(status=mystatus)
    return HttpResponse('')

def resize_and_encode_icon(imagefile):
    maxWidth = 200
    try:
        with io.BytesIO() as image_buffer:
            for chunk in imagefile.chunks():
                image_buffer.write(chunk)
            image_buffer.seek(0)

            img = Image.open(image_buffer)
            imgcopy = img.copy()
    except (IOError, OSError):
        raise ValueError("Uploaded file is not a valid image format.")

    # Check if resizing is necessary
    if img.size[0] <= maxWidth:
        with io.BytesIO() as image_buffer:
            imgcopy.save(image_buffer, format=imagefile.content_type.split('/')[1])
            image_buffer.seek(0)
            return_image = ContentFile(image_buffer.read(), name=imagefile.name)
        return base64.b64encode(return_image.read())

    # Calculate resized height based on aspect ratio
    wpercent = (maxWidth / float(img.size[0]))
    hsize = int((float(img.size[1]) * float(wpercent)))

    # Resize the image while maintaining aspect ratio using LANCZOS resampling
    imgcopy = imgcopy.resize((maxWidth, hsize), Image.Resampling.LANCZOS)

    with io.BytesIO() as resized_image_buffer:
        imgcopy.save(resized_image_buffer, format=imagefile.content_type.split('/')[1])
        resized_image_buffer.seek(0)

        resized_imagefile = ContentFile(resized_image_buffer.read(), name=imagefile.name)

    # Return the Base64 encoded representation of the resized image
    resized64 = base64.b64encode(resized_imagefile.read())
    #print(resized64)
    return resized64
 
#the following is used when accessed from an external source, like the rustdesk api server
@csrf_exempt
def deprecated_generation(request):
    return JsonResponse({'error': 'Use /api/generate with Authorization: Bearer SH_SECRET.'}, status=410)


def startgh(request):
    #print(request)
    data_ = json.loads(request.body)
    ####from here run the github action, we need user, repo, access token.
    url = 'https://api.github.com/repos/'+_settings.GHUSER+'/'+_settings.REPONAME+'/actions/workflows/generator-'+data_.get('platform')+'.yml/dispatches'  
    data = {
        "ref": _settings.GHBRANCH,
        "inputs":{
            "server":data_.get('server'),
            "key":data_.get('key'),
            "apiServer":data_.get('apiServer'),
            "custom":data_.get('custom'),
            "uuid":data_.get('uuid'),
            "iconlink":data_.get('iconlink'),
            "logolink":data_.get('logolink'),
            "appname":data_.get('appname'),
            "extras":data_.get('extras'),
            "filename":data_.get('filename')
        }
    } 
    headers = {
        'Accept':  'application/vnd.github+json',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer '+_settings.GHBEARER,
        'X-GitHub-Api-Version': '2026-03-10'
    }
    response = requests.post(url, json=data, headers=headers)
    print(response)
    return HttpResponse(status=204)

def save_png(file, uuid, domain, name):
    file_save_path = "png/%s/%s" % (uuid, name)
    Path("png/%s" % uuid).mkdir(parents=True, exist_ok=True)

    if isinstance(file, str):  # Check if it's a base64 string
        try:
            header, encoded = file.split(';base64,')
            decoded_img = base64.b64decode(encoded)
            file = ContentFile(decoded_img, name=name) # Create a file-like object
        except ValueError:
            print("Invalid base64 data")
            return None  # Or handle the error as you see fit
        except Exception as e:  # Catch general exceptions during decoding
            print(f"Error decoding base64: {e}")
            return None
        
    with open(file_save_path, "wb+") as f:
        for chunk in file.chunks():
            f.write(chunk)
    # imageJson = {}
    # imageJson['url'] = domain
    # imageJson['uuid'] = uuid
    # imageJson['file'] = name
    #return "%s/%s" % (domain, file_save_path)
    return domain, uuid, name

@csrf_exempt
def save_custom_client(request):
    file = request.FILES.get('file')
    myuuid = request.POST.get('uuid')
    if file is None or not _safe_parts(myuuid, file.name):
        return HttpResponseForbidden("Invalid filename")
    sent = request.META.get('HTTP_AUTHORIZATION', '')
    if not sent.startswith('Bearer ') or not hmac.compare_digest(sent[7:].strip(), build_token(myuuid)):
        return HttpResponseForbidden("Invalid token")
    if file.size > MAX_CLIENT_BYTES:
        return HttpResponseForbidden("File too large")
    file_save_path = "exe/%s/%s" % (myuuid, file.name)
    Path("exe/%s" % myuuid).mkdir(parents=True, exist_ok=True)
    with open(file_save_path, "wb+") as f:
        for chunk in file.chunks():
            f.write(chunk)

    return HttpResponse("File saved successfully!")

@csrf_exempt
def cleanup_secrets(request):
    # Pass the UUID as a query param or in JSON body
    data = json.loads(request.body)
    my_uuid = data.get('uuid')

    # uuid inteiro e valido: antes bastava um pedaco ("-") para apagar o pacote de todos os builds em andamento
    if not my_uuid or not _UUID_RE.match(str(my_uuid)):
        return HttpResponse("Missing UUID", status=400)

    file_path = os.path.join('temp_zips', f"secrets_{my_uuid}.zip")
    try:
        os.remove(file_path)
        print(f"Successfully deleted {file_path}")
    except OSError as e:
        print(f"Error deleting file: {e}")

    return HttpResponse("Cleanup successful", status=200)

def get_zip(request):
    filename = request.GET.get('filename', '')
    if not _ZIP_RE.match(filename):
        return HttpResponseForbidden("Invalid filename")
    base_dir = os.path.abspath('temp_zips')
    file_path = os.path.abspath(os.path.join(base_dir, filename))
    if not file_path.startswith(base_dir + os.sep):
        return HttpResponseForbidden("Invalid filename")
    try:
        return FileResponse(open(file_path, 'rb'), as_attachment=True, filename=filename,
                            content_type='application/zip')
    except OSError:
        raise Http404('Build package not found')


def branding_view(request):
    """Tela protegida pelo Cloudflare Access para manter as imagens padrão do gerador."""
    if request.method == 'POST':
        kind = (request.POST.get('asset') or '').strip()
        action = (request.POST.get('action') or 'upload').strip()
        if kind not in branding.ASSETS:
            return HttpResponseForbidden('Tipo de imagem inválido.')
        try:
            if action == 'reset':
                path = branding.managed_path(kind)
                if path and path.is_file():
                    path.unlink()
                message = 'Imagem restaurada para o padrão do gerador.'
            elif action == 'upload':
                branding.save_upload(kind, request.FILES.get('image'))
                message = 'Imagem atualizada. Ela será usada nas próximas gerações.'
            else:
                return HttpResponseForbidden('Ação inválida.')
        except ValueError as exc:
            return render(request, 'branding.html', {
                'assets': _branding_rows(), 'product_version': nextec.product_version(), 'error': str(exc),
            }, status=400)
        except OSError:
            return render(request, 'branding.html', {
                'assets': _branding_rows(), 'product_version': nextec.product_version(),
                'error': 'Não foi possível salvar no armazenamento persistente do gerador.',
            }, status=500)
        return render(request, 'branding.html', {
            'assets': _branding_rows(), 'product_version': nextec.product_version(), 'message': message,
        })
    return render(request, 'branding.html', {
        'assets': _branding_rows(), 'product_version': nextec.product_version(),
    })


def _branding_rows():
    rows = branding.list_assets()
    for row in rows:
        row['url'] = reverse('get_artwork', args=(row['key'],))
        row['upload_url'] = reverse('branding')
    return rows


def get_artwork(request, asset):
    """Serve only the named, validated Nextec preview assets."""
    path = branding.get_path(asset)
    if not path or not path.is_file() or path.is_symlink():
        raise Http404('Artwork not found')
    content_type = 'image/bmp' if path.suffix.lower() == '.bmp' else 'image/png'
    return FileResponse(open(path, 'rb'), content_type=content_type)
