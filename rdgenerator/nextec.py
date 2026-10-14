"""Padroes Nextec do gerador de clientes.

Tudo vem de variaveis de ambiente (NX_*), entao o codigo do gerador continua igual ao oficial e a configuracao fica
na stack. Sem NX_SERVER_HOST nada muda: o gerador se comporta como o original.

  NX_SERVER_HOST    host do servidor de ID (ex.: remoto.nex.tec.br)
  NX_SERVER_PORT    porta do servidor de ID (vazio = 21116)
  NX_API_SERVER     URL do painel/API (ex.: https://painel-remoto.nex.tec.br)
  NX_KEY / NX_KEY_FILE   chave publica do servidor (texto, ou arquivo id_ed25519.pub montado so leitura)
  NX_URL_LINK, NX_DOWNLOAD_LINK, NX_COMPANY, NX_APP_NAME
  NX_LOCK_SERVER    1 (padrao) trava host, porta, API, chave, links e empresa: nem o formulario nem a API mudam
  NX_ICON_FILE, NX_LOGO_FILE   imagens padrao (PNG) usadas quando nenhuma for enviada
  NX_ENROLL_KEY     chave de inscricao global (nx1.<epoca>.<hmac>): override opcional, usado so quando a busca no painel falha
  NX_PANEL_INTERNAL_URL   painel na rede interna da stack (padrao http://rustdesk:21114); vazio desliga a busca automatica

A chave de inscricao e buscada no painel a cada build (GET /api/nextec/gen/enroll-key, cabecalho X-Nextec-Gen-Secret com
o SH_SECRET), entao girar a chave no painel nao exige mexer na stack. Ela nunca vai ao banco nem a logs.
"""
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

from django.conf import settings

from django.core.files.base import ContentFile

LOCKED_FIELDS = ('serverIP', 'serverPort', 'apiServer', 'key', 'urlLink', 'downloadLink', 'compname')
_PRODUCT_VERSION = Path(__file__).resolve().parent / 'VERSION'


def _env(name, default=''):
    return os.environ.get(name, default).strip()


def server_defaults():
    key = _env('NX_KEY')
    key_file = _env('NX_KEY_FILE')
    company = _env('NX_COMPANY')
    if _env('NX_SERVER_HOST') and company in ('', 'Nextec'):
        company = 'Nextec LTDA'
    if not key and key_file:
        try:
            key = Path(key_file).read_text(encoding='utf-8').strip()
        except (OSError, ValueError) as exc:
            # arquivo inexistente, e um diretorio (o Docker cria um quando o caminho do host nao existe) ou ilegivel
            print(f"NX_KEY_FILE ({key_file}) nao pode ser lido: {exc}")
            key = ''
    values = {
        'serverIP': _env('NX_SERVER_HOST'),
        'serverPort': _env('NX_SERVER_PORT'),
        'apiServer': _env('NX_API_SERVER'),
        'key': key,
        'urlLink': _env('NX_URL_LINK'),
        'downloadLink': _env('NX_DOWNLOAD_LINK'),
        'compname': company,
        'appname': _env('NX_APP_NAME'),
    }
    return {k: v for k, v in values.items() if v}


ENROLL_KEY_RE = re.compile(r'nx1\.[0-9]{1,12}\.[A-Za-z0-9_-]{16,128}')
CLIENT_KEY_RE = re.compile(r'nx2\.[0-9]{1,10}\.[0-9]{1,12}\.[0-9a-f]{64}')
CLIENT_ID_RE = re.compile(r'[0-9]{1,10}')
_ENROLL_PANEL_RE = re.compile(r'https?://[A-Za-z0-9._:\[\]-]+(?:/[A-Za-z0-9._~%/-]*)?')


PANEL_INTERNAL_DEFAULT = 'http://rustdesk:21114'
PANEL_FETCH_TIMEOUT = 3
_FETCH_CACHE_OK, _FETCH_CACHE_FAIL = 60, 15
_fetch_cache = {'at': 0.0, 'key': '', 'ok': False}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # o segredo nunca segue para outro endereco
        return None


def _panel_internal_url():
    if 'NX_PANEL_INTERNAL_URL' in os.environ:
        value = _env('NX_PANEL_INTERNAL_URL')
    else:
        value = PANEL_INTERNAL_DEFAULT
    value = value.rstrip('/')
    return value if value and _ENROLL_PANEL_RE.fullmatch(value) and value.startswith(('http://', 'https://')) else ''


def fetch_panel_key():
    """Busca a chave vigente no painel (rede interna, 3 s). Devolve '' em qualquer falha, sem logar chave nem segredo."""
    secret = (getattr(settings, 'SH_SECRET', '') or '').strip()
    base = _panel_internal_url()
    if not is_configured() or not base or not secret or secret == 'secret':
        return ''
    request = urllib.request.Request(base + '/api/nextec/gen/enroll-key', headers={'X-Nextec-Gen-Secret': secret}, method='GET')
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=PANEL_FETCH_TIMEOUT) as response:
            data = json.loads(response.read(4096).decode('utf-8'))
        value = data.get('enroll_key', '') if isinstance(data, dict) else ''
        return value if isinstance(value, str) and ENROLL_KEY_RE.fullmatch(value) else ''
    except urllib.error.HTTPError as exc:
        print(f"Painel recusou a busca da chave de inscricao (HTTP {exc.code}).")
    except Exception as exc:  # rede, timeout, JSON invalido: so o tipo, nunca a mensagem
        print(f"Nao foi possivel buscar a chave de inscricao no painel ({type(exc).__name__}).")
    return ''


def _panel_get_json(path, what):
    """GET interno no painel com o segredo compartilhado. Devolve o JSON (dict) ou None; nunca loga chave nem segredo."""
    secret = (getattr(settings, 'SH_SECRET', '') or '').strip()
    base = _panel_internal_url()
    if not is_configured() or not base or not secret or secret == 'secret':
        return None
    request = urllib.request.Request(base + path, headers={'X-Nextec-Gen-Secret': secret}, method='GET')
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=PANEL_FETCH_TIMEOUT) as response:
            data = json.loads(response.read(262144).decode('utf-8'))
        return data if isinstance(data, dict) else None
    except urllib.error.HTTPError as exc:
        print(f"Painel recusou {what} (HTTP {exc.code}).")
    except Exception as exc:
        print(f"Nao foi possivel obter {what} no painel ({type(exc).__name__}).")
    return None


_CLIENT_NAME_BLOCKED = '<>&"\'\\'
_clients_cache = {'at': 0.0, 'items': []}


def panel_clients(use_cache=True):
    """Clientes do painel [(id, nome)] para o seletor do formulario. Lista vazia quando o painel nao responde."""
    now = time.monotonic()
    if use_cache and _clients_cache['at'] and now - _clients_cache['at'] < 30:
        return list(_clients_cache['items'])
    data = _panel_get_json('/api/nextec/gen/clients', 'a lista de clientes')
    items = []
    if data and isinstance(data.get('clients'), list):
        for row in data['clients'][:1000]:
            if isinstance(row, dict) and isinstance(row.get('id'), int) and isinstance(row.get('name'), str):
                name = ''.join(ch for ch in row['name'] if ch.isprintable() and ch not in _CLIENT_NAME_BLOCKED).strip()[:80]
                if row['id'] > 0 and name:
                    items.append((str(row['id']), name))
    _clients_cache.update(at=now, items=items)
    return list(items)


def client_key(client_id):
    """Credencial por cliente (nx2) e nome do cliente, buscadas no painel a cada build. ('', '') se falhar.

    Falhar aqui NUNCA cai na chave global: o instalador pedido para um cliente nao pode sair "pendente" sem aviso."""
    client_id = str(client_id or '').strip()
    if not CLIENT_ID_RE.fullmatch(client_id) or int(client_id) <= 0:
        return '', ''
    data = _panel_get_json('/api/nextec/gen/enroll-key?group=' + client_id, 'a credencial do cliente')
    if not data:
        return '', ''
    value = data.get('enroll_key', '')
    name = data.get('client_name', '')
    if not (isinstance(value, str) and CLIENT_KEY_RE.fullmatch(value)):
        return '', ''
    if not value.startswith('nx2.%s.' % int(client_id)):
        return '', ''
    return value, (name if isinstance(name, str) else '')[:120]


def resolve_enroll_key(use_cache=False):
    """Chave de inscricao: a do painel (busca automatica) ou, se falhar, NX_ENROLL_KEY. Vazia se nada valer.

    O build chama sem cache (sempre a chave vigente). A tela do formulario usa cache curto para nao travar a pagina.
    Nunca deve ser gravada em banco, modelo salvo, log ou resposta: so entra no pacote cifrado do build.
    """
    now = time.monotonic()
    if use_cache:
        ttl = _FETCH_CACHE_OK if _fetch_cache['ok'] else _FETCH_CACHE_FAIL
        if _fetch_cache['at'] and now - _fetch_cache['at'] < ttl:
            if _fetch_cache['key']:
                return _fetch_cache['key']
            value = _env('NX_ENROLL_KEY')
            return value if ENROLL_KEY_RE.fullmatch(value) else ''
    fetched = fetch_panel_key()
    _fetch_cache.update(at=now, key=fetched, ok=bool(fetched))
    if fetched:
        return fetched
    value = _env('NX_ENROLL_KEY')
    return value if ENROLL_KEY_RE.fullmatch(value) else ''


def enroll_key():
    """Compatibilidade: chave vigente sem cache."""
    return resolve_enroll_key()


def enroll_panel(api_server=''):
    """URL do painel para a inscricao: NX_API_SERVER, ou o apiServer do build quando for uma URL http(s)."""
    for candidate in (_env('NX_API_SERVER'), (api_server or '').strip()):
        candidate = candidate.rstrip('/')
        if candidate and _ENROLL_PANEL_RE.fullmatch(candidate):
            return candidate
    return ''


def enrollment_warning(api_server='', key=None):
    """Aviso (sem a chave) quando o instalador sair sem inscricao automatica; vazio quando tudo certo.

    `key` e a chave ja resolvida pelo build; sem ela usa a resolucao com cache curto (tela do formulario).
    """
    if key is None:
        key = resolve_enroll_key(use_cache=True)
    if not key:
        raw = _env('NX_ENROLL_KEY')
        if raw:
            return ('Inscrição automática desativada: o gerador não conseguiu buscar a chave no painel e NX_ENROLL_KEY tem formato inválido '
                    '(esperado nx1.<época>.<assinatura>). O instalador será gerado sem inscricao.json.')
        return ('Inscrição automática desativada: o gerador não conseguiu buscar a credencial de inscrição no painel '
                '(confira se o painel está no ar e se GERADOR_SH_SECRET é o mesmo nos dois) e NX_ENROLL_KEY não está configurada. '
                'O instalador será gerado sem inscricao.json e a máquina não se inscreverá sozinha no painel.')
    if not enroll_panel(api_server):
        return ('Inscrição automática desativada: a URL do painel (NX_API_SERVER) não foi definida. '
                'O instalador será gerado sem inscricao.json.')
    return ''


def is_configured():
    """True quando o servidor Nextec esta configurado (NX_SERVER_HOST)."""
    return 'serverIP' in server_defaults()


def locked_fields():
    """Campos travados. A chave so trava se houver valor padrao: sem ele o campo fica editavel (e obrigatorio)."""
    defaults = server_defaults()
    return [f for f in LOCKED_FIELDS if f in defaults or f == 'serverPort']


def is_locked():
    return _env('NX_LOCK_SERVER', '1').lower() in ('1', 'true', 'yes', 'sim') and 'serverIP' in server_defaults()


def initial():
    """Valores iniciais do formulario."""
    return server_defaults()


def apply(params):
    """Aplica os padroes Nextec aos parametros (formulario e API). Com a trava ligada, sobrescreve os campos fixos."""
    params = dict(params)
    defaults = server_defaults()
    locked = is_locked()
    for field, value in defaults.items():
        if (locked and field in LOCKED_FIELDS) or not params.get(field):
            params[field] = value
    if locked and 'serverPort' not in defaults:
        params['serverPort'] = ''
    return params


_TRUE = ('1', 'true', 'yes', 'sim', 'on')
_FALSE = ('0', 'false', 'no', 'nao', 'não', 'off')


def agent_enabled(params):
    """Flag nx_agent do build: inclui o agente (Coordenar/Provisionar/Agente-Senha, atualizador, registro) no pacote.

    Ligado por padrao para o cliente de acesso. So fica desligado para o app de suporte avulso, ou seja, quando
    `nx_agent` vem explicito como falso, ou quando a instalacao esta desativada (app apenas executavel, sem nada para
    manter no equipamento). O NOME do app nunca entra na decisao: pode ser qualquer um."""
    raw = params.get('nx_agent')
    if isinstance(raw, bool):
        return raw
    value = str(raw).strip().lower() if raw is not None else ''
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    return params.get('installation', 'installationY') != 'installationN'


def default_image(kind):
    """Imagem padrão gerenciada quando nenhuma foi enviada no formulário."""
    env_name = {'icon': 'NX_ICON_FILE', 'logo': 'NX_LOGO_FILE', 'logo_light': 'NX_LOGO_LIGHT_FILE', 'logo_dark': 'NX_LOGO_DARK_FILE', 'privacy': 'NX_PRIVACY_FILE'}.get(kind)
    env = _env(env_name) if env_name else ''
    if env:
        path = Path(env)
    else:
        from .branding import get_path
        path = get_path(kind)
        if not path:
            return None
    try:
        return ContentFile(path.read_bytes(), name=path.name)
    except OSError:
        return None


def product_version():
    """Versão da experiência Nextec do gerador, separada da versão-base RustDesk."""
    try:
        value = _PRODUCT_VERSION.read_text(encoding='utf-8').strip()
    except OSError:
        return '2.0.2'
    return value if value and len(value) <= 32 else '2.0.2'


def config_problems():
    """Lista, em portugues, o que falta configurar para o gerador funcionar. Vazia = tudo certo."""
    from django.conf import settings
    problems = []
    if is_configured() and not server_defaults().get('key'):
        problems.append('Chave pública do servidor ausente ou ilegível (NX_KEY ou NX_KEY_FILE).')
    if not settings.GHBEARER:
        problems.append('Token do GitHub ausente (variável GHBEARER; no Portainer: GERADOR_GH_TOKEN).')
    if not settings.GHUSER:
        problems.append('Usuário do GitHub ausente (variável GHUSER; no Portainer: GERADOR_GH_USER).')
    if not settings.ZIP_PASSWORD or settings.ZIP_PASSWORD == 'insecure':
        problems.append('Senha do pacote ausente ou padrão (variável ZIP_PASSWORD; no Portainer: GERADOR_ZIP_SENHA). '
                        'Precisa ser igual ao segredo ZIP_PASSWORD do repositório no GitHub.')
    if not settings.SH_SECRET or settings.SH_SECRET == 'secret':
        problems.append('Senha da API ausente ou padrão (variável SH_SECRET; no Portainer: GERADOR_SH_SECRET).')
    return problems


# Rotas que o GitHub Actions chama (liberadas no Access). Todas as outras exigem pessoa autorizada.
PUBLIC_PATHS = ('/updategh', '/cleanzip', '/save_custom_client', '/get_png', '/get_zip', '/get_artwork')


def allowed_emails():
    """E-mails autorizados a gerar (NX_ALLOWED_EMAILS, separados por vírgula ou espaço). Vazio = quem passa pelo Access."""
    raw = _env('NX_ALLOWED_EMAILS').replace(';', ',').replace(' ', ',')
    return {e.strip().lower() for e in raw.split(',') if e.strip()}


def access_user(request):
    """E-mail que o Cloudflare Access autenticou (cabeçalho Cf-Access-Authenticated-User-Email), em minúsculas."""
    return (request.META.get('HTTP_CF_ACCESS_AUTHENTICATED_USER_EMAIL') or '').strip().lower()


def access_denied(request):
    """True se há lista de autorizados e esta requisição não é de uma pessoa da lista."""
    allowed = allowed_emails()
    if not allowed:
        return False
    path = request.path_info.rstrip('/')
    if path in PUBLIC_PATHS or path.startswith('/get_artwork/'):
        return False
    if request.META.get('REMOTE_ADDR') in ('127.0.0.1', '::1'):
        return False  # verificação de saúde do próprio contêiner
    return access_user(request) not in allowed
