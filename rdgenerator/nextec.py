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
"""
import os
from pathlib import Path

from django.core.files.base import ContentFile

LOCKED_FIELDS = ('serverIP', 'serverPort', 'apiServer', 'key', 'urlLink', 'downloadLink', 'compname')
_PRODUCT_VERSION = Path(__file__).resolve().parent / 'VERSION'


def _env(name, default=''):
    return os.environ.get(name, default).strip()


def server_defaults():
    key = _env('NX_KEY')
    key_file = _env('NX_KEY_FILE')
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
        'compname': _env('NX_COMPANY'),
        'appname': _env('NX_APP_NAME'),
    }
    return {k: v for k, v in values.items() if v}


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


def default_image(kind):
    """Imagem padrão gerenciada quando nenhuma foi enviada no formulário."""
    env_name = {'icon': 'NX_ICON_FILE', 'logo': 'NX_LOGO_FILE', 'privacy': 'NX_PRIVACY_FILE'}.get(kind)
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
        return '2.0.1'
    return value if value and len(value) <= 32 else '2.0.1'


def config_problems():
    """Lista, em portugues, o que falta configurar para o gerador funcionar. Vazia = tudo certo."""
    from django.conf import settings
    problems = []
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
