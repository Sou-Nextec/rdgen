"""
WSGI config for rdgen project.

Padrao Nextec: URL_PREFIX (ex.: /gerador) permite servir o gerador num caminho do mesmo dominio do painel.
O Cloudflare repassa o caminho inteiro, entao o prefixo e tirado aqui e entregue ao Django como SCRIPT_NAME.
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'rdgen.settings')


class PrefixMiddleware:
    def __init__(self, app, prefix):
        self.app = app
        self.prefix = '/' + prefix.strip('/') if prefix.strip('/') else ''

    def __call__(self, environ, start_response):
        if self.prefix:
            path = environ.get('PATH_INFO', '')
            if path == self.prefix:
                # sem a barra final os links relativos da pagina apontariam para a raiz do dominio
                query = environ.get('QUERY_STRING', '')
                start_response('301 Moved Permanently', [('Location', self.prefix + '/' + ('?' + query if query else '')), ('Content-Length', '0')])
                return [b'']
            if path.startswith(self.prefix + '/'):
                environ['SCRIPT_NAME'] = self.prefix
                environ['PATH_INFO'] = path[len(self.prefix):]
        return self.app(environ, start_response)


application = PrefixMiddleware(get_wsgi_application(), os.environ.get('URL_PREFIX', ''))
