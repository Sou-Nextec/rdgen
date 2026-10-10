from django.shortcuts import render

from . import nextec


class NextecAccessMiddleware:
    """Só administradores e pessoas autorizadas geram clientes (lista NX_ALLOWED_EMAILS, além do Cloudflare Access)."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if nextec.access_denied(request):
            return render(request, 'access_denied.html', {'email': nextec.access_user(request)}, status=403)
        return self.get_response(request)
