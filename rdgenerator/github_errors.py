"""Traduz a falha de uma chamada ao GitHub em texto que diz o que aconteceu e o que fazer.

Nunca devolve o corpo bruto nem o token: so um trecho curto da mensagem do proprio GitHub.
"""
import json

import requests

_MAX_DETAIL = 240


def _github_message(response):
    text = getattr(response, 'text', '')
    if not isinstance(text, str) or not text:
        return ''
    try:
        data = json.loads(text)
        message = data.get('message', '') if isinstance(data, dict) else ''
    except ValueError:
        message = ''
    return str(message or '').strip()[:_MAX_DETAIL]


def _info(code, title, message, action, status, detail, uncertain=False):
    return {'code': code, 'title': title, 'message': message, 'action': action,
            'http_status': status, 'detail': detail, 'uncertain': uncertain}


def explain_response(response):
    """Falha devolvida pelo GitHub ao iniciar a geracao."""
    status = getattr(response, 'status_code', 0)
    detail = _github_message(response)
    low = detail.lower()
    if status == 422 and 'actions has been disabled' in low:
        return _info('github_actions_desativado', 'O GitHub Actions está desativado no repositório do gerador',
                     'O GitHub recusou iniciar a geração porque o Actions está desativado nesse repositório. '
                     'Nenhum instalador sai enquanto isso (HTTP 422).',
                     'No GitHub, abra o repositório do gerador em Settings > Actions > General, escolha '
                     '"Allow all actions", salve e confira Billing (limite de gasto). Depois tente de novo.',
                     status, detail)
    if status == 422:
        return _info('github_pedido_invalido', 'O GitHub não aceitou o pedido de geração',
                     'O GitHub recusou os dados enviados ao workflow (HTTP 422).',
                     'Confira se o workflow existe na branch configurada e aceita estes campos. '
                     'Quem administra o gerador vê o detalhe abaixo.', status, detail)
    if status == 401:
        return _info('github_token_invalido', 'O token do GitHub é inválido ou expirou',
                     'O GitHub rejeitou o token usado pelo gerador (HTTP 401).',
                     'Gere um novo token com permissão de Actions e atualize a variável GHBEARER na stack.',
                     status, detail)
    if status == 403 and ('rate limit' in low or 'abuse' in low):
        return _info('github_limite', 'O GitHub limitou as requisições',
                     'Muitas requisições em pouco tempo (HTTP 403).', 'Aguarde alguns minutos e tente de novo.',
                     status, detail)
    if status == 403:
        return _info('github_sem_permissao', 'O token do GitHub não tem permissão',
                     'O token do gerador não pode iniciar workflows neste repositório (HTTP 403).',
                     'Dê ao token acesso de escrita a Actions no repositório (e autorize o SSO, se a organização exigir).',
                     status, detail)
    if status == 404:
        return _info('github_nao_encontrado', 'O GitHub não encontrou o repositório ou o workflow',
                     'Repositório, workflow ou branch inexistente, ou o token não enxerga o repositório (HTTP 404).',
                     'Confira GHUSER, REPONAME e GHBRANCH na stack e se o token tem acesso ao repositório.',
                     status, detail)
    if status == 429:
        return _info('github_limite', 'O GitHub limitou as requisições', 'Muitas requisições (HTTP 429).',
                     'Aguarde alguns minutos e tente de novo.', status, detail)
    if status >= 500:
        return _info('github_indisponivel', 'O GitHub está instável',
                     f'O GitHub respondeu com erro interno (HTTP {status}). '
                     'O GitHub pode ter aceitado a geração; verifique o histórico antes de tentar novamente.',
                     'Confira o status em githubstatus.com e olhe o histórico antes de gerar de novo.',
                     status, detail, uncertain=True)
    return _info('github_resposta_inesperada', 'Resposta inesperada do GitHub',
                 f'O GitHub respondeu com HTTP {status}, que o gerador não esperava.',
                 'Tente de novo; se repetir, envie o detalhe abaixo a quem administra o gerador.', status, detail)


def explain_exception(exc):
    """Falha de rede ou interna antes de o GitHub responder."""
    if isinstance(exc, requests.Timeout):
        return _info('github_timeout', 'O GitHub demorou demais para responder',
                     'O pedido passou do tempo limite. O GitHub pode ter aceitado a geração; '
                     'verifique o histórico antes de tentar novamente.',
                     'Olhe o histórico (Itens gerados) e só gere de novo se não houver item novo.',
                     0, '', uncertain=True)
    if isinstance(exc, requests.ConnectionError):
        return _info('github_sem_conexao', 'O gerador não conseguiu falar com o GitHub',
                     'Falha de rede ou DNS ao chamar api.github.com. O GitHub pode ter aceitado a geração; '
                     'verifique o histórico antes de tentar novamente.',
                     'Confira a saída de internet do servidor do gerador e tente de novo.',
                     0, '', uncertain=True)
    return _info('github_erro_interno', 'Erro inesperado ao iniciar a geração',
                 'O gerador falhou antes de concluir o pedido. O GitHub pode ter aceitado a geração; '
                 'verifique o histórico antes de tentar novamente.',
                 'Tente de novo; se repetir, avise quem administra o gerador.', 0, type(exc).__name__, uncertain=True)
