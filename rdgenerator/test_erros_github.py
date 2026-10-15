from unittest.mock import Mock, patch

import requests
from django.test import SimpleTestCase, TestCase, override_settings

from .github_errors import explain_exception, explain_response


def _resp(status, body=''):
    return Mock(status_code=status, text=body)


class ExplainResponseTests(SimpleTestCase):
    def test_actions_disabled_is_named_and_actionable(self):
        info = explain_response(_resp(422, '{"message":"Actions has been disabled for this repository."}'))
        self.assertEqual(info['code'], 'github_actions_desativado')
        self.assertIn('Actions', info['title'])
        self.assertIn('Settings', info['action'])
        self.assertFalse(info['uncertain'])

    def test_other_422_keeps_github_message_as_detail(self):
        info = explain_response(_resp(422, '{"message":"Unexpected inputs provided: [\\"x\\"]"}'))
        self.assertEqual(info['code'], 'github_pedido_invalido')
        self.assertIn('Unexpected inputs', info['detail'])

    def test_token_errors(self):
        self.assertEqual(explain_response(_resp(401))['code'], 'github_token_invalido')
        self.assertEqual(explain_response(_resp(403, '{"message":"Resource not accessible"}'))['code'], 'github_sem_permissao')
        self.assertEqual(explain_response(_resp(403, '{"message":"API rate limit exceeded"}'))['code'], 'github_limite')

    def test_not_found_and_server_errors(self):
        self.assertEqual(explain_response(_resp(404))['code'], 'github_nao_encontrado')
        server = explain_response(_resp(503))
        self.assertEqual(server['code'], 'github_indisponivel')
        self.assertTrue(server['uncertain'])
        self.assertIn('pode ter aceitado', server['message'])

    def test_non_json_and_mock_bodies_do_not_break(self):
        self.assertEqual(explain_response(_resp(422, '<html>boom</html>'))['detail'], '')
        self.assertEqual(explain_response(Mock(status_code=422))['code'], 'github_pedido_invalido')

    def test_detail_is_truncated(self):
        info = explain_response(_resp(422, '{"message":"' + 'x' * 1000 + '"}'))
        self.assertLessEqual(len(info['detail']), 240)

    def test_exceptions(self):
        timeout = explain_exception(requests.Timeout())
        self.assertEqual(timeout['code'], 'github_timeout')
        self.assertTrue(timeout['uncertain'])
        self.assertEqual(explain_exception(requests.ConnectionError())['code'], 'github_sem_conexao')
        self.assertEqual(explain_exception(ValueError('x'))['code'], 'github_erro_interno')


class GeneratorErrorPageTests(TestCase):
    def test_get_prefills_retry_fields_only(self):
        from django.test import RequestFactory
        from . import nextec, views
        request = RequestFactory().get('/', {'exename': 'Meu-App', 'client_name': 'Carteira A', 'key': 'segredo'})
        with patch.object(nextec, 'config_problems', return_value=[]):
            response = views.generator_view(request)
        body = response.content.decode()
        self.assertEqual(response.status_code, 200)
        self.assertIn('Meu-App', body)
        self.assertIn('Carteira A', body)
        self.assertNotIn('segredo', body)

    def test_failed_start_renders_readable_page_with_retry(self):
        from django.test import RequestFactory
        from . import nextec, views
        failure = {'success': False, 'error': 'x', 'title': 'O GitHub Actions está desativado',
                   'message': 'Nenhum instalador sai.', 'action': 'Ative o Actions.', 'detail': '',
                   'error_code': 'github_actions_desativado', 'status_code': 424}
        request = RequestFactory().post('/', {'exename': 'Meu-App', 'appname': 'Meu-App', 'platform': 'windows', 'key': 'segredo'})
        with patch.object(nextec, 'config_problems', return_value=[]),                 patch.object(views, 'generate_custom_client', return_value=failure),                 patch.object(views.GenerateForm, 'is_valid', return_value=True):
            views.GenerateForm.cleaned_data = {'exename': 'Meu-App'}
            try:
                response = views.generator_view(request)
            finally:
                del views.GenerateForm.cleaned_data
        body = response.content.decode()
        self.assertEqual(response.status_code, 424)
        self.assertIn('Tentar de novo', body)
        self.assertIn('exename=Meu-App', body)
        self.assertIn('github_actions_desativado', body)
        self.assertNotIn('segredo', body)
