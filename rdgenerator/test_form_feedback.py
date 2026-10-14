from unittest.mock import patch

from django.test import RequestFactory, SimpleTestCase

from .forms import GenerateForm
from .views import generator_view


class GeneratorFormFeedbackTests(SimpleTestCase):
    def data(self):
        values = {name: field.initial if field.initial is not None else ""
                  for name, field in GenerateForm.base_fields.items()
                  if name not in ("iconfile", "logofile", "privacyfile")}
        values.update(exename="Nextec-Connect", profile="default")
        return values

    @patch("rdgenerator.views.nextec.config_problems", return_value=[])
    @patch("rdgenerator.views.generate_custom_client")
    def test_invalid_version_is_visible_and_does_not_start_a_build(self, generate, config):
        data = self.data()
        data["package_version"] = "2.bad"
        response = generator_view(RequestFactory().post("/generator", data))
        self.assertEqual(response.status_code, 400)
        html = response.content.decode()
        self.assertIn('role="alert"', html)
        self.assertIn("Revise os campos indicados antes de gerar.", html)
        generate.assert_not_called()

    @patch("rdgenerator.views.nextec.config_problems", return_value=[])
    @patch("rdgenerator.views.generate_custom_client")
    def test_invalid_choice_does_not_echo_the_submitted_value(self, generate, config):
        data = self.data()
        data["passApproveMode"] = "test-private-value-not-for-display"
        response = generator_view(RequestFactory().post("/generator", data))
        self.assertEqual(response.status_code, 400)
        self.assertIn("Escolha uma das opções disponíveis.", response.content.decode())
        self.assertNotIn(data["passApproveMode"], response.content.decode())
        generate.assert_not_called()


class GeneratorSimpleModeTests(SimpleTestCase):
    @patch("rdgenerator.views.nextec.config_problems", return_value=[])
    def test_simple_mode_by_default_with_advanced_collapsed(self, config):
        html = generator_view(RequestFactory().get("/generator")).content.decode()
        self.assertIn("Gerar instalador", html)
        self.assertIn('id="advanced"', html)
        self.assertNotIn('id="advanced" open', html)
        self.assertIn("Já aplicado pela Nextec", html)

    @patch("rdgenerator.views.nextec.config_problems", return_value=[])
    @patch("rdgenerator.views.generate_custom_client")
    def test_error_in_advanced_field_opens_advanced_and_shows_message_on_field(self, generate, config):
        data = GeneratorFormFeedbackTests.data(self)
        data["serverPort"] = "21117"
        html = generator_view(RequestFactory().post("/generator", data)).content.decode()
        self.assertIn('id="advanced" open', html)
        self.assertIn('class="field-error"', html)
        generate.assert_not_called()
