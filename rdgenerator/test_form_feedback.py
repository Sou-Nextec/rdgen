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
    def test_invalid_base_version_is_visible_and_does_not_start_a_build(self, generate, config):
        data = self.data()
        data["version"] = "2.bad"
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


class GeneratorP1RefinementTests(SimpleTestCase):
    def page(self, query="", **env):
        patches = [patch("rdgenerator.views.nextec.config_problems", return_value=[])]
        if "enrollment" in env:
            patches += [patch("rdgenerator.views.nextec.is_configured", return_value=True),
                        patch("rdgenerator.views.nextec.enrollment_warning", return_value=env["enrollment"])]
        for p in patches:
            p.start()
        try:
            return generator_view(RequestFactory().get("/generator" + query)).content.decode()
        finally:
            for p in patches:
                p.stop()

    def test_enrollment_warning_is_an_alert_and_blocks_generate_until_confirmed(self):
        html = self.page(enrollment="Inscrição automática desativada: teste.")
        self.assertIn('role="alert" id="appliedAlert"', html)
        self.assertIn("Atenção: confira antes de gerar", html)
        self.assertNotIn("Já aplicado pela Nextec", html)
        self.assertIn('id="ackNoEnroll"', html)
        self.assertIn('id="submitButton" disabled', html)
        # a confirmacao nao tem name: nao entra no POST nem em modelos salvos
        self.assertNotIn('name="ackNoEnroll"', html)

    def test_no_warning_keeps_the_note_and_enabled_button(self):
        html = self.page()
        self.assertIn("Já aplicado pela Nextec", html)
        self.assertNotIn('id="ackNoEnroll"', html)
        self.assertNotIn('id="submitButton" disabled', html)

    def test_installer_name_is_prefilled_and_placeholders_read_as_examples(self):
        html = self.page()
        self.assertIn('value="Nextec-Connect"', html)
        self.assertIn('placeholder="Ex.: Nextec-Connect"', html)

    def test_retry_without_app_name_leaves_it_blank_to_be_checked(self):
        html = self.page("?exename=Suporte-Nextec")
        self.assertIn('value="Suporte-Nextec"', html)
        self.assertNotIn('name="appname" value="Nextec-Connect"', html)

    def test_names_are_validated_while_typing(self):
        html = self.page()
        self.assertIn('id="appnameError"', html)
        self.assertIn("appProblem", html)
        self.assertIn("aria-describedby=\"appname-hint appnameError\"", html)

    def test_header_stays_readable_with_system_dark_scheme(self):
        html = self.page()
        self.assertIn("prefers-color-scheme:dark) { html:not([data-embedded]):not(.light) .nx-header {", html)

    def test_link_addresses_have_their_own_honest_group(self):
        html = self.page()
        server = html.split("<h3>Servidor Nextec</h3>")[1].split("<h3>Endereços do aplicativo</h3>")[0]
        self.assertNotIn("urlLink", server)
        self.assertNotIn("downloadLink", server)
        self.assertIn("Opcionais. Vazios usam os endereços padrão do RustDesk.", html)


class GeneratorP2RefinementTests(SimpleTestCase):
    def html(self, query=""):
        with patch("rdgenerator.views.nextec.config_problems", return_value=[]):
            return generator_view(RequestFactory().get("/generator" + query)).content.decode()

    def test_model_bar_is_just_a_selector_that_loads_on_choice(self):
        html = self.html()
        self.assertIn("Começar de um modelo", html)
        self.assertNotIn('id="loadServerModel"', html)
        self.assertIn("modelSelect.addEventListener('change'", html)

    def test_save_and_delete_model_sit_next_to_generate_not_on_top(self):
        html = self.html()
        save = html.index('id="saveServerModel"')
        self.assertGreater(save, html.index('<div class="applied'))
        self.assertLess(save, html.index('id="submitButton"'))
        self.assertIn('id="deleteServerModel" class="secondary-action" hidden', html)

    def test_no_native_dialogs_remain(self):
        html = self.html()
        for call in ("prompt(", "confirm(", "alert("):
            self.assertNotIn(call, html.replace("askBox", ""), call)

    def test_app_name_follows_installer_name_until_edited(self):
        html = self.html()
        self.assertIn("let follow = !app.value || app.value === name.value;", html)
        self.assertIn("Acompanha o nome do instalador", html)

    def test_package_version_is_a_readonly_chip_not_a_field(self):
        html = self.html()
        self.assertNotIn("Versão do pacote</label>", html)
        self.assertIn('class="pkg-chip"', html)
        self.assertIn('name="package_version"', html)

    def test_profile_and_client_sit_together_and_about_block_is_gone(self):
        html = self.html()
        self.assertLess(html.index("Destinado a"), html.index('id="clientRequired"'))
        self.assertNotIn("Sobre nomes, versões e acesso", html)

    def test_specific_client_profile_requires_a_client_name(self):
        data = GeneratorFormFeedbackTests.data(self)
        data.update(profile="client", client_name="")
        form = GenerateForm(data)
        self.assertFalse(form.is_valid())
        self.assertIn("client_name", form.errors)
        data["client_name"] = "Carteira Bruno"
        self.assertNotIn("client_name", GenerateForm(data).errors)
        data.update(profile="default", client_name="")
        self.assertNotIn("client_name", GenerateForm(data).errors)

    def test_blank_model_option_resets_the_form_and_names_resume_following(self):
        html = self.html()
        self.assertIn("function resetToDefaults()", html)
        self.assertIn("if (modelLoaded) { resetToDefaults();", html)
        self.assertIn("if (!app.value || app.value === name.value) follow = true;", html)
