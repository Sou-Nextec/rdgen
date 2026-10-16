"""Nome nos atalhos do Windows (menu Iniciar, pesquisa e area de trabalho), separado do nome tecnico do app."""
import io
import json
import os
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

import pyzipper
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings

from .build_inputs import validate_build_inputs
from .forms import GenerateForm
from .views import generate_custom_client, generator_view


class ShortcutNameValidation(SimpleTestCase):
    def data(self, **extra):
        values = {name: field.initial if field.initial is not None else ""
                  for name, field in GenerateForm.base_fields.items()
                  if name not in ("iconfile", "logofile", "privacyfile")}
        values.update(exename="Nextec-Connect", profile="default")
        values.update(extra)
        return values

    def test_accepts_spaces_and_accents(self):
        for name in ("Suporte Nextec", "Nextec Connect", "Suporte Técnico", "Nextec-Connect", "TI 2"):
            form = GenerateForm(self.data(shortcutname=name))
            form.is_valid()
            self.assertNotIn("shortcutname", form.errors, name)
            self.assertEqual(form.cleaned_data["shortcutname"], name)

    def test_spaces_at_the_ends_are_trimmed_not_rejected(self):
        form = GenerateForm(self.data(shortcutname="  Suporte Nextec  "))
        form.is_valid()
        self.assertEqual(form.cleaned_data["shortcutname"], "Suporte Nextec")

    def test_empty_is_allowed_and_means_the_app_name(self):
        form = GenerateForm(self.data(shortcutname=""))
        self.assertNotIn("shortcutname", form.errors)

    def test_rejects_characters_windows_does_not_allow_in_file_names(self):
        for name in ("a/b", "a\\b", "x*y", "a:b", "a?b", "<b>", "a|b", 'a"b', "Nome.", "n" * 41, "_inicio"):
            form = GenerateForm(self.data(shortcutname=name))
            self.assertIn("shortcutname", form.errors, repr(name))

    def test_build_inputs_validation_matches_the_form(self):
        validate_build_inputs({"shortcutname": "Suporte Nextec"})
        validate_build_inputs({"shortcutname": ""})
        for bad in ("a/b", "Nome ", "x" * 41, "a&b", "$(x)"):
            with self.assertRaises(ValueError, msg=bad):
                validate_build_inputs({"shortcutname": bad})


@override_settings(GHBEARER="t", GHUSER="u", ZIP_PASSWORD="test-only-zip", SH_SECRET="outra-forte", GENURL="https://generator.example")
class ShortcutNameInBuild(TestCase):
    def setUp(self):
        self.old = os.getcwd()
        self.tmp = tempfile.TemporaryDirectory()
        os.chdir(self.tmp.name)
        self.addCleanup(lambda: (os.chdir(self.old), self.tmp.cleanup()))

    def test_name_goes_to_the_encrypted_build_inputs(self):
        response = Mock(status_code=200)
        response.json.return_value = {"workflow_run_id": 7, "html_url": "https://github.com/test/actions/runs/7"}
        out, err = io.StringIO(), io.StringIO()
        with patch("rdgenerator.views.requests.post", return_value=response), redirect_stdout(out), redirect_stderr(err):
            result = generate_custom_client({"exename": "Suporte", "appname": "Suporte-Nextec", "shortcutname": "Suporte Nextec"}, "https://generator.example")
        self.assertTrue(result["success"], result)
        with pyzipper.AESZipFile(Path("temp_zips") / ("secrets_" + result["uuid"] + ".zip")) as zf:
            zf.setpassword(b"test-only-zip")
            inputs = json.loads(zf.read("secrets.json"))
        self.assertEqual(inputs["shortcutname"], "Suporte Nextec")
        self.assertEqual(inputs["appname"], "Suporte-Nextec")
        validate_build_inputs(inputs)


class ShortcutNameField(SimpleTestCase):
    def html(self):
        with patch("rdgenerator.views.nextec.config_problems", return_value=[]):
            return generator_view(RequestFactory().get("/generator")).content.decode()

    def test_field_is_in_the_simple_area_with_an_explanation(self):
        html = self.html()
        self.assertIn('name="shortcutname"', html)
        self.assertIn("menu Iniciar", html)
        self.assertIn("pesquisa do Windows", html)
        self.assertIn('id="shortcutError"', html)

    def test_name_is_checked_while_typing_like_the_server(self):
        html = self.html()
        self.assertIn("function shortcutProblem(", html)
