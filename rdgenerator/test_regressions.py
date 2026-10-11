import importlib.util
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from django.test import SimpleTestCase, TestCase, override_settings
from .models import GithubRun
from .progress import workflow_progress


class CachedFlutterPatchTests(SimpleTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.sdk = Path(self.tmp.name)
        subprocess.run(['git', 'init', str(self.sdk)], check=True, capture_output=True)
        self.source = self.sdk / 'dropdown.dart'
        self.source.write_text('before\n', encoding='utf-8')
        self.patch = self.sdk / 'fix.diff'
        self.patch.write_text('diff --git a/dropdown.dart b/dropdown.dart\n--- a/dropdown.dart\n+++ b/dropdown.dart\n@@ -1 +1 @@\n-before\n+after\n', encoding='utf-8')
        script = Path(__file__).resolve().parents[1] / 'nextec/scripts/apply_flutter_patch.py'
        spec = importlib.util.spec_from_file_location('flutter_patch', script)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def test_fresh_sdk_is_patched_once_and_cached_sdk_is_accepted(self):
        self.assertEqual(self.module.apply_patch(self.sdk, self.patch), 'applied')
        self.assertEqual(self.module.apply_patch(self.sdk, self.patch), 'already applied')
        self.assertEqual(self.source.read_text(), 'after\n')

    def test_incompatible_sdk_fails_without_modifying_source(self):
        self.source.write_text('incompatible\n', encoding='utf-8')
        with self.assertRaisesRegex(RuntimeError, 'incompatible'):
            self.module.apply_patch(self.sdk, self.patch)
        self.assertEqual(self.source.read_text(), 'incompatible\n')


class ProgressTests(SimpleTestCase):
    def test_progress_counts_real_steps_and_excludes_cleanup(self):
        jobs = [{'name': 'Build Windows', 'steps': [
            {'name': 'Compile', 'status': 'completed', 'conclusion': 'success'},
            {'name': 'Package', 'status': 'in_progress'},
            {'name': 'Post checkout', 'status': 'completed', 'conclusion': 'success'},
            {'name': 'Optional signer', 'status': 'completed', 'conclusion': 'skipped'},
        ]}]
        self.assertEqual(workflow_progress(jobs, 'in_progress'), {'percent': 50, 'stage': 'Package', 'failed_step': ''})

    def test_failure_identifies_stage_and_never_claims_completion(self):
        jobs = [{'name': 'Build', 'steps': [{'name': 'Patch flutter', 'status': 'completed', 'conclusion': 'failure'}]}]
        self.assertEqual(workflow_progress(jobs, 'failure')['failed_step'], 'Patch flutter')
        self.assertNotEqual(workflow_progress([], 'incomplete')['percent'], 100)
        self.assertEqual(workflow_progress([], 'success', True)['percent'], 100)


@override_settings(GHBEARER='test', GHUSER='test', REPONAME='rdgen')
class BuildStatusRegressionTests(TestCase):
    def setUp(self):
        self.uuid = 'b2af7668-d0e2-4bd4-b803-50b93d11a7f7'
        GithubRun.objects.create(uuid=self.uuid, github_run_id='123', status='failure', filename='test', platform='windows')

    @patch('rdgenerator.views.requests.get')
    def test_api_and_failure_page_report_failed_step(self, get):
        get.return_value = Mock(status_code=200)
        get.return_value.json.return_value = {'jobs': [{'name': 'Build', 'steps': [{'name': 'Patch flutter', 'status': 'completed', 'conclusion': 'failure'}]}]}
        response = self.client.get('/api/status', {'uuid': self.uuid})
        self.assertEqual(response.json()['progress']['failed_step'], 'Patch flutter')
        html = self.client.get('/check_for_file', {'uuid': self.uuid}).content.decode()
        self.assertIn('Patch flutter', html)
        self.assertIn('nextec-generator-ready', html)

    @patch('rdgenerator.views.requests.get', side_effect=__import__('requests').Timeout)
    def test_github_timeout_does_not_erase_build_status(self, get):
        response = self.client.get('/api/status', {'uuid': self.uuid})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status'], 'failure')
        self.assertIsNone(response.json()['progress']['percent'])

    def test_missing_config_can_render_inside_same_origin_panel(self):
        response = self.client.get('/')
        self.assertEqual(response.headers['X-Frame-Options'], 'SAMEORIGIN')
        self.assertIn('nextec-generator-ready', response.content.decode())


class WaitingPageRegressionTests(SimpleTestCase):
    def test_platform_notice_only_appears_for_macos(self):
        from django.template.loader import render_to_string
        for platform in ('windows', 'windows-x86', 'linux'):
            with self.subTest(platform=platform):
                html = render_to_string('waiting.html', {'platform': platform})
                self.assertNotIn('macOS: a geração', html)
        html = render_to_string('waiting.html', {'platform': 'macos'})
        self.assertIn('macOS: a geração', html)
