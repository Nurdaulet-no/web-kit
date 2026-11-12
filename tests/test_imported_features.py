import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from auditkit.cli import main
from auditkit.dependency_check import check_dependencies, parse_npm, parse_pip
from auditkit.rce_check import check_rce_potential_enhanced
from auditkit.scope import Scope


class ImportedScopeTests(unittest.TestCase):
    def test_default_ports_and_backward_compatible_constructor(self):
        for scheme, port in [('https', 443), ('http', 80)]:
            value = scheme + '://example.test'
            scope = Scope.from_dict(dict(targets=[value], allowed_origins=[value], allowed_ports=[port]))
            self.assertTrue(scope.permits(value))
            self.assertTrue(scope.is_target(value + ':' + str(port)))
            self.assertEqual(scope.get_allowed_hosts(), ['example.test'])
        self.assertTrue(Scope(['https://example.test/'], {'https://example.test'}, []).permits('https://example.test'))

    def test_bad_ports_and_conflicting_origins_rejected(self):
        for ports in [[True], [False], [0], [65536], ['443'], [80], None]:
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                Scope.from_dict(dict(targets=['https://example.test'],
                                     allowed_origins=['https://example.test'], allowed_ports=ports))

    def test_ports_do_not_expand_origins(self):
        scope = Scope.from_dict(dict(targets=['https://example.test'], allowed_origins=['https://example.test'],
                                     allowed_ports=[443, 8443]))
        self.assertFalse(scope.permits('https://example.test:8443'))
        self.assertFalse(scope.permits('https://other.test'))
        self.assertFalse(scope.permits('https://example.test/logout'))


class DependencyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_pip_schema_and_unknown_severity(self):
        findings = parse_pip({'dependencies': [{'name': 'demo', 'version': '1',
                              'vulns': [{'id': 'TEST-1', 'fix_versions': ['2']}]}]}, 'requirements.txt')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['severity'], 'info')
        self.assertEqual(findings[0]['confidence'], 'unverified-tool-alert')
        with self.assertRaises(ValueError):
            parse_pip({'dependencies': [{'name': 'demo', 'skip_reason': 'unresolved'}]}, 'requirements.txt')

    def test_npm_moderate_and_invalid_results(self):
        findings = parse_npm({'vulnerabilities': {'demo': {'severity': 'moderate', 'via': ['TEST']}}}, 'package.json')
        self.assertEqual(findings[0]['severity'], 'medium')
        for payload in [[], {}, {'error': 'registry unavailable', 'vulnerabilities': {}}]:
            with self.assertRaises(ValueError):
                parse_npm(payload, 'package.json')

    def test_pip_exit_one_preserves_advisories_and_correct_manifest(self):
        manifest = self.root / 'requirements.txt'
        manifest.write_text('demo==1\n')
        def execute(command, timeout, cwd):
            self.assertEqual(command[command.index('-r') + 1], str(manifest))
            self.assertEqual(cwd, self.root)
            Path(command[command.index('--output') + 1]).write_text(json.dumps(
                {'dependencies': [{'name': 'demo', 'version': '1', 'vulns': [{'id': 'TEST-1'}]}]}))
            return {'status': 'completed', 'exit_code': 1, 'log': ''}
        with patch('auditkit.dependency_check.shutil.which', return_value='/tools/pip-audit'), \
             patch('auditkit.dependency_check.execute', side_effect=execute):
            result = check_dependencies(code_path=self.root)
        self.assertEqual(len(result['findings']), 1)
        self.assertFalse(result['errors'])

    def test_nested_npm_uses_its_directory(self):
        nested = self.root / 'frontend'
        nested.mkdir()
        (nested / 'package.json').write_text('{}')
        (nested / 'package-lock.json').write_text('{}')
        execution = {'status': 'completed', 'exit_code': 1,
                     'log': json.dumps({'vulnerabilities': {'demo': {'severity': 'high'}}})}
        with patch('auditkit.dependency_check.shutil.which', return_value='/tools/npm'), \
             patch('auditkit.dependency_check.execute', return_value=execution) as execute:
            result = check_dependencies(code_path=self.root)
        self.assertEqual(execute.call_args.kwargs['cwd'], nested)
        self.assertEqual(len(result['findings']), 1)
        self.assertFalse(result['errors'])

    def test_missing_tool_is_incomplete_not_clean(self):
        (self.root / 'requirements.txt').write_text('demo==1')
        with patch('auditkit.dependency_check.shutil.which', return_value=None):
            result = check_dependencies(code_path=self.root)
        self.assertEqual(result['errors'][0]['type'], 'ToolUnavailable')
        self.assertEqual(result['dependency_checks'][0]['status'], 'unavailable')

    def test_missing_lock_does_not_launch_npm(self):
        (self.root / 'package.json').write_text('{}')
        with patch('auditkit.dependency_check.shutil.which', return_value='/tools/npm'), \
             patch('auditkit.dependency_check.execute') as execute:
            result = check_dependencies(code_path=self.root)
        execute.assert_not_called()
        self.assertTrue(result['errors'])

    def test_timeout_and_invalid_json_are_errors(self):
        (self.root / 'package.json').write_text('{}')
        (self.root / 'package-lock.json').write_text('{}')
        for execution in [{'status': 'timeout', 'exit_code': -15, 'log': ''},
                          {'status': 'completed', 'exit_code': 0, 'log': 'not JSON'},
                          {'status': 'completed', 'exit_code': 1, 'log': '{"vulnerabilities":{}}'}]:
            with patch('auditkit.dependency_check.shutil.which', return_value='/tools/npm'), \
                 patch('auditkit.dependency_check.execute', return_value=execution):
                result = check_dependencies(code_path=self.root)
            self.assertTrue(result['errors'])
            self.assertEqual(result['dependency_checks'][0]['status'], 'error')

    def test_symlinks_and_vendor_directories_skipped(self):
        (self.root / 'requirements.txt').symlink_to('/does-not-exist')
        vendor = self.root / 'node_modules'
        vendor.mkdir()
        (vendor / 'package.json').write_text('{}')
        with patch('auditkit.dependency_check.execute') as execute:
            result = check_dependencies(code_path=self.root)
        execute.assert_not_called()
        self.assertFalse(result['dependency_checks'])

    def test_unsupported_manifests_report_coverage_gap(self):
        (self.root / 'Pipfile').write_text('[packages]')
        result = check_dependencies(code_path=self.root)
        self.assertEqual(result['errors'][0]['type'], 'UnsupportedManifest')

    def test_static_analysis_has_no_simulated_compromise(self):
        (self.root / 'app.py').write_text('eval(user_input)\n')
        result = check_rce_potential_enhanced(code_path=self.root)
        self.assertEqual(len(result['findings']), 1)
        self.assertEqual(result['findings'][0]['confidence'], 'heuristic-review-required')
        self.assertEqual(result['requests'], 0)

    def test_security_cli_writes_serializable_report_and_fail_on(self):
        (self.root / 'app.py').write_text('eval(user_input)\n')
        scope_path = self.root / 'scope.json'
        scope_path.write_text(json.dumps(dict(targets=['https://example.test'], allowed_origins=['https://example.test'])))
        output = self.root / 'output'
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = main(['security', '--scope', str(scope_path), '--code-path', str(self.root), '--authorized',
                         '--ui', 'off', '--out', str(output), '--fail-on', 'medium'])
        self.assertEqual(code, 1)
        report = json.loads((output / 'report.json').read_text())
        self.assertEqual(report['schema_version'], 1)
        self.assertEqual(report['mode'], 'security-check')
        self.assertEqual(report['scope']['allowed_origins'], ['https://example.test'])


if __name__ == '__main__':
    unittest.main()
