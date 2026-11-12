import contextlib
import io
import json
from http.client import HTTPResponse
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from auditkit.cli import main
from auditkit.engines import Captures, failure_reason, nuclei_scan
from auditkit.reports import empty_report, execution_outcome, group_findings, write_report


class MemorySocket:
    def __init__(self, raw):
        self.raw = raw

    def makefile(self, *args):
        return io.BytesIO(self.raw)


class ReportQualityTests(unittest.TestCase):
    def test_dechunked_capture_round_trips_with_real_http_parser(self):
        with tempfile.TemporaryDirectory() as temporary:
            captures = Captures(temporary)
            response = {'status': 200, 'elapsed': .1, 'body': b'first\nsecond\n',
                        'headers': [('Transfer-Encoding', 'chunked'), ('Content-Length', '500'),
                                    ('Content-Type', 'text/plain'), ('Set-Cookie', 'one=1'), ('Set-Cookie', 'two=2')]}
            captures('https://example.test/', response)
            raw = (captures.raw / '0000.txt').read_bytes()
            parsed = HTTPResponse(MemorySocket(raw))
            parsed.begin()
            self.assertEqual(parsed.read(), response['body'])
            self.assertEqual(parsed.getheader('Content-Length'), str(len(response['body'])))
            self.assertIsNone(parsed.getheader('Transfer-Encoding'))
            self.assertEqual(len([key for key, _ in parsed.getheaders() if key == 'Set-Cookie']), 2)
            self.assertIn(('Transfer-Encoding', 'chunked'), response['headers'])
            har = json.loads(captures.har().read_text())
            self.assertNotIn('Transfer-Encoding', [h['name'] for h in har['log']['entries'][0]['response']['headers']])

    def findings(self):
        return [dict(rule='header.hsts', title='HSTS absent', url=f'https://example.test/{index}',
                     severity='low', confidence='observed', evidence='Missing header', recommendation='Configure HSTS')
                for index in range(100)]

    def test_grouping_retains_all_urls_and_separates_sites_and_rules(self):
        values = self.findings()
        values.append({**values[0], 'url': 'https://other.test/'})
        values.append({**values[0], 'rule': 'another.rule'})
        groups = group_findings(values)
        self.assertEqual(len(groups), 3)
        largest = max(groups, key=lambda group: group['occurrences'])
        self.assertEqual(largest['occurrences'], 100)
        self.assertEqual(len(largest['urls']), 100)

    def test_html_does_not_embed_json_or_duplicate_findings(self):
        data = {**empty_report(), 'mode': 'production-orchestrator', 'findings': self.findings(),
                'engines': [{'log': 'RAW_ENGINE_LOG_SENTINEL'}],
                'errors': [{'engine': 'zap', 'message': '<script>alert(1)</script>'}],
                'coverage': [{'engine': 'zap', 'status': 'error', 'reason': 'exit 1'}]}
        with tempfile.TemporaryDirectory() as temporary:
            result = write_report(data, temporary)
            page = (Path(temporary) / 'report.html').read_text()
            saved = json.loads((Path(temporary) / 'report.json').read_text())
        self.assertEqual(result['summary']['finding_groups'], 1)
        self.assertEqual(len(saved['findings']), 100)
        self.assertEqual(page.count('<article class="finding'), 1)
        self.assertNotIn('RAW_ENGINE_LOG_SENTINEL', page)
        self.assertNotIn('<script>', page)
        self.assertIn('&lt;script&gt;', page)
        self.assertIn('Проверка завершена не полностью', page)
        self.assertNotIn('<details open>', page)

    def test_failed_coverage_cannot_be_success_even_without_errors(self):
        data = {**empty_report(), 'mode': 'production-orchestrator', 'execution_status': 'completed',
                'coverage': [{'engine': 'zap', 'status': 'error', 'reason': 'exit 1'}]}
        self.assertEqual(execution_outcome(data), 'incomplete')
        with tempfile.TemporaryDirectory() as temporary, patch('auditkit.cli.run_pipeline', return_value=data), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            result = main(['run', '--url', 'https://example.test', '--authorized', '--out', temporary, '--ui', 'off'])
        self.assertEqual(result, 2)
        self.assertIn('ПРОВЕРКА НЕ ЗАВЕРШЕНА ПОЛНОСТЬЮ', output.getvalue())
        self.assertIn('exit 1', output.getvalue())

    def test_successful_pipeline_has_explicit_final_message(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch('auditkit.cli.run_pipeline', return_value={**empty_report(), 'mode': 'production-orchestrator'}), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(['run', '--url', 'https://example.test', '--authorized', '--out', temporary, '--ui', 'off']), 0)
        self.assertIn('ВСЕ ЗАПЛАНИРОВАННЫЕ ЭТАПЫ ВЫПОЛНЕНЫ', output.getvalue())

    def test_engine_failure_exposes_actionable_log_without_ansi(self):
        reason = failure_reason({'status': 'output-limit', 'exit_code': -15,
                                 'log': '\x1b[31m[ERR] could not dump raw http response\x1b[0m'})
        self.assertIn('2 MiB', reason)
        self.assertIn('could not dump', reason)
        self.assertNotIn('\x1b', reason)

    def test_nuclei_parse_errors_do_not_report_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            captures = Captures(root)
            def execute(*args, **kwargs):
                (root / 'nuclei.jsonl').write_text('')
                return {'status': 'completed', 'exit_code': 0, 'log': '[ERR] Could not execute raw input sample'}
            with patch('auditkit.engines.execute', side_effect=execute), \
                 patch.dict('os.environ', {'AUDIT_NUCLEI_TEMPLATES': temporary}):
                result = nuclei_scan('nuclei', captures, root, None)
            self.assertEqual(result['status'], 'error')
            self.assertTrue((root / 'config/.nuclei-ignore').is_file())


if __name__ == '__main__':
    unittest.main()
