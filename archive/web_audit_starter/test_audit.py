import tempfile
import unittest
from pathlib import Path
from audit import validate_url, PageParser, write_report

class AuditTests(unittest.TestCase):
    def test_reject_nonhttps(self):
        with self.assertRaises(ValueError):
            validate_url('http://example.com', False)
    def test_reject_credentials(self):
        with self.assertRaises(ValueError):
            validate_url('https://user:pass@example.com/', False)
    def test_html(self):
        p = PageParser()
        p.feed('<title>Lab</title><form method="post"><input></form><script></script>')
        self.assertEqual(''.join(p.title_text), 'Lab')
        self.assertEqual(p.forms[0]['method'], 'POST')
        self.assertEqual(p.scripts, 1)
    def test_write(self):
        sample = {'target': 'https://example.com/', 'timestamp_utc': 'today', 'status': 200, 'content_type': 'text/html', 'title': 'Example', 'form_count': 0, 'script_tag_count': 0, 'security_headers': {}, 'findings': [], 'limitations': 'safe'}
        with tempfile.TemporaryDirectory() as p:
            write_report(sample, p)
            self.assertTrue((Path(p) / 'report.md').is_file())
            self.assertTrue((Path(p) / 'report.json').is_file())

if __name__ == '__main__':
    unittest.main()
