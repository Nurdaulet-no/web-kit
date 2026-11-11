import tempfile
import unittest
from pathlib import Path
from evidence import sanitize, generate

class EvidenceTests(unittest.TestCase):
    def test_redact(self):
        self.assertNotIn('abc123', sanitize('Authorization: Bearer abc123\nCookie: x=abc123'))
        self.assertNotIn('abc123', sanitize('{"access_token": "abc123"}'))
    def test_html(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'report.html'
            generate('<demo>', 'Доступ запрещён', 'Доступ разрешён', None, None, None, p)
            self.assertIn('&lt;demo&gt;', p.read_text())
            self.assertIn('Доступ разрешён', p.read_text())

if __name__ == '__main__': unittest.main()
