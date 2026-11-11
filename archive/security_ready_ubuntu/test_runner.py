import tempfile
import unittest
from pathlib import Path
from runner import validate_target, analyse, write_result

class RunnerTests(unittest.TestCase):
    def test_urls(self):
        self.assertEqual(validate_target('https://example.com'), 'https://example.com/')
        with self.assertRaises(ValueError): validate_target('ftp://example.com')
        with self.assertRaises(ValueError): validate_target('http://example.com')
        with self.assertRaises(ValueError): validate_target('http://example.com', local_only=True)
    def test_header_notes(self):
        found = analyse({'url':'https://example.com/','headers':{}})
        self.assertTrue(any('HSTS' in x for x in found))
    def test_reports(self):
        with tempfile.TemporaryDirectory() as td:
            write_result(dict(url='https://example.com/', status=200,seconds=0.3,sample_length_bytes=10,headers={},preview='',notes=[]), Path(td))
            self.assertTrue((Path(td)/'result.json').exists())
            self.assertTrue((Path(td)/'report.md').exists())

if __name__ == '__main__': unittest.main()
