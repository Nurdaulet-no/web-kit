import pathlib,tempfile,unittest
from runner import local_url,load_tool_report,write_report
class Tests(unittest.TestCase):
    def test_scope(self):
        self.assertTrue(local_url('http://127.0.0.1:8765/'))
        self.assertFalse(local_url('http://example.com:8765/'))
        self.assertFalse(local_url('http://127.0.0.1:80/'))
    def test_import(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'nuclei.jsonl';p.write_text('{"name":"sample"}\n')
            self.assertEqual(load_tool_report(p)['entries'],1)
    def test_report(self):
        with tempfile.TemporaryDirectory() as d:
            write_report(d,None)
            self.assertTrue((pathlib.Path(d)/'report.html').exists())
if __name__=='__main__':unittest.main()
