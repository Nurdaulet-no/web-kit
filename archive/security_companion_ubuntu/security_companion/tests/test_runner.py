import pathlib,sys,tempfile,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import runner
class TestRunner(unittest.TestCase):
    def test_scope(self):
        self.assertTrue(runner.local_target('http://127.0.0.1:8765/'))
        self.assertFalse(runner.local_target('https://example.org/'))
        self.assertFalse(runner.local_target('http://localhost.evil.example/'))
    def test_title(self): self.assertEqual(runner.extract_title(b'<title>Test</title>'),'Test')
    def test_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=runner.save_report(pathlib.Path(tmp),{'url':'http://localhost','checks':{},'status':200})
            self.assertTrue(p.exists()); self.assertTrue((pathlib.Path(tmp)/'report.json').exists())
    def test_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=pathlib.Path(tmp)/'x.jsonl';p.write_text('{"info":{"name":"Mock finding","severity":"info"},"matched-at":"http://127.0.0.1"}\n')
            self.assertEqual(len(runner.import_findings(p)),1)
if __name__=='__main__': unittest.main()
