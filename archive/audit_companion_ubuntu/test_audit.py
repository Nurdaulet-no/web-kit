import tempfile
import threading
import unittest
from pathlib import Path
from http.server import ThreadingHTTPServer
from audit import LabHandler, request, write_report

class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv=ThreadingHTTPServer(('127.0.0.1',0),LabHandler)
        cls.thread=threading.Thread(target=cls.srv.serve_forever,daemon=True)
        cls.thread.start()
    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
    def test_local_idor_fixture(self):
        url=f'http://127.0.0.1:{self.srv.server_port}/api/profile/101'
        a=request(url, {'X-Lab-User':'A'})
        b=request(url, {'X-Lab-User':'B'})
        self.assertEqual(a[0],200)
        self.assertEqual(b[0],200)
        self.assertIn('OWNED_BY_A_TEST_DATA',b[2])
    def test_404(self):
        url=f'http://127.0.0.1:{self.srv.server_port}/missing'
        self.assertEqual(request(url)[0],404)
    def test_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_report(Path(tmp),'demo',['A < B'], {'data':'<script>alert(1)</script>'})
            output=(Path(tmp)/'report.html').read_text()
            self.assertIn('A &lt; B', output)
            self.assertNotIn('<script>',output)

if __name__=='__main__':unittest.main()
