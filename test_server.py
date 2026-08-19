import unittest
import urllib.request
import urllib.error
import json
import threading
import time
from server import HTTPServer, SafetyGateHandler, validate_output

class TestSafetyGateDirect(unittest.TestCase):
    def test_invalid_schema(self):
        self.assertEqual(validate_output("not an object"), {"safe": False, "reason": "INVALID_SCHEMA"})
        self.assertEqual(validate_output([1, 2, 3]), {"safe": False, "reason": "INVALID_SCHEMA"})
        self.assertEqual(validate_output({"channel": "html"}), {"safe": False, "reason": "INVALID_SCHEMA"})
        self.assertEqual(validate_output({"output": "hello"}), {"safe": False, "reason": "INVALID_SCHEMA"})
        self.assertEqual(validate_output({"channel": "css", "output": "hello"}), {"safe": False, "reason": "INVALID_SCHEMA"})
        self.assertEqual(validate_output({"channel": "html", "output": 123}), {"safe": False, "reason": "INVALID_SCHEMA"})
        
        long_output = "a" * 20001
        self.assertEqual(validate_output({"channel": "html", "output": long_output}), {"safe": False, "reason": "INVALID_SCHEMA"})
        
        boundary_output = "a" * 20000
        self.assertEqual(validate_output({"channel": "html", "output": boundary_output})["reason"], "SAFE")

    def test_encoded_payload(self):
        self.assertEqual(validate_output({"channel": "html", "output": "%3Cscript%3E"}), {"safe": False, "reason": "ENCODED_PAYLOAD"})
        self.assertEqual(validate_output({"channel": "html", "output": "&lt;script&gt;"}), {"safe": False, "reason": "ENCODED_PAYLOAD"})
        self.assertEqual(validate_output({"channel": "html", "output": "&#60;script&#62;"}), {"safe": False, "reason": "ENCODED_PAYLOAD"})
        self.assertEqual(validate_output({"channel": "html", "output": "&#x3C;script&#x3E;"}), {"safe": False, "reason": "ENCODED_PAYLOAD"})
        self.assertEqual(validate_output({"channel": "html", "output": "\\u003cscript\\u003e"}), {"safe": False, "reason": "ENCODED_PAYLOAD"})
        self.assertEqual(validate_output({"channel": "html", "output": "hello%20world"}), {"safe": True, "reason": "SAFE"})

    def test_html_channel(self):
        self.assertEqual(validate_output({"channel": "html", "output": "<script>"})["reason"], "SCRIPT_TAG")
        self.assertEqual(validate_output({"channel": "html", "output": "<iframe src='x'>"})["reason"], "SCRIPT_TAG")
        self.assertEqual(validate_output({"channel": "html", "output": "<object>"})["reason"], "SCRIPT_TAG")
        self.assertEqual(validate_output({"channel": "html", "output": "<embed>"})["reason"], "SCRIPT_TAG")
        self.assertEqual(validate_output({"channel": "html", "output": "<script/src='foo'>"})["reason"], "SCRIPT_TAG")
        self.assertEqual(validate_output({"channel": "html", "output": "<iFrAmE>"})["reason"], "SCRIPT_TAG")
        self.assertEqual(validate_output({"channel": "html", "output": "<div>"})["reason"], "SAFE")
        self.assertEqual(validate_output({"channel": "html", "output": "</script>"})["reason"], "SAFE")

        self.assertEqual(validate_output({"channel": "html", "output": "onload="})["reason"], "EVENT_HANDLER")
        self.assertEqual(validate_output({"channel": "html", "output": "onclick = 'alert(1)'"})["reason"], "EVENT_HANDLER")
        self.assertEqual(validate_output({"channel": "html", "output": "onerror\n="})["reason"], "EVENT_HANDLER")

        self.assertEqual(validate_output({"channel": "html", "output": "javascript:alert(1)"})["reason"], "DANGEROUS_SCHEME")
        self.assertEqual(validate_output({"channel": "html", "output": "data:text/html,abc"})["reason"], "DANGEROUS_SCHEME")
        self.assertEqual(validate_output({"channel": "html", "output": "vbscript:msgbox"})["reason"], "DANGEROUS_SCHEME")
        
        self.assertEqual(validate_output({"channel": "html", "output": "<img src=\"ftp://example.com\">"})["reason"], "DANGEROUS_SCHEME")
        self.assertEqual(validate_output({"channel": "html", "output": "<a href=\"/local/page\">"})["reason"], "SAFE")

        self.assertEqual(validate_output({"channel": "html", "output": "<a href=\"http://cdn-aphsg5b.example/foo\">"})["reason"], "SAFE")
        self.assertEqual(validate_output({"channel": "html", "output": "<a href=\"https://app-2b0ft0g.example\">"})["reason"], "SAFE")
        self.assertEqual(validate_output({"channel": "html", "output": "<a href=\"http://cdn-aphsg5b.example.\">"})["reason"], "SAFE") # trailing dot handled
        
        self.assertEqual(validate_output({"channel": "html", "output": "<a href=\"http://attacker.example\">"})["reason"], "EXTERNAL_EXFIL")

    def test_markdown_channel(self):
        self.assertEqual(validate_output({"channel": "markdown", "output": "[link](javascript:alert(1))"})["reason"], "DANGEROUS_SCHEME")
        self.assertEqual(validate_output({"channel": "markdown", "output": "[link](ftp://example.com)"})["reason"], "DANGEROUS_SCHEME")
        self.assertEqual(validate_output({"channel": "markdown", "output": "[link](/local/page)"})["reason"], "SAFE")
        self.assertEqual(validate_output({"channel": "markdown", "output": "[link](http://cdn-aphsg5b.example \"Title\")"})["reason"], "SAFE") # title handled
        self.assertEqual(validate_output({"channel": "markdown", "output": "[link](http://attacker.example \"Title\")"})["reason"], "EXTERNAL_EXFIL")

    def test_url_channel(self):
        self.assertEqual(validate_output({"channel": "url", "output": "javascript:alert(1)"})["reason"], "DANGEROUS_SCHEME")
        self.assertEqual(validate_output({"channel": "url", "output": "http://cdn-aphsg5b.example"})["reason"], "SAFE")
        self.assertEqual(validate_output({"channel": "url", "output": "http://attacker.example"})["reason"], "EXTERNAL_EXFIL")

    def test_sql_channel(self):
        self.assertEqual(validate_output({"channel": "sql", "output": "SELECT * FROM users WHERE name = 'admin'"})["reason"], "SQL_METACHAR")
        self.assertEqual(validate_output({"channel": "sql", "output": "1 or(1=1)"})["reason"], "SQL_METACHAR")

    def test_shell_channel(self):
        self.assertEqual(validate_output({"channel": "shell", "output": "ls; rm -rf /"})["reason"], "SHELL_METACHAR")


class TestSafetyGateHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = 18081
        cls.server = HTTPServer(('127.0.0.1', cls.port), SafetyGateHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join()

    def send_post(self, path="/sanitize-output", data_bytes=b"", headers=None):
        url = f"http://127.0.0.1:{self.port}{path}"
        if headers is None:
            headers = {'Content-Type': 'application/json'}
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method='POST')
        try:
            with urllib.request.urlopen(req) as response:
                return response.status, json.loads(response.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode('utf-8')

    def test_http_endpoint_query_string_and_trailing_slash(self):
        payload = json.dumps({"channel": "html", "output": "hello"}).encode('utf-8')
        status1, resp1 = self.send_post("/sanitize-output/", payload)
        self.assertEqual(status1, 200)
        self.assertEqual(resp1, {"safe": True, "reason": "SAFE"})

        status2, resp2 = self.send_post("/sanitize-output?api_version=1", payload)
        self.assertEqual(status2, 200)
        self.assertEqual(resp2, {"safe": True, "reason": "SAFE"})

    def test_http_endpoint_cors_options(self):
        url = f"http://127.0.0.1:{self.port}/sanitize-output"
        req = urllib.request.Request(url, method='OPTIONS')
        with urllib.request.urlopen(req) as response:
            self.assertEqual(response.status, 200)
            self.assertIn('Access-Control-Allow-Origin', response.headers)

    def test_http_endpoint_bom_json(self):
        # UTF-8 BOM prefix
        payload = b'\xef\xbb\xbf' + json.dumps({"channel": "html", "output": "hello"}).encode('utf-8')
        status, resp = self.send_post("/sanitize-output", payload)
        self.assertEqual(status, 200)
        self.assertEqual(resp, {"safe": True, "reason": "SAFE"})


if __name__ == "__main__":
    unittest.main()
