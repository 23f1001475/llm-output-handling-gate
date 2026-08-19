import unittest
import urllib.request
import urllib.error
import json
import threading
import time
from server import HTTPServer, SafetyGateHandler, validate_output

class TestSafetyGateDirect(unittest.TestCase):
    def test_invalid_schema(self):
        # Body is not an object
        self.assertEqual(validate_output("not an object"), {"safe": False, "reason": "INVALID_SCHEMA"})
        self.assertEqual(validate_output([1, 2, 3]), {"safe": False, "reason": "INVALID_SCHEMA"})
        
        # Missing keys
        self.assertEqual(validate_output({"channel": "html"}), {"safe": False, "reason": "INVALID_SCHEMA"})
        self.assertEqual(validate_output({"output": "hello"}), {"safe": False, "reason": "INVALID_SCHEMA"})
        
        # Invalid channel
        self.assertEqual(validate_output({"channel": "css", "output": "hello"}), {"safe": False, "reason": "INVALID_SCHEMA"})
        
        # Non-string output
        self.assertEqual(validate_output({"channel": "html", "output": 123}), {"safe": False, "reason": "INVALID_SCHEMA"})
        
        # Output too long
        long_output = "a" * 20001
        self.assertEqual(validate_output({"channel": "html", "output": long_output}), {"safe": False, "reason": "INVALID_SCHEMA"})
        
        # Output exactly boundary (20000 characters) - should be safe/evaluable
        boundary_output = "a" * 20000
        self.assertEqual(validate_output({"channel": "html", "output": boundary_output})["reason"], "SAFE")

    def test_encoded_payload(self):
        # Trips on percent encoding
        self.assertEqual(
            validate_output({"channel": "html", "output": "%3Cscript%3E"}),
            {"safe": False, "reason": "ENCODED_PAYLOAD"}
        )
        # Trips on HTML entity encoding (named)
        self.assertEqual(
            validate_output({"channel": "html", "output": "&lt;script&gt;"}),
            {"safe": False, "reason": "ENCODED_PAYLOAD"}
        )
        # Trips on HTML entity encoding (decimal numeric)
        self.assertEqual(
            validate_output({"channel": "html", "output": "&#60;script&#62;"}),
            {"safe": False, "reason": "ENCODED_PAYLOAD"}
        )
        # Trips on HTML entity encoding (hex numeric)
        self.assertEqual(
            validate_output({"channel": "html", "output": "&#x3C;script&#x3E;"}),
            {"safe": False, "reason": "ENCODED_PAYLOAD"}
        )
        # Trips on Unicode escape
        self.assertEqual(
            validate_output({"channel": "html", "output": "\\u003cscript\\u003e"}),
            {"safe": False, "reason": "ENCODED_PAYLOAD"}
        )
        # Decoded differs but is benign -> should be SAFE
        self.assertEqual(
            validate_output({"channel": "html", "output": "hello%20world"}),
            {"safe": True, "reason": "SAFE"}
        )

    def test_html_channel(self):
        # SCRIPT_TAG
        self.assertEqual(validate_output({"channel": "html", "output": "<script>"})["reason"], "SCRIPT_TAG")
        self.assertEqual(validate_output({"channel": "html", "output": "<iframe src='x'>"})["reason"], "SCRIPT_TAG")
        self.assertEqual(validate_output({"channel": "html", "output": "<object>"})["reason"], "SCRIPT_TAG")
        self.assertEqual(validate_output({"channel": "html", "output": "<embed>"})["reason"], "SCRIPT_TAG")
        self.assertEqual(validate_output({"channel": "html", "output": "<script/src='foo'>"})["reason"], "SCRIPT_TAG")
        self.assertEqual(validate_output({"channel": "html", "output": "<iFrAmE>"})["reason"], "SCRIPT_TAG")
        # Benign tags or closing tags
        self.assertEqual(validate_output({"channel": "html", "output": "<div>"})["reason"], "SAFE")
        self.assertEqual(validate_output({"channel": "html", "output": "</script>"})["reason"], "SAFE")
        self.assertEqual(validate_output({"channel": "html", "output": "<scripting>"})["reason"], "SAFE")

        # EVENT_HANDLER
        self.assertEqual(validate_output({"channel": "html", "output": "onload="})["reason"], "EVENT_HANDLER")
        self.assertEqual(validate_output({"channel": "html", "output": "onclick = 'alert(1)'"})["reason"], "EVENT_HANDLER")
        self.assertEqual(validate_output({"channel": "html", "output": "onerror\n="})["reason"], "EVENT_HANDLER")
        self.assertEqual(validate_output({"channel": "html", "output": "button.onclick="})["reason"], "EVENT_HANDLER")
        self.assertEqual(validate_output({"channel": "html", "output": "one=1"})["reason"], "SAFE")

        # DANGEROUS_SCHEME (html context)
        self.assertEqual(validate_output({"channel": "html", "output": "javascript:alert(1)"})["reason"], "DANGEROUS_SCHEME")
        self.assertEqual(validate_output({"channel": "html", "output": "javaScript  :alert(1)"})["reason"], "DANGEROUS_SCHEME")
        self.assertEqual(validate_output({"channel": "html", "output": "data:text/html,abc"})["reason"], "DANGEROUS_SCHEME")
        self.assertEqual(validate_output({"channel": "html", "output": "vbscript:msgbox"})["reason"], "DANGEROUS_SCHEME")
        self.assertEqual(validate_output({"channel": "html", "output": "myjavascript:alert(1)"})["reason"], "SAFE") # Word boundaries prevent match
        self.assertEqual(validate_output({"channel": "html", "output": "metadata:abc"})["reason"], "SAFE") # Word boundaries prevent match
        
        # Quoted URLs scheme check
        self.assertEqual(validate_output({"channel": "html", "output": "<img src=\"ftp://example.com\">"})["reason"], "DANGEROUS_SCHEME")
        self.assertEqual(validate_output({"channel": "html", "output": "<a href='mailto:test@example.com'>"})["reason"], "DANGEROUS_SCHEME")
        self.assertEqual(validate_output({"channel": "html", "output": "<a href=\"/local/page\">"})["reason"], "SAFE")

        # EXTERNAL_EXFIL (html context)
        self.assertEqual(validate_output({"channel": "html", "output": "<a href=\"http://cdn-aphsg5b.example/foo\">"})["reason"], "SAFE")
        self.assertEqual(validate_output({"channel": "html", "output": "<a href=\"https://app-2b0ft0g.example\">"})["reason"], "SAFE")
        self.assertEqual(validate_output({"channel": "html", "output": "<a href=\"//cdn-aphsg5b.example\">"})["reason"], "SAFE")
        
        self.assertEqual(validate_output({"channel": "html", "output": "<a href=\"http://attacker.example\">"})["reason"], "EXTERNAL_EXFIL")
        self.assertEqual(validate_output({"channel": "html", "output": "<a href=\"http://sub.cdn-aphsg5b.example\">"})["reason"], "EXTERNAL_EXFIL")
        self.assertEqual(validate_output({"channel": "html", "output": "<a href=\"http://cdn-aphsg5b.example.attacker.example\">"})["reason"], "EXTERNAL_EXFIL")
        self.assertEqual(validate_output({"channel": "html", "output": "<a href=\"http://cdn-aphsg5b.example-attacker.example\">"})["reason"], "EXTERNAL_EXFIL")
        self.assertEqual(validate_output({"channel": "html", "output": "<a href=\"https://allowed@attacker.example/\">"})["reason"], "EXTERNAL_EXFIL")
        self.assertEqual(validate_output({"channel": "html", "output": "<a href=\"https://cdn-aphsg5b.example/?next=https://attacker.example/\">"})["reason"], "SAFE")

    def test_markdown_channel(self):
        # DANGEROUS_SCHEME
        self.assertEqual(validate_output({"channel": "markdown", "output": "[link](javascript:alert(1))"})["reason"], "DANGEROUS_SCHEME")
        self.assertEqual(validate_output({"channel": "markdown", "output": "[link](ftp://example.com)"})["reason"], "DANGEROUS_SCHEME")
        self.assertEqual(validate_output({"channel": "markdown", "output": "[link](/local/page)"})["reason"], "SAFE")

        # Nested parentheses inside markdown URL should extract and validate properly
        self.assertEqual(validate_output({"channel": "markdown", "output": "[link](http://cdn-aphsg5b.example/foo(bar))"})["reason"], "SAFE")
        self.assertEqual(validate_output({"channel": "markdown", "output": "[link](http://attacker.example/foo(bar))"})["reason"], "EXTERNAL_EXFIL")

        # EXTERNAL_EXFIL
        self.assertEqual(validate_output({"channel": "markdown", "output": "[link](http://cdn-aphsg5b.example)"})["reason"], "SAFE")
        self.assertEqual(validate_output({"channel": "markdown", "output": "[link](http://attacker.example)"})["reason"], "EXTERNAL_EXFIL")
        self.assertEqual(validate_output({"channel": "markdown", "output": "[link](//cdn-aphsg5b.example)"})["reason"], "SAFE")
        self.assertEqual(validate_output({"channel": "markdown", "output": "[link](//attacker.example)"})["reason"], "EXTERNAL_EXFIL")

    def test_url_channel(self):
        # DANGEROUS_SCHEME
        self.assertEqual(validate_output({"channel": "url", "output": "javascript:alert(1)"})["reason"], "DANGEROUS_SCHEME")
        self.assertEqual(validate_output({"channel": "url", "output": "ftp://example.com"})["reason"], "DANGEROUS_SCHEME")
        self.assertEqual(validate_output({"channel": "url", "output": "/local/page"})["reason"], "SAFE")

        # EXTERNAL_EXFIL
        self.assertEqual(validate_output({"channel": "url", "output": "  http://cdn-aphsg5b.example  "})["reason"], "SAFE") # trim handles whitespace
        self.assertEqual(validate_output({"channel": "url", "output": "http://attacker.example"})["reason"], "EXTERNAL_EXFIL")

    def test_sql_channel(self):
        # SQL_METACHAR
        self.assertEqual(validate_output({"channel": "sql", "output": "SELECT * FROM users WHERE name = 'admin'"})["reason"], "SQL_METACHAR")
        self.assertEqual(validate_output({"channel": "sql", "output": "SELECT * FROM users; DROP TABLE users"})["reason"], "SQL_METACHAR")
        self.assertEqual(validate_output({"channel": "sql", "output": "SELECT * FROM users -- comment"})["reason"], "SQL_METACHAR")
        self.assertEqual(validate_output({"channel": "sql", "output": "SELECT /* comment */ * FROM users"})["reason"], "SQL_METACHAR")
        self.assertEqual(validate_output({"channel": "sql", "output": "SELECT * FROM users union select null"})["reason"], "SQL_METACHAR")
        self.assertEqual(validate_output({"channel": "sql", "output": "1 or 1=1"})["reason"], "SQL_METACHAR")
        self.assertEqual(validate_output({"channel": "sql", "output": "1 OR  1 = 1"})["reason"], "SQL_METACHAR")
        
        # Benign SQL words / patterns
        self.assertEqual(validate_output({"channel": "sql", "output": "SELECT onion FROM users"})["reason"], "SAFE")
        self.assertEqual(validate_output({"channel": "sql", "output": "SELECT 1 for 1=1"})["reason"], "SAFE")

    def test_shell_channel(self):
        # SHELL_METACHAR
        self.assertEqual(validate_output({"channel": "shell", "output": "ls; rm -rf /"})["reason"], "SHELL_METACHAR")
        self.assertEqual(validate_output({"channel": "shell", "output": "ls && rm -rf /"})["reason"], "SHELL_METACHAR")
        self.assertEqual(validate_output({"channel": "shell", "output": "ls | grep test"})["reason"], "SHELL_METACHAR")
        self.assertEqual(validate_output({"channel": "shell", "output": "echo `id`"})["reason"], "SHELL_METACHAR")
        self.assertEqual(validate_output({"channel": "shell", "output": "cat < /etc/passwd"})["reason"], "SHELL_METACHAR")
        self.assertEqual(validate_output({"channel": "shell", "output": "echo > file.txt"})["reason"], "SHELL_METACHAR")
        self.assertEqual(validate_output({"channel": "shell", "output": "echo $(whoami)"})["reason"], "SHELL_METACHAR")
        self.assertEqual(validate_output({"channel": "shell", "output": "echo ${USER}"})["reason"], "SHELL_METACHAR")
        
        # Benign shell commands
        self.assertEqual(validate_output({"channel": "shell", "output": "echo 'hello world'"})["reason"], "SAFE")


class TestSafetyGateHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = 18080
        cls.server = HTTPServer(('127.0.0.1', cls.port), SafetyGateHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(0.5)  # Wait for server to start

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join()

    def send_post(self, payload_dict, is_json=True):
        url = f"http://127.0.0.1:{self.port}/sanitize-output"
        if is_json:
            data = json.dumps(payload_dict).encode('utf-8')
            headers = {'Content-Type': 'application/json'}
        else:
            data = payload_dict # raw bytes
            headers = {'Content-Type': 'text/plain'}
            
        req = urllib.request.Request(url, data=data, headers=headers, method='POST')
        try:
            with urllib.request.urlopen(req) as response:
                status = response.status
                body = response.read().decode('utf-8')
                return status, json.loads(body)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode('utf-8')

    def test_http_endpoint_success(self):
        status, resp = self.send_post({"channel": "html", "output": "hello"})
        self.assertEqual(status, 200)
        self.assertEqual(resp, {"safe": True, "reason": "SAFE"})

    def test_http_endpoint_invalid_schema_json(self):
        # Invalid JSON syntax
        status, resp = self.send_post(b"{invalid-json}", is_json=False)
        self.assertEqual(status, 200)
        self.assertEqual(resp, {"safe": False, "reason": "INVALID_SCHEMA"})

    def test_http_endpoint_invalid_schema_structure(self):
        # JSON List instead of object
        status, resp = self.send_post([{"channel": "html", "output": "hello"}])
        self.assertEqual(status, 200)
        self.assertEqual(resp, {"safe": False, "reason": "INVALID_SCHEMA"})

    def test_http_endpoint_404_not_found(self):
        # Wrong path
        url = f"http://127.0.0.1:{self.port}/invalid-path"
        req = urllib.request.Request(url, data=b"", method='POST')
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
