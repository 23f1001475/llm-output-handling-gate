import json
import re
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys
import os

# Helper decoding functions
def html_decode(text):
    named_entities = {
        '&lt;': '<', '&lt': '<',
        '&gt;': '>', '&gt': '>',
        '&quot;': '"', '&quot': '"',
        '&apos;': "'", '&apos': "'",
        '&amp;': '&', '&amp': '&'
    }
    def replace_entity(match):
        entity = match.group(0)
        lower_entity = entity.lower()
        if lower_entity in named_entities:
            return named_entities[lower_entity]
        dec_match = re.match(r'^&#(\d+);?$', entity)
        if dec_match:
            try:
                return chr(int(dec_match.group(1)))
            except ValueError:
                return entity
        hex_match = re.match(r'^&#[xX]([0-9a-fA-F]+);?$', entity)
        if hex_match:
            try:
                return chr(int(hex_match.group(1), 16))
            except ValueError:
                return entity
        return entity

    pattern = r'&(?:lt|gt|quot|apos|amp);?|&#\d+;?|&#[xX][0-9a-fA-F]+;?'
    return re.sub(pattern, replace_entity, text, flags=re.IGNORECASE)


def unicode_decode(text):
    def replace_unicode(match):
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)
            
    return re.sub(r'\\u([0-9a-fA-F]{4})', replace_unicode, text)


def decode_once(text):
    # 1. Percent-escapes
    try:
        text_1 = urllib.parse.unquote(text)
    except Exception:
        text_1 = text
    # 2. HTML entities
    text_2 = html_decode(text_1)
    # 3. Unicode escapes
    text_3 = unicode_decode(text_2)
    return text_3


# URL Extraction Helpers
def extract_markdown_urls(text):
    targets = []
    start_idx = 0
    while True:
        idx = text.find('](', start_idx)
        if idx == -1:
            break
        paren_count = 1
        url_chars = []
        curr = idx + 2
        while curr < len(text):
            char = text[curr]
            if char == '(':
                paren_count += 1
                url_chars.append(char)
            elif char == ')':
                paren_count -= 1
                if paren_count == 0:
                    break
                else:
                    url_chars.append(char)
            else:
                url_chars.append(char)
            curr += 1
        raw_target = "".join(url_chars).strip()
        if raw_target.startswith('<') and raw_target.endswith('>'):
            target = raw_target[1:-1].strip()
        else:
            tokens = raw_target.split()
            target = tokens[0] if tokens else ""
        if target:
            targets.append(target)
        start_idx = idx + 2
    return targets


# General URL safety checkers
def check_urls(urls, text):
    # DANGEROUS_SCHEME Check 1: General text scheme match
    if re.search(r'(?i)\b(javascript|data|vbscript)\s*:', text):
        return "DANGEROUS_SCHEME"
        
    # DANGEROUS_SCHEME Check 2: Extracted URLs scheme check
    for url in urls:
        url_clean = url.strip().replace('\\', '/')
        if url_clean.startswith('//'):
            url_clean = 'https:' + url_clean
            
        scheme_match = re.match(r'^([a-zA-Z][a-zA-Z0-9.+-]*):', url_clean)
        if scheme_match:
            scheme = scheme_match.group(1).lower()
            if scheme not in ('http', 'https'):
                return "DANGEROUS_SCHEME"

    # EXTERNAL_EXFIL Check: Extracted URLs hostname check
    allowed_hosts = {'cdn-aphsg5b.example', 'app-2b0ft0g.example'}
    for url in urls:
        url_clean = url.strip().replace('\\', '/')
        if url_clean.startswith('//'):
            url_clean = 'https:' + url_clean
            
        scheme_match = re.match(r'^([a-zA-Z][a-zA-Z0-9.+-]*):', url_clean)
        if scheme_match:
            scheme = scheme_match.group(1).lower()
            if scheme in ('http', 'https'):
                try:
                    parsed = urllib.parse.urlparse(url_clean)
                    hostname = parsed.hostname
                except Exception:
                    return "EXTERNAL_EXFIL"
                
                if not hostname:
                    return "EXTERNAL_EXFIL"
                
                hostname_lower = hostname.rstrip('.').lower()
                if hostname_lower not in allowed_hosts:
                    return "EXTERNAL_EXFIL"
                    
    return "SAFE"


# Channel validation rules
def check_html(text):
    # 1. SCRIPT_TAG
    if re.search(r'(?i)<\s*(script|iframe|object|embed)(?![a-zA-Z0-9_-])', text):
        return "SCRIPT_TAG"
        
    # 2. EVENT_HANDLER
    if re.search(r'(?i)\bon[a-zA-Z0-9_-]+\s*=', text):
        return "EVENT_HANDLER"
        
    # 3. DANGEROUS_SCHEME & EXTERNAL_EXFIL
    urls = []
    for match in re.finditer(r'(?i)\b(?:src|href)\s*=\s*(["\'])(.*?)\1', text, re.DOTALL):
        urls.append(match.group(2))
        
    return check_urls(urls, text)


def check_markdown(text):
    urls = extract_markdown_urls(text)
    return check_urls(urls, text)


def check_url_channel(text):
    raw_url = text.strip()
    if raw_url.startswith('<') and raw_url.endswith('>'):
        raw_url = raw_url[1:-1].strip()
    tokens = raw_url.split()
    url_target = tokens[0] if tokens else ""
    urls = [url_target] if url_target else []
    return check_urls(urls, text)


def check_sql(text):
    for metachar in ["'", '"', ';', '--', '/*']:
        if metachar in text:
            return "SQL_METACHAR"
    if re.search(r'\bunion\b', text, re.IGNORECASE):
        return "SQL_METACHAR"
    if re.search(r'(?i)\bor[\s(]*1\s*=\s*1\b', text):
        return "SQL_METACHAR"
    return "SAFE"


def check_shell(text):
    for metachar in [';', '&', '|', '`', '<', '>', '$(', '${']:
        if metachar in text:
            return "SHELL_METACHAR"
    return "SAFE"


def run_channel_rules(channel, text):
    if channel == "html":
        return check_html(text)
    elif channel == "markdown":
        return check_markdown(text)
    elif channel == "url":
        return check_url_channel(text)
    elif channel == "sql":
        return check_sql(text)
    elif channel == "shell":
        return check_shell(text)
    return "INVALID_SCHEMA"


def check_encoded_payload(channel, original_output):
    decoded = decode_once(original_output)
    if decoded != original_output:
        trip_reason = run_channel_rules(channel, decoded)
        if trip_reason != "SAFE":
            return "ENCODED_PAYLOAD"
    return "SAFE"


def validate_output(body):
    if not isinstance(body, dict):
        return {"safe": False, "reason": "INVALID_SCHEMA"}
        
    if "channel" not in body or "output" not in body:
        return {"safe": False, "reason": "INVALID_SCHEMA"}
        
    channel = body["channel"]
    output = body["output"]
    
    if channel not in ["html", "markdown", "url", "sql", "shell"]:
        return {"safe": False, "reason": "INVALID_SCHEMA"}
        
    if not isinstance(output, str):
        return {"safe": False, "reason": "INVALID_SCHEMA"}
        
    if len(output) > 20000:
        return {"safe": False, "reason": "INVALID_SCHEMA"}
        
    encoded_reason = check_encoded_payload(channel, output)
    if encoded_reason != "SAFE":
        return {"safe": False, "reason": "ENCODED_PAYLOAD"}
        
    channel_reason = run_channel_rules(channel, output)
    if channel_reason != "SAFE":
        return {"safe": False, "reason": channel_reason}
        
    return {"safe": True, "reason": "SAFE"}


class SafetyGateHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS, HEAD')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()

    def do_GET(self):
        self.do_POST()

    def do_HEAD(self):
        self.do_POST()

    def do_POST(self):
        clean_path = self.path.split('?')[0].rstrip('/')
        if clean_path not in ["/sanitize-output", ""]:
            self.send_response(404)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Not Found")
            return

        content_length_hdr = self.headers.get('Content-Length')
        if content_length_hdr is not None:
            try:
                length = int(content_length_hdr)
                body_bytes = self.rfile.read(length)
            except Exception:
                body_bytes = b""
        else:
            body_bytes = b""

        try:
            body_str = body_bytes.decode('utf-8-sig', errors='replace')
            body = json.loads(body_str)
        except Exception:
            body = None

        response_data = validate_output(body)
        response_bytes = json.dumps(response_data).encode('utf-8')
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Length', str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)


def run_server(port=8080):
    server_address = ('0.0.0.0', port)
    httpd = HTTPServer(server_address, SafetyGateHandler)
    print(f"Safety Gate Server running on port {port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        httpd.server_close()


if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    run_server(port)
