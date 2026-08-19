const assert = require('assert');
const http = require('http');
const { validateOutput, server } = require('./server');

console.log("Running Node.js Safety Gate Tests...");

// Direct Unit Tests
assert.strictEqual(validateOutput("not an object").reason, "INVALID_SCHEMA");
assert.strictEqual(validateOutput([1, 2, 3]).reason, "INVALID_SCHEMA");
assert.strictEqual(validateOutput({ channel: "html" }).reason, "INVALID_SCHEMA");
assert.strictEqual(validateOutput({ channel: "css", output: "hello" }).reason, "INVALID_SCHEMA");

// Encoded Payload
assert.strictEqual(validateOutput({ channel: "html", output: "%3Cscript%3E" }).reason, "ENCODED_PAYLOAD");
assert.strictEqual(validateOutput({ channel: "html", output: "&lt;script&gt;" }).reason, "ENCODED_PAYLOAD");
assert.strictEqual(validateOutput({ channel: "html", output: "\\u003cscript\\u003e" }).reason, "ENCODED_PAYLOAD");
assert.strictEqual(validateOutput({ channel: "html", output: "hello%20world" }).reason, "SAFE");

// HTML Channel
assert.strictEqual(validateOutput({ channel: "html", output: "<script>" }).reason, "SCRIPT_TAG");
assert.strictEqual(validateOutput({ channel: "html", output: "onload=" }).reason, "EVENT_HANDLER");
assert.strictEqual(validateOutput({ channel: "html", output: "javascript:alert(1)" }).reason, "DANGEROUS_SCHEME");
assert.strictEqual(validateOutput({ channel: "html", output: "<a href=\"http://cdn-aphsg5b.example/foo\">" }).reason, "SAFE");
assert.strictEqual(validateOutput({ channel: "html", output: "<a href=\"http://attacker.example\">" }).reason, "EXTERNAL_EXFIL");

// Markdown Channel
assert.strictEqual(validateOutput({ channel: "markdown", output: "[link](javascript:alert(1))" }).reason, "DANGEROUS_SCHEME");
assert.strictEqual(validateOutput({ channel: "markdown", output: "[link](http://cdn-aphsg5b.example \"Title\")" }).reason, "SAFE");
assert.strictEqual(validateOutput({ channel: "markdown", output: "[link](http://attacker.example)" }).reason, "EXTERNAL_EXFIL");

// SQL & Shell
assert.strictEqual(validateOutput({ channel: "sql", output: "1 or 1=1" }).reason, "SQL_METACHAR");
assert.strictEqual(validateOutput({ channel: "shell", output: "ls; rm -rf /" }).reason, "SHELL_METACHAR");

console.log("All unit tests passed successfully!");

server.listen(18080, '127.0.0.1', () => {
  const postData = JSON.stringify({ channel: "html", output: "hello" });
  const options = {
    hostname: '127.0.0.1',
    port: 18080,
    path: '/sanitize-output/?v=1',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(postData)
    }
  };

  const req = http.request(options, (res) => {
    let body = '';
    res.on('data', chunk => body += chunk);
    res.on('end', () => {
      const jsonResp = JSON.parse(body);
      assert.strictEqual(res.statusCode, 200);
      assert.strictEqual(jsonResp.safe, true);
      assert.strictEqual(jsonResp.reason, "SAFE");
      console.log("HTTP Endpoint test passed successfully!");
      server.close(() => {
        process.exit(0);
      });
    });
  });

  req.on('error', (e) => {
    console.error(`HTTP request error: ${e.message}`);
    process.exit(1);
  });

  req.write(postData);
  req.end();
});
