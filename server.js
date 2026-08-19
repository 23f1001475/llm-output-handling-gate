const http = require('http');
const { URL } = require('url');

// Helper decoding functions
function htmlDecode(text) {
  const namedEntities = {
    '&lt;': '<', '&lt': '<',
    '&gt;': '>', '&gt': '>',
    '&quot;': '"', '&quot': '"',
    '&apos;': "'", '&apos': "'",
    '&amp;': '&', '&amp': '&'
  };

  return text.replace(/&(?:lt|gt|quot|apos|amp);?|&#\d+;?|&#[xX][0-9a-fA-F]+;?/gi, (match) => {
    const lower = match.toLowerCase();
    if (namedEntities[lower]) {
      return namedEntities[lower];
    }
    const decMatch = match.match(/^&#(\d+);?$/);
    if (decMatch) {
      try {
        return String.fromCharCode(parseInt(decMatch[1], 10));
      } catch (e) {
        return match;
      }
    }
    const hexMatch = match.match(/^&#[xX]([0-9a-fA-F]+);?$/);
    if (hexMatch) {
      try {
        return String.fromCharCode(parseInt(hexMatch[1], 16));
      } catch (e) {
        return match;
      }
    }
    return match;
  });
}

function unicodeDecode(text) {
  return text.replace(/\\u([0-9a-fA-F]{4})/g, (match, grp) => {
    try {
      return String.fromCharCode(parseInt(grp, 16));
    } catch (e) {
      return match;
    }
  });
}

function decodeOnce(text) {
  let t1 = text;
  try {
    t1 = decodeURIComponent(text);
  } catch (e) {
    t1 = text;
  }
  const t2 = htmlDecode(t1);
  const t3 = unicodeDecode(t2);
  return t3;
}

// Markdown URL Extractor
function extractMarkdownUrls(text) {
  const targets = [];
  let startIdx = 0;
  while (true) {
    const idx = text.indexOf('](', startIdx);
    if (idx === -1) break;
    let parenCount = 1;
    let urlChars = [];
    let curr = idx + 2;
    while (curr < text.length) {
      const char = text[curr];
      if (char === '(') {
        parenCount++;
        urlChars.push(char);
      } else if (char === ')') {
        parenCount--;
        if (parenCount === 0) break;
        else urlChars.push(char);
      } else {
        urlChars.push(char);
      }
      curr++;
    }
    let rawTarget = urlChars.join('').trim();
    let target = '';
    if (rawTarget.startsWith('<') && rawTarget.endsWith('>')) {
      target = rawTarget.slice(1, -1).trim();
    } else {
      const tokens = rawTarget.split(/\s+/);
      target = tokens[0] || '';
    }
    if (target) {
      targets.push(target);
    }
    startIdx = idx + 2;
  }
  return targets;
}

// General URL safety checkers
function checkUrls(urls, text) {
  // DANGEROUS_SCHEME Check 1: General text scheme match
  if (/\b(javascript|data|vbscript)\s*:/i.test(text)) {
    return "DANGEROUS_SCHEME";
  }

  // DANGEROUS_SCHEME Check 2: Extracted URLs scheme check
  for (let rawUrl of urls) {
    let urlClean = rawUrl.trim().replace(/\\/g, '/');
    if (urlClean.startsWith('//')) {
      urlClean = 'https:' + urlClean;
    }
    const schemeMatch = urlClean.match(/^([a-zA-Z][a-zA-Z0-9.+-]*):/);
    if (schemeMatch) {
      const scheme = schemeMatch[1].toLowerCase();
      if (scheme !== 'http' && scheme !== 'https') {
        return "DANGEROUS_SCHEME";
      }
    }
  }

  // EXTERNAL_EXFIL Check: Extracted URLs hostname check
  const allowedHosts = new Set(['cdn-aphsg5b.example', 'app-2b0ft0g.example']);
  for (let rawUrl of urls) {
    let urlClean = rawUrl.trim().replace(/\\/g, '/');
    if (urlClean.startsWith('//')) {
      urlClean = 'https:' + urlClean;
    }
    const schemeMatch = urlClean.match(/^([a-zA-Z][a-zA-Z0-9.+-]*):/);
    if (schemeMatch) {
      const scheme = schemeMatch[1].toLowerCase();
      if (scheme === 'http' || scheme === 'https') {
        try {
          const parsed = new URL(urlClean);
          let hostname = parsed.hostname;
          if (!hostname) return "EXTERNAL_EXFIL";
          hostname = hostname.replace(/\.$/, '').toLowerCase();
          if (!allowedHosts.has(hostname)) {
            return "EXTERNAL_EXFIL";
          }
        } catch (e) {
          return "EXTERNAL_EXFIL";
        }
      }
    }
  }

  return "SAFE";
}

// Channel validation rules
function checkHtml(text) {
  // 1. SCRIPT_TAG
  if (/<\s*(script|iframe|object|embed)(?![a-zA-Z0-9_-])/i.test(text)) {
    return "SCRIPT_TAG";
  }
  // 2. EVENT_HANDLER
  if (/\bon[a-zA-Z0-9_-]+\s*=/i.test(text)) {
    return "EVENT_HANDLER";
  }
  // 3. DANGEROUS_SCHEME & EXTERNAL_EXFIL
  const urls = [];
  const regex = /(?:src|href)\s*=\s*(["'])(.*?)\1/gi;
  let match;
  while ((match = regex.exec(text)) !== null) {
    urls.push(match[2]);
  }
  return checkUrls(urls, text);
}

function checkMarkdown(text) {
  const urls = extractMarkdownUrls(text);
  return checkUrls(urls, text);
}

function checkUrlChannel(text) {
  let rawUrl = text.trim();
  if (rawUrl.startsWith('<') && rawUrl.endsWith('>')) {
    rawUrl = rawUrl.slice(1, -1).trim();
  }
  const tokens = rawUrl.split(/\s+/);
  const target = tokens[0] || '';
  const urls = target ? [target] : [];
  return checkUrls(urls, text);
}

function checkSql(text) {
  const metachars = ["'", '"', ';', '--', '/*'];
  for (let m of metachars) {
    if (text.includes(m)) return "SQL_METACHAR";
  }
  if (/\bunion\b/i.test(text)) return "SQL_METACHAR";
  if (/\bor[\s(]*1\s*=\s*1\b/i.test(text)) return "SQL_METACHAR";
  return "SAFE";
}

function checkShell(text) {
  const metachars = [';', '&', '|', '`', '<', '>', '$(', '${'];
  for (let m of metachars) {
    if (text.includes(m)) return "SHELL_METACHAR";
  }
  return "SAFE";
}

function runChannelRules(channel, text) {
  if (channel === 'html') return checkHtml(text);
  if (channel === 'markdown') return checkMarkdown(text);
  if (channel === 'url') return checkUrlChannel(text);
  if (channel === 'sql') return checkSql(text);
  if (channel === 'shell') return checkShell(text);
  return "INVALID_SCHEMA";
}

function checkEncodedPayload(channel, originalOutput) {
  const decoded = decodeOnce(originalOutput);
  if (decoded !== originalOutput) {
    const tripReason = runChannelRules(channel, decoded);
    if (tripReason !== "SAFE") {
      return "ENCODED_PAYLOAD";
    }
  }
  return "SAFE";
}

function validateOutput(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { safe: false, reason: "INVALID_SCHEMA" };
  }
  if (!('channel' in body) || !('output' in body)) {
    return { safe: false, reason: "INVALID_SCHEMA" };
  }
  const channel = body.channel;
  const output = body.output;

  if (!['html', 'markdown', 'url', 'sql', 'shell'].includes(channel)) {
    return { safe: false, reason: "INVALID_SCHEMA" };
  }
  if (typeof output !== 'string') {
    return { safe: false, reason: "INVALID_SCHEMA" };
  }
  if (output.length > 20000) {
    return { safe: false, reason: "INVALID_SCHEMA" };
  }

  const encodedReason = checkEncodedPayload(channel, output);
  if (encodedReason !== "SAFE") {
    return { safe: false, reason: "ENCODED_PAYLOAD" };
  }

  const channelReason = runChannelRules(channel, output);
  if (channelReason !== "SAFE") {
    return { safe: false, reason: channelReason };
  }

  return { safe: true, reason: "SAFE" };
}

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS, HEAD');
  res.setHeader('Access-Control-Allow-Headers', '*');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  const rawPath = (req.url || '').split('?')[0].replace(/\/+$/, '');
  if (rawPath !== '/sanitize-output' && rawPath !== '') {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
    return;
  }

  let bodyChunks = [];
  req.on('data', chunk => bodyChunks.push(chunk));
  req.on('end', () => {
    let bodyBuffer = Buffer.concat(bodyChunks);
    let bodyStr = bodyBuffer.toString('utf8');
    if (bodyStr.charCodeAt(0) === 0xFEFF) {
      bodyStr = bodyStr.slice(1);
    }

    let body = null;
    try {
      body = JSON.parse(bodyStr);
    } catch (e) {
      body = null;
    }

    const responseData = validateOutput(body);
    const responseJson = JSON.stringify(responseData);

    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': Buffer.byteLength(responseJson)
    });
    res.end(responseJson);
  });
});

if (require.main === module) {
  const PORT = parseInt(process.env.PORT || '8080', 10);
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`Safety Gate Node.js Server running on port ${PORT}`);
  });
}

module.exports = { validateOutput, server };
