import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import { URL } from 'node:url';

const DIST_DIR = process.env.DIST_DIR || '/app/dist';
const PORT = Number(process.env.PORT || 8080);

// Backend base URL for server-side proxy. IMPORTANT: browser never sees this.
// Examples:
// - http://host.docker.internal:8001
// - http://backend:8001
const BACKEND_BASE_URL = process.env.PTW_BACKEND_BASE_URL || 'http://host.docker.internal:8001';

function send(res, status, body, headers = {}) {
  res.writeHead(status, {
    'Cache-Control': 'no-store',
    ...headers,
  });
  res.end(body);
}

function contentTypeFor(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case '.html':
      return 'text/html; charset=utf-8';
    case '.js':
      return 'text/javascript; charset=utf-8';
    case '.css':
      return 'text/css; charset=utf-8';
    case '.json':
      return 'application/json; charset=utf-8';
    case '.svg':
      return 'image/svg+xml';
    case '.png':
      return 'image/png';
    case '.jpg':
    case '.jpeg':
      return 'image/jpeg';
    case '.ico':
      return 'image/x-icon';
    case '.txt':
      return 'text/plain; charset=utf-8';
    default:
      return 'application/octet-stream';
  }
}

function safeResolve(requestPath) {
  const decoded = decodeURIComponent(requestPath);
  const stripped = decoded.replace(/^\/+/, '');
  const resolved = path.resolve(DIST_DIR, stripped);
  if (!resolved.startsWith(path.resolve(DIST_DIR))) return null;
  return resolved;
}

function proxyToBackend(req, res) {
  const backendBase = new URL(BACKEND_BASE_URL);
  const targetUrl = new URL(req.url, backendBase);

  const isHttps = backendBase.protocol === 'https:';
  const client = isHttps ? https : http;

  const headers = { ...req.headers };
  // Make backend see its own host.
  headers.host = backendBase.host;

  const proxyReq = client.request(
    {
      protocol: backendBase.protocol,
      hostname: backendBase.hostname,
      port: backendBase.port || (isHttps ? 443 : 80),
      method: req.method,
      path: targetUrl.pathname + targetUrl.search,
      headers,
    },
    (proxyRes) => {
      res.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
      proxyRes.pipe(res);
    }
  );

  proxyReq.on('error', (err) => {
    send(res, 502, `Bad Gateway: ${err.message}`);
  });

  req.pipe(proxyReq);
}

const server = http.createServer((req, res) => {
  try {
    if (!req.url) return send(res, 400, 'Bad Request');

    // Proxy API requests server-side.
    if (req.url.startsWith('/api/')) {
      return proxyToBackend(req, res);
    }

    const parsed = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = parsed.pathname;

    // Static file serve
    let filePath = safeResolve(pathname);

    // SPA fallback
    if (!filePath || !fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
      filePath = path.join(DIST_DIR, 'index.html');
    }

    const stream = fs.createReadStream(filePath);
    stream.on('error', (err) => send(res, 500, `Server error: ${err.message}`));

    res.writeHead(200, {
      'Content-Type': contentTypeFor(filePath),
      // Let assets be cached a bit; index.html falls back to no-store via send(), but here we keep it simple.
    });
    stream.pipe(res);
  } catch (err) {
    send(res, 500, `Server error: ${err?.message || String(err)}`);
  }
});

server.listen(PORT, '0.0.0.0', () => {
  // eslint-disable-next-line no-console
  console.log(`[frontend] listening on :${PORT}`);
  console.log(`[frontend] serving dist: ${DIST_DIR}`);
  console.log(`[frontend] proxy /api/* -> ${BACKEND_BASE_URL}`);
});
