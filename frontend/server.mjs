import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import { URL } from 'node:url';

const DIST_DIR = process.env.DIST_DIR || '/app/dist';
const DIST_ROOT = path.resolve(DIST_DIR);
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

// Refactor: map-based content type lookup keeps logic declarative.
const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
};

function contentTypeFor(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  return CONTENT_TYPES[ext] || 'application/octet-stream';
}

// Refactor: isolate path safety checks into a single helper.
function safeResolve(requestPath) {
  const decoded = decodeURIComponent(requestPath);
  const stripped = decoded.replace(/^\/+/, '');
  const resolved = path.resolve(DIST_DIR, stripped);
  if (!resolved.startsWith(DIST_ROOT)) return null;
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

    // Refactor note: SPA fallback only for non-asset routes. Previously a
    // missing .js/.css request would return index.html with text/html
    // content-type, causing the browser to silently parse HTML as JS/CSS.
    const hasExtension = path.extname(pathname) !== '';
    if (!filePath || !fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
      if (hasExtension) {
        return send(res, 404, 'Not Found');
      }
      filePath = path.join(DIST_DIR, 'index.html');
    }

    const isIndexHtml = path.basename(filePath) === 'index.html';
    const stream = fs.createReadStream(filePath);
    stream.on('error', (err) => send(res, 500, `Server error: ${err.message}`));

    const headers = { 'Content-Type': contentTypeFor(filePath) };
    // Refactor note: index.html should never be cached; hashed assets can be
    // cached long-term (content-addressed by Vite).
    if (isIndexHtml) {
      headers['Cache-Control'] = 'no-store';
    } else {
      headers['Cache-Control'] = 'public, max-age=31536000, immutable';
    }
    res.writeHead(200, headers);
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
