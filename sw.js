// Serves the portal out of the encrypted files under d/. Without keys every
// request falls through to the host, which answers with the login page.
importScripts('keys.js');

const BASE = new URL(self.registration.scope).pathname;
const PLAIN = new Set(['sw.js', 'keys.js', 'gate.json']);
const TYPES = {
  html: 'text/html; charset=utf-8', css: 'text/css; charset=utf-8', js: 'text/javascript; charset=utf-8',
  mjs: 'text/javascript; charset=utf-8', json: 'application/json', xml: 'application/xml',
  txt: 'text/plain; charset=utf-8', csv: 'text/csv; charset=utf-8', svg: 'image/svg+xml',
  png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp',
  ico: 'image/x-icon', woff: 'font/woff', woff2: 'font/woff2', ttf: 'font/ttf', pdf: 'application/pdf',
  wasm: 'application/wasm', map: 'application/json',
};
// The host cannot send headers of its own choosing, so the worker sets them on
// what it decrypts. Scripts, styles and requests are held to the portal's own
// origin: a script from anywhere else would run with the reader's keys. Inline
// script stays allowed because both generators rely on it, and evaluated
// script because the vault's graph view and the plan's reports do.
const HEADERS = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' blob:; style-src 'self' 'unsafe-inline'; "
    + "img-src 'self' data: blob:; font-src 'self' data:; worker-src 'self' blob:; object-src 'none'; base-uri 'self'; form-action 'self'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
};
let keys;

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== self.location.origin || !url.pathname.startsWith(BASE)) return;
  const path = decodeURIComponent(url.pathname.slice(BASE.length));
  if (PLAIN.has(path) || path.startsWith('d/')) return;
  event.respondWith(serve(path, url, event.request));
});

async function fetchSealed(path) {
  return fetch(`${BASE}d/${await gate.nameFor(keys.mac, path)}`);
}

async function open(path) {
  const sealed = await fetchSealed(path);
  if (!sealed.ok) return null;
  const bytes = new Uint8Array(await sealed.arrayBuffer());
  const body = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.subarray(0, 12), additionalData: gate.bytes(path) }, keys.aes, bytes.subarray(12)));
  // The first byte says whether encrypt.mjs gzipped the file.
  const file = new Blob([body.subarray(1)]);
  return body[0] ? file.stream().pipeThrough(new DecompressionStream('gzip')) : file;
}

async function serve(path, url, request) {
  keys ??= await gate.loadKeys();
  if (!keys) return fetch(request);
  if (path === '__logout') {
    await gate.clearKeys();
    keys = undefined;
    return Response.redirect(BASE);
  }
  const isDir = path === '' || path.endsWith('/');
  for (const candidate of isDir ? [`${path}index.html`] : [path, `${path}.html`]) {
    const body = await open(candidate);
    if (body) {
      const type = TYPES[candidate.split('.').pop().toLowerCase()] ?? 'application/octet-stream';
      return new Response(body, { headers: { ...HEADERS, 'Content-Type': type } });
    }
  }
  if (!isDir && (await fetchSealed(`${path}/index.html`)).ok) return Response.redirect(`${url.pathname}/${url.search}`);
  // Keys from an earlier passphrase name files that no longer exist; dropping
  // them returns the reader to the login page instead of a wall of 404s. Asked
  // only on a miss, so a page that exists costs one request, not two.
  if (!(await fetchSealed(gate.CHECK)).ok) {
    await gate.clearKeys();
    keys = undefined;
    return fetch(request);
  }
  return new Response(`<!doctype html><meta charset="utf-8"><title>Not found</title><p>Nothing at this address. <a href="${BASE}">Portal home</a>`,
    { status: 404, headers: { 'Content-Type': TYPES.html } });
}
