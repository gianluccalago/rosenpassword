/* Rosen service worker: cache-first apenas para os arquivos do próprio app.
   Nunca toca em dados: o cofre vive só em localStorage/IndexedDB e nunca passa pela rede. */
const VERSION = 'rosen-v1.1.0';
const ASSETS = ['./', 'index.html', 'styles.css', 'app.js', 'manifest.webmanifest',
  'icons/icon-192.png', 'icons/icon-512.png', 'icons/icon-512-maskable.png', 'icons/apple-touch-icon.png'];
const SCOPE = new URL('./', self.location).href;

self.addEventListener('install', e => {
  e.waitUntil(caches.open(VERSION).then(c => c.addAll(ASSETS)));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== VERSION).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('message', e => {
  if (e.data && e.data.type === 'SKIP_WAITING') self.skipWaiting();
});
self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin || !url.href.startsWith(SCOPE)) return;
  // Só responde ao que está na lista do app. Qualquer outra coisa segue direto para a rede.
  let path = url.href.slice(SCOPE.length).split('?')[0].split('#')[0];
  if (path === '' || path === 'index.html' || req.mode === 'navigate') path = './';
  if (!ASSETS.includes(path)) return;
  e.respondWith(
    caches.match(path === './' ? './' : path).then(hit => hit || fetch(req).then(res => {
      if (res && res.ok) caches.open(VERSION).then(c => c.put(path, res.clone()));
      return res;
    })).catch(() => caches.match('./'))
  );
});
