// Service worker mínimo: habilita la instalación como app. No guarda datos en caché
// (los reportes y las consultas siempre van al servidor) y NO intercepta recursos de
// otros orígenes (Bootstrap, íconos), que carga el navegador directamente.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', e => {
  if (e.request.mode !== 'navigate') return;   // solo páginas propias; el resto, sin intervenir
  e.respondWith(fetch(e.request).catch(() =>
    new Response('Sin conexión. Verifique su conexión a internet e intente nuevamente.',
      {status: 503, headers: {'Content-Type': 'text/plain; charset=utf-8'}})));
});
