// Trabajador de servicio: permite abrir el verificador sin internet después de la primera visita.
// Al exportar desde el programa, 20260913020640 se reemplaza para que los teléfonos descarguen la versión nueva.
const VERSION = "20260913020640";
const CACHE = `verificador-avjac-${VERSION}`;
const ARCHIVOS = [
  "./",
  "index.html",
  "app.js",
  "vendor/jsQR.js",
  "manifest.webmanifest",
  "icono-192.png",
  "icono-512.png",
  "datos/claves.json",
  "datos/cancelados.json",
];

self.addEventListener("install", (evento) => {
  evento.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(ARCHIVOS)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (evento) => {
  evento.waitUntil(
    caches.keys()
      .then((nombres) => Promise.all(nombres.filter((n) => n !== CACHE).map((n) => caches.delete(n))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (evento) => {
  const peticion = evento.request;
  if (peticion.method !== "GET" || new URL(peticion.url).origin !== self.location.origin) return;

  // Claves y cancelaciones: primero la red (para tener la lista más reciente); sin conexión, la copia guardada.
  if (new URL(peticion.url).pathname.includes("/datos/")) {
    evento.respondWith(
      fetch(peticion)
        .then((respuesta) => {
          if (respuesta.ok) {
            const copia = respuesta.clone();
            caches.open(CACHE).then((cache) => cache.put(peticion, copia));
          }
          return respuesta;
        })
        .catch(() => caches.match(peticion, { ignoreSearch: true }))
    );
    return;
  }

  evento.respondWith(caches.match(peticion, { ignoreSearch: true }).then((guardada) => guardada || fetch(peticion)));
});
