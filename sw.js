// Trabajador de servicio: permite abrir el verificador sin internet después de la primera visita.
// Al exportar desde el programa, 20260915015550 se reemplaza para que los teléfonos descarguen la versión nueva.
const VERSION = "20260915015550";
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
  // cache: "reload" evita la caché HTTP de GitHub Pages (hasta 10 minutos): sin esto, la versión nueva podría
  // guardar el app.js anterior.
  const peticiones = ARCHIVOS.map((archivo) => new Request(archivo, { cache: "reload" }));
  evento.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(peticiones)).then(() => self.skipWaiting()));
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
  const url = new URL(peticion.url);
  if (url.pathname.includes("/datos/")) {
    const clave = url.origin + url.pathname;
    evento.respondWith(
      fetch(peticion)
        .then((respuesta) => {
          if (respuesta.ok) {
            const copia = respuesta.clone();
            caches.open(CACHE).then((cache) => cache.put(clave, copia));
          }
          return respuesta;
        })
        .catch(() => caches.match(clave))
    );
    return;
  }

  evento.respondWith(caches.match(peticion, { ignoreSearch: true }).then((guardada) => guardada || fetch(peticion)));
});
