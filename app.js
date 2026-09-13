"use strict";

/* Verificador de documentos AVJAC.
 *
 * Formato AVJ2 del QR (lo genera el programa de escritorio):
 *   AVJ2*CNA*K1*RJ037*C5L02*TITULAR*2*20260831*20260912*20261012*SELLOCORTO*FIRMA
 *   AVJ2*CTC*K1*CTC/2026/001*C5L02*SOLICITANTE*2*32.50*2*20260915*20270915*SELLOCORTO*FIRMA
 * FIRMA = ECDSA P-256 / SHA-256 (r||s, 64 bytes) en Base32 sin relleno, sobre todo lo anterior al último '*'.
 * Toda la verificación ocurre en el teléfono: el contenido del QR no se envía a ningún servidor.
 */

const ALCANCES = {
  1: "Cuotas ordinarias y extraordinarias",
  2: "Cuotas ordinarias y extraordinarias, multas y recargos",
};
const TIPOS_OBRA = [
  "Construcción nueva", "Ampliación", "Remodelación", "Modificación de fachada", "Barda o muro perimetral", "Otra",
];
const MESES = [
  "enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre",
];
const CAMPOS_ESPERADOS = { CNA: 11, CTC: 12 };

const $ = (id) => document.getElementById(id);
const estado = {
  claves: {}, cancelados: [], actualizado: null, repositorio: null, flujo: null, escaneando: false, detector: undefined,
};
const lienzo = document.createElement("canvas");
const ctx = lienzo.getContext("2d", { willReadFrequently: true });

/* ---------------- Datos publicados por la Administración ---------------- */

const ESPERA_DATOS_MS = 5000;

async function obtenerJSON(url, encabezados = {}) {
  const control = new AbortController();
  const temporizador = setTimeout(() => control.abort(), ESPERA_DATOS_MS);
  try {
    const respuesta = await fetch(url, { cache: "no-store", headers: encabezados, signal: control.signal });
    return respuesta.ok ? await respuesta.json() : null;
  } catch {
    return null;
  } finally {
    clearTimeout(temporizador);
  }
}

function repositorio() {
  if (estado.repositorio) return estado.repositorio;
  const organizacion = /^([\w-]+)\.github\.io$/i.exec(location.hostname);
  const carpeta = location.pathname.split("/").filter(Boolean)[0];
  return organizacion && carpeta ? `${organizacion[1]}/${carpeta}` : null;
}

async function obtenerCancelados() {
  // 1) Directo del repositorio con la API de GitHub: refleja una cancelación en segundos. La página publicada puede
  //    tardar hasta 10 minutos por la caché de GitHub Pages. La API permite 60 consultas por hora por red.
  const repo = repositorio();
  if (repo) {
    const datos = await obtenerJSON(`https://api.github.com/repos/${repo}/contents/datos/cancelados.json`, {
      Accept: "application/vnd.github.raw+json",
    });
    if (datos?.folios) return datos;
  }
  // 2) Copia de la página publicada; sin conexión, el trabajador de servicio entrega la última guardada.
  return obtenerJSON("datos/cancelados.json");
}

async function actualizarDatos() {
  const [claves, cancelados] = await Promise.all([obtenerJSON("datos/claves.json"), obtenerCancelados()]);
  if (claves?.claves) {
    estado.claves = claves.claves;
    estado.repositorio = claves.repositorio || estado.repositorio;
  }
  if (cancelados?.folios) {
    estado.cancelados = cancelados.folios;
    estado.actualizado = cancelados.actualizado ?? null;
  }
  $("pie-datos").textContent = estado.actualizado
    ? `Lista de cancelaciones actualizada al ${fechaHora(estado.actualizado)}.`
    : "No se pudieron cargar los datos del verificador. Ábrelo con conexión a internet.";
}

let listos = actualizarDatos();

/* ---------------- Utilidades ---------------- */

const aCompacta = (iso) => iso.slice(0, 10).replaceAll("-", "");
const esFecha = (texto) => /^\d{8}$/.test(texto);
const fechaCorta = (f) => `${f.slice(6, 8)}/${f.slice(4, 6)}/${f.slice(0, 4)}`;
const fechaLarga = (f) => `${Number(f.slice(6, 8))} de ${MESES[Number(f.slice(4, 6)) - 1]} de ${f.slice(0, 4)}`;
const fechaHora = (iso) => `${fechaCorta(aCompacta(iso))} ${iso.slice(11, 16)}`;

function hoy() {
  const f = new Date();
  return `${f.getFullYear()}${String(f.getMonth() + 1).padStart(2, "0")}${String(f.getDate()).padStart(2, "0")}`;
}

function inmueble(clave) {
  const m = /^C(\d+)L(\d+)$/.exec(clave);
  return m ? `Coto ${Number(m[1])}, Lote ${Number(m[2])}` : clave;
}

function base32(texto) {
  const alfabeto = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const salida = [];
  let bits = 0;
  let valor = 0;
  for (const caracter of texto) {
    const indice = alfabeto.indexOf(caracter);
    if (indice < 0) return null;
    valor = ((valor << 5) | indice) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      salida.push((valor >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(salida);
}

async function claveCripto(identificador) {
  const spki = estado.claves[identificador];
  if (!spki) return null;
  const der = Uint8Array.from(atob(spki), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey("spki", der, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
}

/* ---------------- Verificación ---------------- */

async function verificarTexto(texto) {
  listos = actualizarDatos(); // cada verificación consulta la lista de cancelaciones más reciente
  await listos;
  texto = (texto || "").trim();
  if (texto.startsWith("AVJ2*")) return verificarFirmado(texto);

  const legado = leerFormatoAnterior(texto);
  if (legado) {
    return mostrar({
      tipo: "neutro",
      titulo: "Formato anterior, sin firma digital",
      detalle: "Este documento se emitió antes de la firma digital del código QR. Sus datos no pueden comprobarse "
        + "en el teléfono: confírmalos con la Administración.",
      filas: legado.filas,
      sello: legado.sello,
    });
  }
  return mostrar({
    tipo: "neutro",
    titulo: "Este código no es de un documento de la Asociación",
    detalle: "Contenido leído:",
    crudo: texto,
  });
}

function noValido(detalle) {
  return mostrar({ tipo: "error", titulo: "Documento NO válido", detalle });
}

async function verificarFirmado(texto) {
  const corte = texto.lastIndexOf("*");
  const mensaje = texto.slice(0, corte);
  const firma = base32(texto.slice(corte + 1));
  const campos = mensaje.split("*");
  const tipo = campos[1];

  if (CAMPOS_ESPERADOS[tipo] !== campos.length || !firma || firma.length !== 64 || !/^[\x20-\x7e]*$/.test(mensaje)) {
    return noValido("El código tiene un formato incorrecto o está incompleto.");
  }
  if (!window.isSecureContext || !window.crypto?.subtle) {
    return mostrar({ tipo: "error", titulo: "No se puede verificar aquí", detalle: "Abre el verificador desde su dirección segura (https)." });
  }

  let clave = null;
  try {
    clave = await claveCripto(campos[2]);
  } catch {
    clave = null;
  }
  if (!clave) {
    return mostrar({
      tipo: "aviso",
      titulo: `Clave de firma no reconocida (${campos[2]})`,
      detalle: "El verificador no tiene la clave con la que se firmó este documento. Conéctate a internet, cierra "
        + "y vuelve a abrir el verificador. Si el aviso continúa, consulta a la Administración.",
    });
  }

  let valida = false;
  try {
    valida = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, clave, firma, new TextEncoder().encode(mensaje));
  } catch {
    valida = false;
  }
  if (!valida) {
    return noValido("La firma digital no corresponde a los datos. El documento fue alterado o no lo emitió la Asociación.");
  }

  const documento = tipo === "CNA" ? datosConstancia(campos) : datosAnuencia(campos);
  if (!documento) return noValido("El código tiene un formato incorrecto.");

  let resultado;
  if (estado.cancelados.includes(documento.folio)) {
    resultado = { tipo: "error", titulo: "Auténtico, pero CANCELADO", detalle: `La Asociación canceló esta ${documento.nombre}. No es válida.` };
  } else if (hoy() > documento.vigencia) {
    resultado = { tipo: "aviso", titulo: "Auténtico, pero VENCIDO", detalle: `Su vigencia terminó el ${fechaLarga(documento.vigencia)}.` };
  } else {
    resultado = {
      tipo: "ok",
      titulo: "Documento auténtico y vigente",
      detalle: "Emitido por Organización Vecinal Residencial Jardines, A.C. Los datos coinciden con la firma digital.",
    };
  }
  return mostrar({ ...resultado, filas: documento.filas, sello: campos[campos.length - 1], nota: notaCancelaciones() });
}

function datosConstancia(c) {
  const [, , , folio, clave, titular, alcance, cubierto, emision, vigencia] = c;
  if (![cubierto, emision, vigencia].every(esFecha) || !ALCANCES[alcance]) return null;
  return {
    folio,
    vigencia,
    nombre: "constancia",
    filas: [
      ["Documento", "Constancia de No Adeudo"],
      ["Folio", folio],
      ["Inmueble", inmueble(clave)],
      ["Titular", titular],
      ["Alcance", ALCANCES[alcance]],
      ["Cuotas cubiertas al", fechaLarga(cubierto)],
      ["Emisión", fechaLarga(emision)],
      ["Vigente hasta", fechaLarga(vigencia)],
    ],
  };
}

function datosAnuencia(c) {
  const [, , , folio, clave, solicitante, tipo, superficie, niveles, emision, vigencia] = c;
  const tipoObra = TIPOS_OBRA[Number(tipo) - 1];
  if (!tipoObra || ![emision, vigencia].every(esFecha) || Number.isNaN(Number(superficie))) return null;
  const metros = Number(superficie).toLocaleString("es-MX", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  return {
    folio,
    vigencia,
    nombre: "anuencia",
    filas: [
      ["Documento", "Anuencia de construcción"],
      ["Folio", folio],
      ["Inmueble", inmueble(clave)],
      ["Solicitante / propietario", solicitante],
      ["Tipo de obra", tipoObra],
      ["Superficie", `${metros} m²`],
      ["Niveles", niveles === "0" ? "No aplica" : niveles],
      ["Emisión", fechaLarga(emision)],
      ["Vigente hasta", fechaLarga(vigencia)],
    ],
  };
}

function leerFormatoAnterior(texto) {
  let m = /^NO ADEUDO (RJ\d+) \* C(\d+)-L(\d+) \* (.+) \* (CUOTAS(?: Y MULTAS)?) AL (\d{2})\/(\d{2})\/(\d{4}) \* SELLO ([0-9A-F]{16})$/.exec(texto);
  if (m) {
    return {
      sello: m[9],
      filas: [
        ["Documento", "Constancia de No Adeudo"],
        ["Folio", m[1]],
        ["Inmueble", `Coto ${m[2]}, Lote ${m[3]}`],
        ["Titular", m[4]],
        ["Alcance", m[5] === "CUOTAS" ? ALCANCES[1] : ALCANCES[2]],
        ["Cuotas cubiertas al", fechaLarga(m[8] + m[7] + m[6])],
      ],
    };
  }
  m = /^ANUENCIA (CTC\/\d{4}\/\d+) \* C(\d+)-L(\d+) \* (.+) \* (.+) \* SELLO ([0-9A-F]{16})$/.exec(texto);
  if (m) {
    return {
      sello: m[6],
      filas: [
        ["Documento", "Anuencia de construcción"],
        ["Folio", m[1]],
        ["Inmueble", `Coto ${m[2]}, Lote ${m[3]}`],
        ["Solicitante / propietario", m[4]],
        ["Tipo de obra", m[5]],
      ],
    };
  }
  return null;
}

function notaCancelaciones() {
  if (!estado.actualizado) return "No se pudo consultar la lista de cancelaciones.";
  return `Cancelaciones consultadas al ${fechaHora(estado.actualizado)}. `
    + "Si se canceló después de esa fecha, la Administración puede confirmarlo.";
}

/* ---------------- Presentación ---------------- */

function mostrarSeccion(nombre) {
  for (const id of ["inicio", "camara", "resultado"]) $(id).hidden = id !== nombre;
}

function mostrar({ tipo, titulo, detalle = "", filas = [], sello = null, nota = "", crudo = null }) {
  detenerCamara();
  const iconos = { ok: "✔", aviso: "!", error: "✖", neutro: "i" };
  $("estado").className = `estado ${tipo}`;
  $("estado-icono").textContent = iconos[tipo];
  $("estado-titulo").textContent = titulo;
  $("estado-detalle").textContent = detalle;

  const lista = $("datos");
  lista.replaceChildren();
  for (const [etiqueta, valor] of filas) {
    const dt = document.createElement("dt");
    const dd = document.createElement("dd");
    dt.textContent = etiqueta;
    dd.textContent = valor;
    lista.append(dt, dd);
  }
  lista.hidden = filas.length === 0;

  $("crudo").hidden = !crudo;
  $("crudo").textContent = crudo || "";
  $("sello").hidden = !sello;
  $("sello-valor").textContent = sello ? `${sello.toLowerCase()}…` : "";
  $("nota").textContent = nota;
  mostrarSeccion("resultado");
  $("resultado").scrollIntoView({ behavior: "smooth", block: "start" });
}

/* ---------------- Lectura del código QR ---------------- */

async function obtenerDetector() {
  if (estado.detector !== undefined) return estado.detector;
  estado.detector = null;
  if ("BarcodeDetector" in window) {
    try {
      if ((await BarcodeDetector.getSupportedFormats()).includes("qr_code")) {
        estado.detector = new BarcodeDetector({ formats: ["qr_code"] });
      }
    } catch {
      estado.detector = null;
    }
  }
  return estado.detector;
}

async function decodificar(fuente, sx, sy, sw, sh, anchoObjetivo) {
  const escala = Math.min(2, anchoObjetivo / sw);
  lienzo.width = Math.max(1, Math.round(sw * escala));
  lienzo.height = Math.max(1, Math.round(sh * escala));
  ctx.drawImage(fuente, sx, sy, sw, sh, 0, 0, lienzo.width, lienzo.height);

  const detector = await obtenerDetector();
  if (detector) {
    try {
      const encontrados = await detector.detect(lienzo);
      if (encontrados.length) return encontrados[0].rawValue;
    } catch {
      /* se intenta con jsQR */
    }
  }
  const imagen = ctx.getImageData(0, 0, lienzo.width, lienzo.height);
  const resultado = jsQR(imagen.data, imagen.width, imagen.height, { inversionAttempts: "dontInvert" });
  return resultado ? new TextDecoder().decode(new Uint8Array(resultado.binaryData)) : null;
}

async function iniciarCamara() {
  if (!navigator.mediaDevices?.getUserMedia) {
    return mostrar({ tipo: "aviso", titulo: "Cámara no disponible", detalle: "Este navegador no permite usar la cámara. Usa «Leer desde foto o captura»." });
  }
  try {
    estado.flujo = await navigator.mediaDevices.getUserMedia({
      audio: false,
      video: { facingMode: { ideal: "environment" }, width: { ideal: 1920 }, height: { ideal: 1080 } },
    });
  } catch {
    return mostrar({
      tipo: "aviso",
      titulo: "No se pudo abrir la cámara",
      detalle: "Permite el acceso a la cámara en el navegador o usa «Leer desde foto o captura».",
    });
  }
  const video = $("video");
  video.srcObject = estado.flujo;
  mostrarSeccion("camara");
  await video.play().catch(() => {});
  estado.escaneando = true;
  buscarEnVideo(0);
}

async function buscarEnVideo(vuelta) {
  const video = $("video");
  if (!estado.escaneando) return;
  if (video.readyState >= 2 && video.videoWidth) {
    const w = video.videoWidth;
    const h = video.videoHeight;
    const lado = Math.min(w, h);
    // Alterna entre el recuadro central (a mayor resolución) y el cuadro completo.
    const texto = vuelta % 2 === 0
      ? await decodificar(video, (w - lado) / 2, (h - lado) / 2, lado, lado, 1000)
      : await decodificar(video, 0, 0, w, h, 1280);
    if (texto && estado.escaneando) {
      estado.escaneando = false;
      navigator.vibrate?.(60);
      return verificarTexto(texto);
    }
  }
  setTimeout(() => buscarEnVideo(vuelta + 1), 120);
}

function detenerCamara() {
  estado.escaneando = false;
  if (estado.flujo) {
    for (const pista of estado.flujo.getTracks()) pista.stop();
    estado.flujo = null;
  }
  $("video").srcObject = null;
}

function cargarImagen(archivo) {
  return new Promise((resolver, rechazar) => {
    const imagen = new Image();
    imagen.onload = () => resolver(imagen);
    imagen.onerror = rechazar;
    imagen.src = URL.createObjectURL(archivo);
  });
}

async function leerFoto(archivo) {
  if (!archivo) return;
  let imagen;
  try {
    imagen = await cargarImagen(archivo);
  } catch {
    return mostrar({ tipo: "aviso", titulo: "No se pudo abrir la imagen", detalle: "Prueba con otra foto o captura." });
  }
  const w = imagen.naturalWidth;
  const h = imagen.naturalHeight;
  // Imagen completa y después mosaicos que se traslapan, empezando por la mitad inferior (donde va el QR).
  const intentos = [[0, 0, w, h, 1600], [0, 0, w, h, 2400]];
  for (const fy of [0.5, 0.25, 0]) {
    for (const fx of [0, 0.25, 0.5]) intentos.push([fx * w, fy * h, w / 2, h / 2, 1400]);
  }
  try {
    for (const [sx, sy, sw, sh, ancho] of intentos) {
      const texto = await decodificar(imagen, sx, sy, sw, sh, ancho);
      if (texto) return verificarTexto(texto);
    }
  } finally {
    URL.revokeObjectURL(imagen.src);
  }
  return mostrar({
    tipo: "aviso",
    titulo: "No se encontró el código QR",
    detalle: "Toma la foto más cerca del código y con buena luz, o recorta la captura alrededor del código y vuelve a intentarlo.",
  });
}

/* ---------------- Cálculo de SHA-256 ---------------- */

async function calcularSHA() {
  const cadena = $("cadena").value.replace(/[\r\n]+$/, "");
  const salida = $("hash");
  const comparacion = $("comparacion");
  comparacion.textContent = "";
  comparacion.className = "comparacion";
  if (!cadena) {
    salida.textContent = "";
    return;
  }
  if (!window.crypto?.subtle) {
    salida.textContent = "Abre el verificador desde su dirección segura (https) para calcular el SHA-256.";
    return;
  }
  const resumen = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(cadena)));
  const hex = Array.from(resumen, (b) => b.toString(16).padStart(2, "0")).join("");
  salida.textContent = hex;

  const esperado = $("sello-esperado").value.toLowerCase().replace(/sello|sha-?256/g, "").replace(/[^0-9a-f]/g, "");
  if (!esperado) return;
  const coincide = hex === esperado || (esperado.length >= 8 && hex.startsWith(esperado));
  comparacion.textContent = coincide ? "✔ Coincide con el sello" : "✖ No coincide con el sello";
  comparacion.classList.add(coincide ? "si" : "no");
}

/* ---------------- Arranque ---------------- */

$("btn-escanear").addEventListener("click", iniciarCamara);
$("btn-cancelar").addEventListener("click", () => {
  detenerCamara();
  mostrarSeccion("inicio");
});
$("btn-otro").addEventListener("click", () => mostrarSeccion("inicio"));
$("foto").addEventListener("change", (evento) => {
  const archivo = evento.target.files[0];
  evento.target.value = "";
  leerFoto(archivo);
});
$("cadena").addEventListener("input", calcularSHA);
$("sello-esperado").addEventListener("input", calcularSHA);
document.addEventListener("visibilitychange", () => {
  if (document.hidden && estado.escaneando) {
    detenerCamara();
    mostrarSeccion("inicio");
  }
});

let solicitudInstalacion = null;
window.addEventListener("beforeinstallprompt", (evento) => {
  evento.preventDefault();
  solicitudInstalacion = evento;
  $("btn-instalar").hidden = false;
});
$("btn-instalar").addEventListener("click", async () => {
  if (!solicitudInstalacion) return;
  solicitudInstalacion.prompt();
  await solicitudInstalacion.userChoice;
  solicitudInstalacion = null;
  $("btn-instalar").hidden = true;
});
if (/iphone|ipad|ipod/i.test(navigator.userAgent) && !navigator.standalone) $("ayuda-ios").hidden = false;

if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});

window.AVJAC = { verificarTexto, leerFoto };
