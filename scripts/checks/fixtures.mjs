// Comprueba que fixtures/ solo contiene direcciones de documentación.
//
// Un 192.168.1.x real y uno inventado son indistinguibles a simple vista,
// así que RFC 1918 está prohibido igual que las públicas. Esto convierte
// "cero datos de cliente" de una intención en una propiedad verificada.

const V4_PERMITIDOS = ["192.0.2.", "198.51.100.", "203.0.113."];
// Excepciones exactas. Añadir una debe verse en el diff.
// 0.0.0.0 es necesaria para ejercitar el rechazo de alcance /0.
const V4_EXACTOS = ["0.0.0.0", "127.0.0.1"];

const RE_V4 = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
const RE_MAC = /\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b/gi;
// Una MAC suelta, sin flag /g: .test() sobre una expresión global mantiene
// lastIndex entre llamadas y devuelve resultados alternos.
const RE_MAC_UNA = /^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/i;
// Los nombres de host NO se comprueban aquí: un patrón lo bastante amplio
// para pillar srv.cliente.com también pilla package.json y v1.2.3, y un
// check que cría lobos deja de leerse. Van por revisión, y así se dice en
// SECURITY.md.
// El primer grupo no puede ir vacío: permitiéndolo, el patrón casaba
// ":00:" dentro de 2026-08-22T10:00:00Z. Como efecto, las formas que
// empiezan por "::" (::1, ::ffff:a.b.c.d) no las ve este patrón — las
// primeras son benignas y en las segundas la parte IPv4 la caza RE_V4.
// Sin \b al final: un límite de palabra no puede casar justo después de
// ":", así que un prefijo de cliente terminado en "::" seguido de "/nn"
// quedaba invisible (dos no-palabra seguidos nunca son límite). El
// lookahead negativo exige que lo siguiente no sea alfanumérico, no solo
// que no sea hexadecimal: "db::ENGAGEMENT_MIGRATIONS" tiene dos grupos no
// vacíos ("db", "E") y pasaría el filtro de abajo si solo se rechazase un
// hexadecimal siguiente, porque la "N" que viene después no lo es.
const RE_V6 = /\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}(?![0-9a-zA-Z])/gi;
// Las horas de las marcas de tiempo ISO (10:00:00) casan con el patrón de
// IPv6. Se descartan por forma en vez de exigir una letra hexadecimal en el
// token, que era como una IPv6 puramente numérica (2001:0db8:6000::1) se
// colaba sin que nadie la viera.
const RE_HORA = /^\d{1,2}:\d{2}:\d{2}$/;

export function findForbiddenAddresses(text) {
  const malas = [];

  for (const m of text.matchAll(RE_V4)) {
    const ip = m[0];
    // 999.1.1.1 no es una dirección: denunciarla sería ruido.
    if (ip.split(".").some((o) => Number(o) > 255)) continue;
    if (V4_EXACTOS.includes(ip)) continue;
    if (V4_PERMITIDOS.some((p) => ip.startsWith(p))) continue;
    malas.push(ip);
  }

  for (const m of text.matchAll(RE_MAC)) {
    const mac = m[0].toLowerCase();
    // Localmente administrada: segundo dígito hex del primer octeto en 2,6,a,e.
    if ("26ae".includes(mac[1])) continue;
    malas.push(m[0]);
  }

  for (const m of text.matchAll(RE_V6)) {
    const token = m[0];
    if (RE_MAC_UNA.test(token)) continue;
    if (RE_HORA.test(token)) continue;
    // Menos de dos grupos no vacíos no es una IPv6 real: es la forma en
    // que "db::" —de db::open, en cualquier fichero de Rust— casa con el
    // patrón. Con dos o más, "db::" queda fuera y toda dirección real
    // (incluida una numérica como 2001:0db8:6000::1) sigue dentro.
    const gruposNoVacios = token.split(":").filter(Boolean).length;
    if (gruposNoVacios < 2) continue;
    // 2001:db8::/32 admite tanto la forma corta como 2001:0db8.
    if (/^2001:0{0,3}db8:/i.test(token)) continue;
    malas.push(token);
  }

  return [...new Set(malas)];
}

// Dos ficheros documentan a propósito los vectores de prueba NEGATIVOS de
// este mismo check —tienen que contener direcciones prohibidas para poder
// afirmar que el check las detecta— y de otro modo se denunciarían a sí
// mismos en cada ejecución. Rutas en forma POSIX: la salida de
// `git ls-files` ya viene así en cualquier plataforma.
export const FICHEROS_EXENTOS = new Set([
  "scripts/checks/checks.test.mjs",
  "docs/superpowers/plans/2026-08-22-auscan-fundacion.md",
]);

const EXT_BINARIAS = new Set([
  ".png", ".ico", ".icns", ".jpg", ".jpeg", ".gif", ".woff", ".woff2",
]);

/// A partir de la salida cruda de `git ls-files -z` (entradas separadas
/// por NUL, terminador final incluido), devuelve los ficheros que de
/// verdad hay que comprobar: sin los exentos, sin binarios reconocibles
/// por extensión. Función pura para poder testearla sin invocar a git.
///
/// -z en vez de saltos de línea: sin él, un nombre con caracteres no
/// ASCII sale entrecomillado y con escapes octales ("archivo con
/// eñe.md" → "\"archivo con e\\303\\261e.md\""), y esa cadena no es una
/// ruta abrible — revienta el readFileSync de más abajo con un ENOENT
/// que no dice qué pasó de verdad.
export function ficherosAComprobar(lsFilesStdout) {
  return lsFilesStdout
    .split("\0")
    .filter(Boolean)
    .filter((f) => !FICHEROS_EXENTOS.has(f))
    .filter((f) => !EXT_BINARIAS.has(f.slice(f.lastIndexOf("."))));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { readFileSync } = await import("node:fs");
  const { execFileSync } = await import("node:child_process");

  // Se recorre lo que git conoce: lo versionado (--cached) MÁS lo nuevo
  // que aún no se ha añadido (--others, filtrado por .gitignore con
  // --exclude-standard). Solo --cached se queda corto: un fichero recién
  // creado con datos de cliente, todavía sin `git add`, pasaría este
  // check en verde justo en el momento —antes de comitear— en el que
  // pillarlo importa más. Si git no responde, el check falla en vez de
  // recorrer un árbol arbitrario — mismo principio que no-http-client.mjs
  // aplica a `cargo tree`: un check que no puede verificar tiene que
  // decirlo, no pasar en silencio.
  let salida;
  try {
    salida = execFileSync(
      "git",
      ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
  } catch (e) {
    console.error(`no se pudo listar los ficheros versionados: ${e.message}`);
    process.exit(2);
  }

  const ficheros = ficherosAComprobar(salida);
  if (ficheros.length < 10) {
    console.error(
      `git ls-files devolvió ${ficheros.length} ficheros: la salida no es creíble y el check no puede afirmar nada`,
    );
    process.exit(2);
  }

  let fallos = 0;
  for (const f of ficheros) {
    let contenido;
    try {
      contenido = readFileSync(f, "utf8");
    } catch (e) {
      // Un fichero listado por git pero ausente del disco (borrado sin
      // `git rm`) o un nombre que -z ya evita que llegue mal formado:
      // se informa como fallo del check, no como una traza cruda de Node.
      console.error(`${f}: no se pudo leer (${e.code ?? e.message})`);
      fallos += 1;
      continue;
    }
    const malas = findForbiddenAddresses(contenido);
    if (malas.length > 0) {
      console.error(`${f}: direcciones prohibidas → ${malas.join(", ")}`);
      fallos += malas.length;
    }
  }
  if (fallos > 0) {
    console.error(
      "\nfixtures/ solo admite RFC 5737 (192.0.2/24, 198.51.100/24, 203.0.113/24),\n" +
        "2001:db8::/32 y MAC localmente administradas.",
    );
    process.exit(1);
  }
  console.log(`fixtures: ${ficheros.length} fichero(s) sin direcciones prohibidas`);
}
