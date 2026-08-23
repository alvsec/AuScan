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
// El lookahead exige al menos una letra hexadecimal, lo que descarta las
// horas de las marcas de tiempo ISO (10:00:00) sin necesidad de listarlas.
// Limitación conocida y aceptada: una IPv6 puramente numérica se escapa.
// Los nombres de host tampoco se comprueban aquí — un patrón lo bastante
// amplio para pillar srv.cliente.com también pilla package.json y v1.2.3,
// y un check que cría lobos deja de leerse. Van por revisión, y así se
// dice en SECURITY.md.
const RE_V6 = /\b(?=[0-9a-f:]*[a-f])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}\b/gi;

export function findForbiddenAddresses(text) {
  const malas = [];

  for (const m of text.matchAll(RE_V4)) {
    const ip = m[0];
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
    // 2001:db8::/32 admite tanto la forma corta como 2001:0db8.
    if (/^2001:0{0,3}db8:/i.test(token)) continue;
    malas.push(token);
  }

  return [...new Set(malas)];
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { readdirSync, readFileSync, statSync, existsSync } = await import("node:fs");
  const { join } = await import("node:path");

  if (!existsSync("fixtures")) {
    console.log("fixtures: no hay directorio todavía");
    process.exit(0);
  }

  const ficheros = [];
  const recorrer = (d) => {
    for (const e of readdirSync(d)) {
      const p = join(d, e);
      if (statSync(p).isDirectory()) recorrer(p);
      else ficheros.push(p);
    }
  };
  recorrer("fixtures");

  let fallos = 0;
  for (const f of ficheros) {
    const malas = findForbiddenAddresses(readFileSync(f, "utf8"));
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
