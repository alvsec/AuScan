// La app no habla con la red: solo lo hacen las herramientas que lanza.
//
// Para Rust NO se grepea Cargo.lock: el lockfile incluye las dependencias
// de todas las plataformas, y tauri arrastra reqwest solo para Android e
// iOS. La propiedad que importa es "el binario de escritorio no habla con
// la red", y eso lo dice el grafo del objetivo, no el lockfile.
//
// Se consulta el grafo COMPLETO una sola vez, en vez de preguntar crate a
// crate con `cargo tree -i`. Con la consulta por crate, un crate ausente y
// un nombre mal escrito en la lista producen la misma salida vacía, así
// que una errata dejaría el check pasando en verde para siempre. Con el
// grafo completo, si cargo falla se nota y se sale con error.

const PROHIBIDOS_JS = ["axios", "node-fetch"];
export const PROHIBIDOS_RUST = ["reqwest", "ureq", "isahc"];

/// Las claves de package-lock.json anidan: "node_modules/a/node_modules/axios".
/// Anclar al principio se dejaría fuera las transitivas, que son la vía más
/// probable por la que entraría un cliente HTTP sin querer.
export function findHttpClients(lockText) {
  return PROHIBIDOS_JS.filter((p) =>
    new RegExp(`"[^"]*node_modules/${p}"|^\\s*"${p}":`, "m").test(lockText),
  );
}

/// `cargo tree --prefix none --format {lib}` emite un nombre por línea, con
/// sufijo " (*)" en las entradas deduplicadas. Los nombres de lib usan
/// guiones bajos donde el crate usa guiones, así que se normalizan ambos.
export function cratesEnElGrafo(stdout) {
  return new Set(
    stdout
      .split("\n")
      .map((l) => l.replace(/\s*\(\*\)\s*$/, "").trim().replace(/-/g, "_"))
      .filter(Boolean),
  );
}

export function findRustHttpClients(stdout, prohibidos = PROHIBIDOS_RUST) {
  const presentes = cratesEnElGrafo(stdout);
  return prohibidos.filter((c) => presentes.has(c.replace(/-/g, "_")));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { readFileSync, existsSync } = await import("node:fs");
  const { execFileSync } = await import("node:child_process");
  let fallos = 0;

  if (existsSync("package-lock.json")) {
    const hallados = findHttpClients(readFileSync("package-lock.json", "utf8"));
    if (hallados.length > 0) {
      console.error(`package-lock.json: cliente HTTP → ${hallados.join(", ")}`);
      fallos += hallados.length;
    }
  }

  let salida;
  try {
    salida = execFileSync(
      "cargo",
      [
        "tree",
        "--manifest-path",
        "src-tauri/Cargo.toml",
        "--prefix",
        "none",
        "--format",
        "{lib}",
        "--edges",
        "normal",
      ],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
  } catch (e) {
    // Fallar ruidosamente. Un check que no puede comprobar debe decirlo,
    // no pasar en silencio: eso es peor que no tener check.
    console.error(`no se pudo consultar el grafo de dependencias: ${e.message}`);
    process.exit(2);
  }

  const crates = cratesEnElGrafo(salida);
  if (crates.size < 10) {
    console.error(
      `cargo tree devolvió ${crates.size} crates: la salida no es creíble y el check no puede afirmar nada`,
    );
    process.exit(2);
  }

  const rust = findRustHttpClients(salida);
  if (rust.length > 0) {
    console.error(`src-tauri: cliente HTTP en el grafo → ${rust.join(", ")}`);
    fallos += rust.length;
  }

  if (fallos > 0) {
    console.error("\nSi es intencionado, justifícalo en el PR y añade la excepción aquí.");
    process.exit(1);
  }
  console.log(`sin clientes HTTP (${crates.size} crates en el grafo de escritorio)`);
}
