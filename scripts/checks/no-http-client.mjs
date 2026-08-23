// La app no habla con la red: solo lo hacen las herramientas que lanza.
//
// Para Rust NO se grepea Cargo.lock: el lockfile incluye las dependencias
// de todas las plataformas, y tauri arrastra reqwest solo para Android e
// iOS. La propiedad que importa es "el binario de escritorio no habla con
// la red", y eso lo dice el grafo del objetivo, no el lockfile.

const PROHIBIDOS_JS = ["axios", "node-fetch"];
export const PROHIBIDOS_RUST = ["reqwest", "ureq", "isahc"];

export function findHttpClients(lockText) {
  return PROHIBIDOS_JS.filter((p) =>
    new RegExp(`"(?:node_modules/)?${p}"|"${p}":`).test(lockText),
  );
}

/// `cargo tree -i <crate>` no imprime nada en stdout cuando el crate no
/// está en el grafo del objetivo actual (avisa por stderr).
export function crateEnElGrafo(stdout) {
  return stdout.trim().length > 0;
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

  for (const crate of PROHIBIDOS_RUST) {
    let salida;
    try {
      salida = execFileSync(
        "cargo",
        ["tree", "-i", crate, "--manifest-path", "src-tauri/Cargo.toml"],
        { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
      );
    } catch {
      salida = ""; // cargo sale con error cuando el crate no está: correcto.
    }
    if (crateEnElGrafo(salida)) {
      console.error(`src-tauri: ${crate} está en el grafo de dependencias`);
      fallos += 1;
    }
  }

  if (fallos > 0) {
    console.error("\nSi es intencionado, justifícalo en el PR y añade la excepción aquí.");
    process.exit(1);
  }
  console.log("sin clientes HTTP en el grafo de escritorio");
}
