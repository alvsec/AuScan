export function keyDiff(a, b) {
  const claves = (o, prefijo = "") =>
    Object.entries(o).flatMap(([k, v]) =>
      v && typeof v === "object" && !Array.isArray(v)
        ? claves(v, `${prefijo}${k}.`)
        : [`${prefijo}${k}`],
    );

  const ca = new Set(claves(a));
  const cb = new Set(claves(b));

  return [
    ...[...ca].filter((k) => !cb.has(k)).map((k) => `falta en el segundo: ${k}`),
    ...[...cb].filter((k) => !ca.has(k)).map((k) => `falta en el primero: ${k}`),
  ];
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { readFileSync } = await import("node:fs");
  const es = JSON.parse(readFileSync("src/i18n/locales/es.json", "utf8"));
  const en = JSON.parse(readFileSync("src/i18n/locales/en.json", "utf8"));
  const d = keyDiff(es, en);
  if (d.length > 0) {
    console.error("Las claves de es.json y en.json no coinciden:");
    for (const l of d) console.error(`  ${l}`);
    process.exit(1);
  }
  console.log("i18n: claves en paridad");
}
