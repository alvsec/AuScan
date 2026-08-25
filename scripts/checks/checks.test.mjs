// En JavaScript a propósito: los módulos comprobados son .mjs y
// `tsc --noEmit` fallaría al no encontrarles declaraciones de tipos.
// `scripts` está en el `exclude` de tsconfig.json por lo mismo.
import { describe, expect, it } from "vitest";

import { ficherosAComprobar, findForbiddenAddresses } from "./fixtures.mjs";
import { keyDiff } from "./i18n-parity.mjs";
import {
  cratesEnElGrafo,
  findHttpClients,
  findRustHttpClients,
} from "./no-http-client.mjs";

describe("comprobación de fixtures", () => {
  it("acepta los rangos de documentación", () => {
    const ok = "198.51.100.5 192.0.2.1 203.0.113.9 2001:db8::1 02:00:5e:10:00:01";
    expect(findForbiddenAddresses(ok)).toEqual([]);
  });

  it("acepta la forma expandida 2001:0db8", () => {
    expect(findForbiddenAddresses("2001:0db8:000a:0000:0000:0000:0000:0001")).toEqual([]);
  });

  it("rechaza direcciones RFC 1918, que podrían ser reales", () => {
    expect(findForbiddenAddresses("192.168.1.10")).toContain("192.168.1.10");
    expect(findForbiddenAddresses("10.0.0.5")).toContain("10.0.0.5");
    expect(findForbiddenAddresses("172.16.4.2")).toContain("172.16.4.2");
  });

  it("rechaza direcciones públicas", () => {
    expect(findForbiddenAddresses("8.8.8.8")).toContain("8.8.8.8");
  });

  it("rechaza IPv6 fuera del rango de documentación", () => {
    expect(findForbiddenAddresses("fe80::1234:5678:9abc:def0")).not.toEqual([]);
  });

  it("rechaza MAC que no sean localmente administradas", () => {
    expect(findForbiddenAddresses("00:1a:2b:3c:4d:5e")).toContain("00:1a:2b:3c:4d:5e");
  });

  it("no confunde una marca de tiempo ISO con una IPv6", () => {
    expect(findForbiddenAddresses('"createdAt": "2026-08-22T10:00:00Z"')).toEqual([]);
  });

  it("es determinista al repetirse sobre el mismo texto", () => {
    // Regresión: RE_MAC con flag /g conservaba lastIndex entre llamadas a
    // .test() y devolvía resultados alternos.
    const texto = "02:00:5e:10:00:01 2001:db8::1 06:aa:bb:cc:dd:ee";
    const primera = findForbiddenAddresses(texto);
    for (let i = 0; i < 5; i += 1) {
      expect(findForbiddenAddresses(texto)).toEqual(primera);
    }
    expect(primera).toEqual([]);
  });

  it("caza una IPv6 prohibida aunque sea puramente numérica", () => {
    // Regresión: el patrón exigía una letra hexadecimal para no confundirse
    // con las horas, y así 2620:100:6000::1 se colaba entero.
    expect(findForbiddenAddresses("2620:100:6000::1")).toContain("2620:100:6000::1");
  });

  it("no confunde el prefijo permitido con uno más largo", () => {
    // 192.0.2. no puede casar por prefijo con 192.0.20.5 porque termina
    // en punto. Este test lo fija por si alguien quita el punto.
    expect(findForbiddenAddresses("192.0.20.5")).toContain("192.0.20.5");
    // 192.0.29.5 sí es una IPv4 válida y comparte los primeros caracteres
    // con el prefijo permitido: es el caso que de verdad ejercita startsWith.
    expect(findForbiddenAddresses("192.0.29.5")).toContain("192.0.29.5");
  });

  it("caza la parte IPv4 de una mapeada prohibida", () => {
    expect(findForbiddenAddresses("::ffff:192.168.1.1")).toContain("192.168.1.1");
    expect(findForbiddenAddresses("::ffff:192.0.2.65")).toEqual([]);
  });

  it("caza un prefijo de cliente terminado en :: seguido de /nn", () => {
    // Regresión: el \b final del patrón no puede casar justo después de
    // ":", así que un prefijo real de ISP como este quedaba invisible.
    expect(findForbiddenAddresses("2a02:26f0::/32")).toContain("2a02:26f0::");
  });

  it("no confunde db::ENGAGEMENT_MIGRATIONS con una IPv6", () => {
    // Regresión: un lookahead que solo rechazara otro carácter
    // hexadecimal habría dejado pasar esto ("db","E" son dos grupos no
    // vacíos, y la "N" que sigue a la "E" no es hexadecimal).
    expect(findForbiddenAddresses("db::ENGAGEMENT_MIGRATIONS")).toEqual([]);
    expect(findForbiddenAddresses("db::open(&p)")).toEqual([]);
  });

  it("acepta el corpus real del repositorio", async () => {
    const { readFileSync } = await import("node:fs");
    const corpus = readFileSync("fixtures/scope/corpus.json", "utf8");
    expect(findForbiddenAddresses(corpus)).toEqual([]);
  });
});

describe("lista de ficheros a comprobar", () => {
  it("excluye los dos ficheros con vectores de prueba negativos", () => {
    const salida = "fixtures/scope/corpus.json\nscripts/checks/checks.test.mjs\nREADME.md\n";
    expect(ficherosAComprobar(salida)).toEqual(["fixtures/scope/corpus.json", "README.md"]);
  });

  it("excluye binarios reconocibles por extensión", () => {
    const salida = "src-tauri/icons/32x32.png\nsrc/App.tsx\n";
    expect(ficherosAComprobar(salida)).toEqual(["src/App.tsx"]);
  });

  it("ignora la línea vacía final de git ls-files", () => {
    expect(ficherosAComprobar("a.txt\nb.txt\n")).toEqual(["a.txt", "b.txt"]);
  });
});

describe("comprobación de cliente HTTP", () => {
  it("detecta axios en package-lock.json", () => {
    expect(findHttpClients('"node_modules/axios": { "version": "1.0.0" }')).toContain(
      "axios",
    );
  });

  it("detecta un cliente HTTP anidado como dependencia transitiva", () => {
    // Regresión: anclar al principio de la clave dejaba fuera las
    // transitivas, que son la vía más probable de entrada.
    expect(
      findHttpClients('"node_modules/foo/node_modules/axios": { "version": "1.0.0" }'),
    ).toContain("axios");
  });

  it("detecta un cliente HTTP escondido tras un alias de npm", () => {
    // Regresión introducida al arreglar lo anterior: anclar a la ruta
    // perdía el caso en que el paquete se instala con otro nombre.
    expect(
      findHttpClients('"node_modules/mi-http": { "name": "axios", "version": "1.0.0" }'),
    ).toContain("axios");
  });

  it("no se inventa hallazgos en el package-lock real del repo", async () => {
    const { readFileSync } = await import("node:fs");
    expect(findHttpClients(readFileSync("package-lock.json", "utf8"))).toEqual([]);
  });

  it("no se inventa hallazgos", () => {
    expect(findHttpClients('"node_modules/zustand": {}')).toEqual([]);
  });

  it("lee el grafo de cargo tree quitando el sufijo de deduplicado", () => {
    const salida = "serde\naho_corasick (*)\nrusqlite\n";
    expect(cratesEnElGrafo(salida)).toEqual(new Set(["serde", "aho_corasick", "rusqlite"]));
  });

  it("encuentra un crate prohibido en el grafo y no se lo inventa", () => {
    expect(findRustHttpClients("serde\nreqwest\ntauri\n")).toEqual(["reqwest"]);
    expect(findRustHttpClients("serde\nrusqlite\ntauri\n")).toEqual([]);
  });

  it("normaliza guiones y guiones bajos entre nombre de crate y de lib", () => {
    expect(findRustHttpClients("mi_cliente\n", ["mi-cliente"])).toEqual(["mi-cliente"]);
  });
});

describe("paridad de claves i18n", () => {
  it("no informa de nada cuando coinciden", () => {
    expect(keyDiff({ a: { b: 1 } }, { a: { b: 2 } })).toEqual([]);
  });

  it("informa de las claves que faltan a cada lado", () => {
    const d = keyDiff({ a: 1, b: 2 }, { a: 1, c: 3 });
    expect(d.join(" ")).toContain("b");
    expect(d.join(" ")).toContain("c");
  });

  it("detecta diferencias anidadas", () => {
    expect(keyDiff({ a: { b: 1, c: 2 } }, { a: { b: 1 } })).not.toEqual([]);
  });
});
