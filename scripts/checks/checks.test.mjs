// En JavaScript a propósito: los módulos comprobados son .mjs y
// `tsc --noEmit` fallaría al no encontrarles declaraciones de tipos.
// `scripts` está en el `exclude` de tsconfig.json por lo mismo.
import { describe, expect, it } from "vitest";

import { findForbiddenAddresses } from "./fixtures.mjs";
import { keyDiff } from "./i18n-parity.mjs";
import { crateEnElGrafo, findHttpClients } from "./no-http-client.mjs";

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

  it("acepta el corpus real del repositorio", async () => {
    const { readFileSync } = await import("node:fs");
    const corpus = readFileSync("fixtures/scope/corpus.json", "utf8");
    expect(findForbiddenAddresses(corpus)).toEqual([]);
  });
});

describe("comprobación de cliente HTTP", () => {
  it("detecta axios en package-lock.json", () => {
    expect(findHttpClients('"node_modules/axios": { "version": "1.0.0" }')).toContain(
      "axios",
    );
  });

  it("no se inventa hallazgos", () => {
    expect(findHttpClients('"node_modules/zustand": {}')).toEqual([]);
  });

  it("interpreta la salida vacía de cargo tree como ausencia", () => {
    expect(crateEnElGrafo("")).toBe(false);
    expect(crateEnElGrafo("   \n  ")).toBe(false);
    expect(crateEnElGrafo("reqwest v0.12.0\n└── tauri v2.0.0")).toBe(true);
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
