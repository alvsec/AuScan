// ESPEJO DEL GUARD. NO ES LA AUTORIDAD.
//
// Existe solo para dar feedback mientras se escribe un CIDR en la UI.
// La decisión real la toma src-tauri/src/scope.rs, y es la única que
// determina si una herramienta se lanza. Si este fichero y aquel
// divergen, el test de paridad contra fixtures/scope/corpus.json pone
// CI en rojo — que es exactamente lo que tiene que pasar.

export type ScopeSpec = { allow: string[]; deny: string[] };
export type Verdict = "in" | "out" | "empty-scope" | "invalid";
export type EntryError = "ambiguous" | "overbroad" | "invalid";

type Addr = { v: bigint; bits: 32 | 128 };
type Net = { base: bigint; prefix: number; bits: 32 | 128 };

function parseIpv4(s: string): Addr | null {
  const p = s.split(".");
  if (p.length !== 4) return null;
  let v = 0n;
  for (const o of p) {
    if (!/^\d{1,3}$/.test(o)) return null;
    const n = Number(o);
    if (n > 255) return null;
    v = (v << 8n) | BigInt(n);
  }
  return { v, bits: 32 };
}

function parseIpv6(s: string): Addr | null {
  // v4-mapeadas: se canonicalizan a v4, igual que Ipv6Addr::to_ipv4_mapped
  // en Rust. Solo la forma con puntos; el corpus no usa la hexadecimal.
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(s);
  if (mapped) return parseIpv4(mapped[1]!);

  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];

  let groups: string[];
  if (halves.length === 1) {
    if (head.length !== 8) return null;
    groups = head;
  } else {
    const fill = 8 - head.length - tail.length;
    if (fill < 1) return null;
    groups = [...head, ...Array<string>(fill).fill("0"), ...tail];
  }

  let v = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
    v = (v << 16n) | BigInt(parseInt(g, 16));
  }
  return { v, bits: 128 };
}

export function parseAddr(s: string): Addr | null {
  const t = s.trim();
  if (!t) return null;
  return t.includes(":") ? parseIpv6(t) : parseIpv4(t);
}

function maskOf(prefix: number, bits: 32 | 128): bigint {
  const total = BigInt(bits);
  return ((1n << total) - 1n) ^ ((1n << (total - BigInt(prefix))) - 1n);
}

export function parseEntry(s: string): { net: Net } | { error: EntryError } {
  const t = s.trim();
  if (!t) return { error: "invalid" };

  const slash = t.indexOf("/");
  if (slash === -1) {
    const a = parseAddr(t);
    if (!a) return { error: "invalid" };
    return { net: { base: a.v, prefix: a.bits, bits: a.bits } };
  }

  const head = t.slice(0, slash);
  const pStr = t.slice(slash + 1);
  if (!/^\d{1,3}$/.test(pStr)) return { error: "invalid" };
  let prefix = Number(pStr);

  // Notación mapeada con prefijo: ::ffff:a.b.c.d/n con n >= 96 es la red
  // v4 a.b.c.d/(n-96). Con n < 96 desborda el rango mapeado y no es
  // ninguna red v4. Mismo criterio que canonical_net en Rust.
  const esMapeada = /^::ffff:\d{1,3}(?:\.\d{1,3}){3}$/i.test(head);
  const a = parseAddr(head);
  if (!a) return { error: "invalid" };

  if (esMapeada) {
    if (prefix < 96 || prefix > 128) return { error: "invalid" };
    prefix -= 96;
  } else if (prefix > a.bits) {
    return { error: "invalid" };
  }

  const base = a.v & maskOf(prefix, a.bits);
  // Bits de host puestos: ambiguo, se rechaza igual que en Rust.
  if (base !== a.v) return { error: "ambiguous" };
  // Un /0 no es un alcance: es la ausencia de uno.
  if (prefix === 0) return { error: "overbroad" };

  return { net: { base, prefix, bits: a.bits } };
}

function contains(net: Net, a: Addr): boolean {
  if (net.bits !== a.bits) return false;
  return (a.v & maskOf(net.prefix, net.bits)) === net.base;
}

export function inScope(spec: ScopeSpec, target: string): Verdict {
  const a = parseAddr(target);
  if (!a) return "invalid";

  const allow: Net[] = [];
  for (const s of spec.allow) {
    const r = parseEntry(s);
    if ("net" in r) allow.push(r.net);
  }
  // Sin autorización explícita no hay nada autorizado.
  if (allow.length === 0) return "empty-scope";

  for (const s of spec.deny) {
    const r = parseEntry(s);
    if ("net" in r && contains(r.net, a)) return "out";
  }

  return allow.some((n) => contains(n, a)) ? "in" : "out";
}
