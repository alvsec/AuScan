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
    // Sin ceros a la izquierda: el parser de Rust rechaza "198.51.100.01",
    // así que aceptarlo aquí sería divergir en silencio.
    if (!/^(0|[1-9]\d{0,2})$/.test(o)) return null;
    const n = Number(o);
    if (n > 255) return null;
    v = (v << 8n) | BigInt(n);
  }
  return { v, bits: 32 };
}

function parseIpv6(s: string): Addr | null {
  let text = s;

  // RFC 4291: el último grupo puede escribirse como IPv4 con puntos, y no
  // solo en la forma ::ffff:. Rust acepta 2001:db8:a::203.0.113.5, así que
  // aquí se traduce a dos grupos hexadecimales antes de seguir.
  const ultimoDosPuntos = text.lastIndexOf(":");
  if (ultimoDosPuntos === -1) return null;
  const cola = text.slice(ultimoDosPuntos + 1);
  if (cola.includes(".")) {
    const v4 = parseIpv4(cola);
    if (!v4) return null;
    const alto = (v4.v >> 16n) & 0xffffn;
    const bajo = v4.v & 0xffffn;
    text = `${text.slice(0, ultimoDosPuntos + 1)}${alto.toString(16)}:${bajo.toString(16)}`;
  }

  const halves = text.split("::");
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

  // Misma regla que Ipv6Addr::to_ipv4_mapped en Rust: solo ::ffff:a.b.c.d
  // se reduce a v4. Las formas compatible-v4 (::a.b.c.d) y NAT64 no.
  if (v >> 32n === 0xffffn) return { v: v & 0xffffffffn, bits: 32 };

  return { v, bits: 128 };
}

export function parseAddr(s: string): Addr | null {
  const t = s.trim();
  if (!t) return null;
  return t.includes(":") ? parseIpv6(t) : parseIpv4(t);
}

function maskOf(prefix: number, bits: 32 | 128): bigint {
  // BigInt no lanza con un desplazamiento negativo: desplaza al otro lado
  // y devolvería una máscara sin sentido. Mejor fallar aquí.
  if (prefix < 0 || prefix > bits) throw new RangeError(`prefijo ${prefix} fuera de rango para /${bits}`);
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
  // Sin ceros a la izquierda tampoco en el prefijo: Rust rechaza /032.
  if (!/^(0|[1-9]\d{0,2})$/.test(pStr)) return { error: "invalid" };
  let prefix = Number(pStr);

  const eraTextualmenteV6 = head.includes(":");
  const a = parseAddr(head);
  if (!a) return { error: "invalid" };

  if (eraTextualmenteV6 && a.bits === 32) {
    // Notación mapeada con prefijo: ::ffff:a.b.c.d/n es la red v4
    // a.b.c.d/(n-96). Con n < 96 desborda el rango mapeado y no es
    // ninguna red v4. Mismo criterio que canonical_net en Rust.
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

/// PRECONDICIÓN: `spec` viene de entradas ya persistidas, que Rust validó
/// con parse_entry antes de guardarlas y almacena en forma canónica. Por eso
/// aquí una entrada ilegible se descarta en silencio mientras que en Rust
/// Scope::from_entries devuelve error: la asimetría es inalcanzable en
/// producción. Si algún día esta función recibe texto sin validar, hay que
/// revisarla.
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
