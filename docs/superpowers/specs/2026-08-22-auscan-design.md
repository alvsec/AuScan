# AUscan — Diseño

**Fecha:** 2026-08-22 · **Estado:** aprobado para planificar · **Autor:** nonnamme

---

## 1. Qué es

Aplicación de escritorio (macOS primero, Windows en paridad de compilación) que
automatiza la **fase de recolección** de una auditoría de seguridad de red
autorizada. Recibe un alcance, orquesta herramientas de seguridad maduras,
normaliza sus salidas y exporta artefactos estructurados a una carpeta elegida
por el operador.

**La app no redacta el informe.** Produce el material con el que el consultor lo
redacta. Esta frase es una restricción de diseño, no una nota de alcance: se
refleja en el modelo de datos (sin severidad), en el exportador y en la UI.

**Stack:** Tauri 2 (Rust) · React 19 · TypeScript strict · Vite · Zustand ·
SQLite · i18next (es-ES / en-US).

Tailwind v4 estaba en el stack inicial y se ha diferido: la UI de la fundación
es sobria y CSS a mano cubre lo que hay. Entra cuando la pantalla de ejecución
justifique un sistema de utilidades.

Se reutiliza la arquitectura de `saldio` (`domain` puro · `services` IO ·
`data/repositories` + mappers · `store` Zustand · `src-tauri` con migraciones
versionadas append-only), con tres divergencias deliberadas documentadas en §4.

Se descartan de la pila de `saldio`: **Recharts** (no hay dashboard decorativo) y
**Motion** (herramienta sobria; la animación no aporta). Si las tablas de
resultados superan el millar de filas se evaluará `@tanstack/react-virtual`; no
antes.

---

## 2. Reglas no negociables

Condicionan el diseño desde el primer commit.

1. **Cero datos de clientes en el repositorio.** Ni IPs, ni hostnames, ni
   nombres, ni capturas, ni fixtures derivados de auditorías reales. Los datos
   de prueba son sintéticos y generados. Los únicos datos personales del repo
   son los del autor. → §11
2. **Privacidad por diseño en ejecución.** Los datos del engagement viven en una
   base local mientras dura. Exportados, la app propone purgar. Sin telemetría,
   sin red salvo la que hacen las herramientas contra el alcance, sin logs con
   datos sensibles fuera del directorio del engagement, sin temporales
   huérfanos. → §9
3. **El alcance es sagrado.** Un guard central `in_scope(target)` se aplica en
   todas las rutas de ejecución y rechaza con error cualquier objetivo fuera de
   alcance. Ninguna herramienta se lanza sin pasar por él. → §6
4. **Solo detección.** Sin explotación, sin fuerza bruta, sin pruebas
   destructivas. Los modos intrusivos se desactivan por bandera. Cualquier
   capacidad activa requiere consulta previa al autor. → §7.3
5. **Trazabilidad.** Cada escaneo registra comando exacto, versión de la
   herramienta, marca de tiempo, duración y hash de su salida cruda, que se
   conserva junto a la normalizada. → §5.3

---

## 3. Decisiones tomadas

Cada una se materializará como ADR corto en `docs/adr/` durante la Fase 1.

| # | Decisión | Razón en una línea |
|---|---|---|
| 0001 | No empaquetar binarios de terceros | NPSL de nmap y licencia de Npcap restringen la redistribución; además un driver de kernel no se empaqueta a la ligera |
| 0002 | Datos efímeros, un directorio por engagement | Hace la purga **verificable** (`assert !exists(path)`) en vez de un acto de fe sobre WAL y páginas libres |
| 0003 | FileVault como frontera de cifrado, sin cifrado de app | Una clave en el Keychain no protege de quien ya tiene la sesión abierta; el control fuerte es no conservar los datos |
| 0004 | Sin privilegios por defecto en macOS; elevación por ejecución si el spike falla | El Mac es la única máquina que pisa una auditoría; ver §8 |
| 0005 | La base de datos la posee Rust, no el frontend | Separar las escrituras del guard regalaría un camino para colar un objetivo sin validar |

---

## 4. Estructura del repositorio

```
AUscan/
├─ README.md                    modelo de amenazas, privilegios, política
├─ SECURITY.md · LICENSE                de datos, aviso legal de uso autorizado
├─ .github/workflows/ci.yml     lint · types · tests · build (mac + win)
│
├─ docs/
│  ├─ THREAT-MODEL.md           amenazas de la propia app
│  ├─ DATA-POLICY.md            qué se guarda, dónde, cuánto tiempo
│  └─ adr/000N-*.md
│
├─ src/                         React 19 · TS strict
│  ├─ domain/                   lógica pura, sin IO, testeable
│  │  ├─ scope/                 espejo de in_scope — SOLO para UX
│  │  ├─ model/                 Host · Service · Observation · ToolRun
│  │  └─ report/                composición de resumen.md (preview en UI)
│  ├─ data/                     capa de tipos sobre invoke + mappers
│  ├─ services/                 invoke, eventos, diálogos de fichero
│  ├─ store/                    zustand — useAppStore
│  ├─ pages/                    Preflight · Engagements · Scope
│  │                            Run · Results · Export
│  ├─ components/ · i18n/locales/{es,en}.json · test/
│
├─ src-tauri/                   Rust
│  ├─ src/
│  │  ├─ lib.rs                 comandos + invoke_handler
│  │  ├─ scope.rs               ★ el guard. autoridad única.
│  │  ├─ engagement.rs          crear · abrir · purgar
│  │  ├─ db.rs                  conexión + migraciones
│  │  ├─ exec.rs                verja · spawn · streaming · cancelación
│  │  ├─ preflight.rs           detección de herramientas y versiones
│  │  ├─ privilege.rs           elevación por plataforma (fase condicional)
│  │  ├─ export.rs              csv · json · resumen.md
│  │  └─ adapters/
│  │     ├─ mod.rs              ★ el trait + el registro
│  │     └─ nmap.rs · httpx.rs · nuclei.rs
│  ├─ migrations/000N_*.sql     versionadas, append-only
│  └─ tests/
│     ├─ scope_guard.rs         ★ ningún camino esquiva el guard
│     ├─ purge.rs               ★ tras purgar, el path no existe
│     └─ parsers/               un test por adaptador, contra fixtures
│
├─ fixtures/                    salidas sintéticas. JAMÁS de cliente.
│  └─ nmap/*.xml · httpx/*.jsonl · nuclei/*.jsonl
└─ tools/gen-fixtures/          generador de fixtures sintéticos
```

### Divergencias respecto a `saldio`

**La base de datos la posee Rust.** En `saldio` el SQL vivía en TypeScript vía
`tauri-plugin-sql`. Aquí no: la ejecución, el streaming, la cancelación y la
purga ya están en Rust, y separar las escrituras del guard abriría un camino
para colar un objetivo sin validar. Rust posee la conexión y expone comandos; el
frontend nunca ve SQL. `src/data/` es una capa de tipos sobre `invoke`.

**`scope.rs` es la autoridad; el TypeScript es un espejo.** El frontend valida
mientras se escribe un CIDR, para dar feedback inmediato. Esa copia no decide
nada, va marcada como tal en el propio fichero, y un test alimenta el mismo
corpus de casos a las dos implementaciones y exige coincidencia. El peligro no
es tener dos implementaciones: es que se separen en silencio.

**`fixtures/` cuelga de la raíz.** Los consumen los parsers en Rust y los tests
de render en TypeScript. Una sola copia, un solo sitio que auditar.

---

## 5. Modelo de datos

Dos bases separadas, consecuencia directa de ADR-0002.

### 5.1 `index.db` — registro global, deliberadamente anémico

```sql
CREATE TABLE engagement_ref (
  id          TEXT PRIMARY KEY,   -- uuid; también el nombre del directorio
  codename    TEXT NOT NULL,      -- nombre en clave, nunca el del cliente
  created_at  TEXT NOT NULL,      -- ISO-8601 UTC
  state       TEXT NOT NULL,      -- draft|scoped|running|exported|purged
  purged_at   TEXT                -- NULL mientras viva
);
```

Es todo lo que existe fuera del directorio del engagement. Sin alcance, sin
autorizante, sin ruta de exportación — un path como `~/Clientes/ACME/`
identifica al cliente igual de bien que su nombre.

**Lápidas.** Al purgar, la fila no se borra: quedan `id`, `codename`,
`created_at`, `purged_at`, `state='purged'`. Es el único rastro que sobrevive, y
sobrevive a propósito: poder demostrar cuándo se purgó vale más que la coartada
de no tener ni el registro.

### 5.2 Disposición en disco

```
~/Library/Application Support/AUscan/        (%APPDATA%\AUscan\ en Windows)
├─ index.db
└─ engagements/
   └─ 7f3a…/
      ├─ engagement.db
      └─ raw/
         ├─ 0001-nmap-sn.xml
         └─ 0002-nmap-sV.xml
```

### 5.3 `engagement.db`

```sql
CREATE TABLE engagement (              -- exactamente una fila
  id TEXT PRIMARY KEY, codename TEXT NOT NULL,
  authorized_by TEXT,                  -- persona y cargo
  authorization_ref TEXT,              -- referencia al documento firmado
  export_dir TEXT, created_at TEXT NOT NULL, state TEXT NOT NULL,
  CHECK (rowid = 1)
);

CREATE TABLE scope_entry (
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('allow','deny')),
  family TEXT NOT NULL CHECK (family IN ('v4','v6')),
  cidr TEXT NOT NULL,                  -- forma canónica normalizada
  note TEXT, created_at TEXT NOT NULL
);

CREATE TABLE tool_run (
  id INTEGER PRIMARY KEY,
  seq INTEGER NOT NULL UNIQUE,         -- 0003 ⟷ raw/0003-nmap-sV.xml
  tool TEXT NOT NULL,
  tool_version TEXT NOT NULL,
  tool_path TEXT NOT NULL,             -- ruta absoluta resuelta en preflight
  phase TEXT NOT NULL,
  argv_json TEXT NOT NULL,             -- array, no cadena
  privileged INTEGER NOT NULL,
  targets_json TEXT NOT NULL,          -- IPs validadas de esta ejecución
  started_at TEXT NOT NULL, finished_at TEXT, exit_code INTEGER,
  status TEXT NOT NULL,                -- running|ok|failed|cancelled
  raw_path TEXT, raw_sha256 TEXT, stderr_path TEXT
);

CREATE TABLE host (
  id INTEGER PRIMARY KEY,
  ip TEXT NOT NULL UNIQUE, hostname TEXT, mac TEXT, vendor TEXT,
  os_guess TEXT, os_accuracy INTEGER, state TEXT,
  first_seen_run INTEGER REFERENCES tool_run(id),
  last_seen_run  INTEGER REFERENCES tool_run(id)
);

CREATE TABLE host_tag (
  host_id INTEGER NOT NULL REFERENCES host(id) ON DELETE CASCADE,
  tag TEXT NOT NULL, PRIMARY KEY (host_id, tag)
);

CREATE TABLE service (
  id INTEGER PRIMARY KEY,
  host_id INTEGER NOT NULL REFERENCES host(id) ON DELETE CASCADE,
  port INTEGER NOT NULL,
  proto TEXT NOT NULL CHECK (proto IN ('tcp','udp','sctp')),
  state TEXT NOT NULL,
  service TEXT, product TEXT, version TEXT, extrainfo TEXT,
  tunnel TEXT,                         -- ssl → el http de arriba es https
  cpe TEXT, banner TEXT,
  first_seen_run INTEGER REFERENCES tool_run(id),
  last_seen_run  INTEGER REFERENCES tool_run(id),
  UNIQUE (host_id, port, proto)
);

CREATE TABLE observation (
  id INTEGER PRIMARY KEY,
  tool_run_id INTEGER NOT NULL REFERENCES tool_run(id),
  host_id    INTEGER REFERENCES host(id)    ON DELETE CASCADE,
  service_id INTEGER REFERENCES service(id) ON DELETE CASCADE,
  kind      TEXT NOT NULL,             -- vocabulario cerrado, §5.5
  subject   TEXT NOT NULL,             -- "198.51.100.5:443"
  statement TEXT NOT NULL,             -- "TLS 1.0 habilitado"
  evidence     TEXT,                   -- fragmento literal de la salida
  evidence_ref TEXT,                   -- raw/0007-testssl.json#L142
  meta_json    TEXT,                   -- lo que dijo la herramienta, tal cual
  observed_at  TEXT NOT NULL,
  UNIQUE (tool_run_id, kind, subject, statement)
);
```

`PRAGMA foreign_keys = ON` · `PRAGMA journal_mode = WAL` ·
`PRAGMA temp_store = MEMORY`.

El último es la regla 2 aplicada a SQLite: por defecto derrama temporales en
`/var/folders`, fuera del directorio del engagement y por tanto fuera del
alcance de la purga.

### 5.4 Decisiones dentro del esquema

**No hay columna de severidad, y no la hay estructuralmente.** No es una
convención que pueda saltarse el adaptador nº7: en el esquema no existe el sitio
donde ponerla. Si en el futuro se quiere puntuar, será en una tabla aparte y
explícita, nunca en el hecho observado.

**`argv_json` es un array.** Una cadena invita a reparsear y a que el
entrecomillado mienta. Se guarda lo que realmente se ejecutó; la línea legible
para `resumen.md` se compone con una función pura.

**`raw_sha256`** permite afirmar meses después que el XML de `raw/` es
exactamente el que produjo la herramienta.

**El guard trabaja con IPs y a las herramientas se les pasan IPs.** Si un
objetivo llega como hostname, se resuelve antes, se valida cada IP resultante
—si una sola cae fuera, se rechaza la ejecución entera— y se pasa la IP. Ninguna
herramienta puede volver a resolver por su cuenta y acabar tocando algo que el
guard nunca vio.

**Severidad de nuclei:** va en `meta_json` bajo la clave `tool_reported`, junto
a `template-id` y referencias CVE. `resumen.md` **nunca** agrupa, ordena ni
colorea por severidad; agrupa por `kind` y por host. El dato se conserva para
redactar, pero la app no presenta una valoración ajena como propia.

### 5.5 Vocabulario de `kind`

`enum` en Rust. Los adaptadores eligen de la lista; no pueden inventar. Es lo
que hace que la agrupación de `resumen.md` funcione en vez de degenerar en cien
categorías de una línea.

```
host.discovered · host.os_guess · service.open · service.version_disclosed
web.technology · web.title · web.header_absent
tls.protocol_enabled · tls.cipher_offered · tls.certificate_expiry
smb.signing_state · ssh.algorithm_offered · template.match
```

Ampliar el vocabulario es una decisión de diseño visible en el diff, no un
efecto colateral de escribir un parser.

---

## 6. Alcance y el guard

`scope.rs` es la autoridad única. Expone:

```rust
pub struct Scope { allow: Vec<IpNet>, deny: Vec<IpNet> }

impl Scope {
    /// Único constructor de ScopedTarget en todo el programa.
    pub fn validate(&self, t: &str) -> Result<ScopedTarget, ScopeError>;
    pub fn validate_all(&self, ts: &[String]) -> Result<Vec<ScopedTarget>, ScopeError>;
}

pub struct ScopedTarget(IpAddr);   // campo privado: infabricable fuera de scope.rs
```

**Reglas de evaluación:**

- `deny` gana siempre sobre `allow`, sin importar la especificidad.
- Sin ninguna entrada `allow`, el alcance está vacío y **todo** se rechaza. El
  estado por defecto es "nada autorizado", nunca "todo autorizado".
- Las entradas se normalizan a forma canónica al guardarse (`198.51.100.5/24` →
  se rechaza como ambigua; se exige `198.51.100.0/24` o `198.51.100.5/32`).
- IPv4 e IPv6 desde el principio: el coste es una dependencia (`ipnet`) y la
  omisión sería difícil de retrofitear.
- Un hostname se resuelve antes de validar; **todas** sus IPs deben estar en
  alcance o se rechaza la ejecución completa.

**Tests obligatorios** (`src-tauri/tests/scope_guard.rs`):

- Límites de CIDR: primera y última dirección dentro, adyacentes fuera.
- `deny` anidado dentro de `allow` gana.
- Alcance vacío rechaza todo.
- Hostname con resolución múltiple parcialmente fuera → rechazo total.
- IPv6, incluidas formas comprimidas y `::ffff:` mapeadas a v4.
- **Paridad TS↔Rust**: el mismo corpus de casos contra ambas implementaciones.

---

## 7. Interfaz de adaptador

### 7.1 Qué NO hace un adaptador

El enunciado original listaba cinco responsabilidades: detectar, comprobar
versión, construir comando, **ejecutar** y parsear. Se le retira la de ejecutar.
Si cada adaptador ejecuta, hay N sitios capaces de lanzar un proceso y por tanto
N sitios donde saltarse el guard. La regla 3 solo es cierta si existe **un único
sitio que lanza**. El adaptador describe y parsea; el núcleo ejecuta.

### 7.2 El trait

```rust
pub struct ToolDescriptor {
    pub id: &'static str,                       // "nmap"
    pub binaries: &'static [&'static str],
    pub min_version: Version,
    pub phases: &'static [Phase],
    pub install_hint: InstallHint,              // brew / winget
    pub allowed_flags: &'static [Flag],         // ★ §7.3
}

pub struct Flag {
    pub name: &'static str,
    pub needs_privilege: bool,   // -sS y -O solo con la ruta privilegiada
    pub takes_value: bool,       // el siguiente token del argv es un valor
                                  // opaco ("1-1000"); la verja lo salta en vez
                                  // de intentar casarlo como otra bandera
}

pub enum Phase {
    Discovery, PortSweep, Services, Web, Templates, Tls, Smb, Ssh, Mdns,
}

pub struct ParseContext<'a> {
    pub tool_run_id: i64,
    pub raw_path: &'a str,      // para componer evidence_ref
    pub observed_at: &'a str,   // reloj inyectado: parse sigue siendo pura
}

pub struct Invocation {
    pub phase: Phase,
    pub argv: Vec<String>,             // sin el binario: lo pone el núcleo
    pub targets: Vec<ScopedTarget>,
    pub needs_privilege: bool,
    pub raw_from: RawSource,           // Stdout | File(name)
    pub progress_from: ProgressSource, // Stderr | Stdout | None
    pub stdin: Option<Vec<u8>>,        // httpx lee URLs por stdin
    pub timeout: Duration,
}

pub struct PlanContext<'a> {
    pub phase:      Phase,               // qué fase pide el operador ahora
    pub scope:      &'a Scope,
    pub targets:    &'a [ScopedTarget],  // ya validados
    pub known:      &'a KnownState,      // hosts y servicios de fases previas
    pub privileged: bool,
    pub options:    &'a PhaseOptions,    // p.ej. -sC sí/no
}

pub trait ToolAdapter: Send + Sync {
    fn descriptor(&self) -> &ToolDescriptor;

    fn version_argv(&self) -> Vec<String>;
    fn parse_version(&self, stdout: &str) -> Result<Version>;

    /// De objetivos ya validados a comandos concretos.
    fn plan(&self, ctx: &PlanContext) -> Result<Vec<Invocation>>;

    /// Función PURA. Sin IO, sin reloj, sin red.
    fn parse(&self, raw: &[u8], ctx: &ParseContext) -> Result<Normalized>;

    fn parse_progress(&self, _line: &str) -> Option<Progress> { None }
}
```

`Normalized` contiene `HostFact`, `ServiceFact` y `ObservationFact`: hechos sin
identidad de base de datos, referenciados por IP y puerto. El núcleo resuelve
ids y hace el upsert. Por eso `parse` puede ser pura, y por eso un test de
parser es `parse(fixture) == esperado`, sin proceso, sin base de datos y sin
reloj.

`known` es lo que encadena las fases: hace que `nmap -sV` escanee solo los
puertos hallados en el descubrimiento y que `httpx` reciba exactamente los
servicios `http`/`https` detectados. Sin SQL en el adaptador.

`privileged` es la matriz de capacidades donde corresponde — dentro del
adaptador, que es quien conoce la herramienta:

```rust
let argv = if ctx.privileged {
    vec!["-sn", "-PR"]                       // ARP: ve todo el segmento
} else {
    vec!["-sn", "-PS80,443,22", "-PA80"]     // TCP: ve lo que responde
};
```

Un `if`, no una rama del repositorio.

### 7.3 La verja

`exec.rs` ejecuta estas tres comprobaciones antes de cada `spawn`, para todos los
adaptadores, sin excepción:

**1 · Ningún objetivo sin validar.** `ScopedTarget` solo lo fabrica `scope.rs`.
Además, el núcleo escanea el argv final: todo token que parsee como IP o CIDR
debe estar en `targets`. Un adaptador que interpole una IP a mano falla
ruidosamente en vez de escanear a un tercero.

**2 · Ninguna bandera fuera de la lista.** El emparejamiento es por igualdad
exacta, nunca por prefijo: colisiones como `-s`/`-sS` o `-P`/`-PS`/`-PR` no
existen porque un token o es exactamente un flag permitido o no lo es. Un flag
marcado `takes_value` consume el siguiente token del argv como valor opaco sin
intentar validarlo como bandera — así una lista de puertos nunca se interpreta
como otra cosa, y una IP sin validar no puede colarse pegada a una bandera.
Dos comprobaciones sobre la misma lista: todo flag del argv debe estar en
`descriptor.allowed_flags`, y todo flag marcado `needs_privilege` exige que la
invocación sea privilegiada. Convierte la regla 4 en algo mecánico: `--script
vuln` y los templates intrusivos de nuclei no es que estén desaconsejados — no
están en la lista y el proceso no arranca; `-sS` sí está, pero marcado, y no
arranca sin la ruta privilegiada. Y como añadir una capacidad activa obliga a
tocar una lista corta y visible, aparece como una línea señalada en el diff.

**3 · El binario es el resuelto en preflight.** Ruta absoluta, versión
revalidada. Ni `PATH`, ni un `nmap` aparecido en el directorio actual entre el
arranque y la ejecución.

### 7.4 El registro

```rust
// adapters/mod.rs
pub fn registry() -> Vec<Box<dyn ToolAdapter>> {
    vec![Box::new(nmap::Nmap), Box::new(httpx::Httpx), Box::new(nuclei::Nuclei)]
}
```

Añadir `ssh-audit` es un fichero nuevo y una línea aquí. El núcleo no se toca.

### 7.5 Preflight

Al arrancar: para cada `ToolDescriptor`, resolver el binario, ejecutar
`version_argv`, parsear, comparar con `min_version`. Resultado por herramienta:
`Ok(version)` · `TooOld(version)` · `Missing` · `Unparseable`.

Para las que faltan, se muestra el comando de instalación (`brew install …` /
`winget install …`) con dos acciones: copiarlo, o ejecutarlo **con confirmación
explícita**. Las fases cuyas herramientas falten se deshabilitan con explicación
concreta de qué se pierde; nunca fallan a mitad de ejecución.

El preflight también evalúa la **matriz de capacidades**: privilegios
disponibles, y en macOS el estado de FileVault, con aviso visible si está
desactivado (ADR-0003).

### 7.6 El adaptador nmap (Fase 4)

Primer adaptador real. Encadena tres fases del enum `Phase` con un solo
`ToolAdapter`, usando `ctx.phase` para saber cuál pide el operador y
`ctx.known` para saber qué hay de fases anteriores:

- **Discovery** — sin privilegio: `-sn -PS80,443,22 -PA80 -n`. Con privilegio:
  `-sn -PR -n` (ARP, ve todo el segmento). Siempre sobre `ctx.targets`.
- **PortSweep** — `-Pn -n` sobre `ctx.known.hosts`, sin `-p`: usa el top-1000
  de nmap por defecto, no barrido completo 1-65535. `-sT` sin privilegio,
  `-sS` con privilegio.
- **Services** — `-sV -Pn -n -p <lista exacta>` sobre los puertos de
  `ctx.known.services` cuyo `state == "open"`, más `-O` si `ctx.privileged`.

Siempre `-oX -` (nunca a fichero: T9) y siempre `-n` (nunca DNS propio de
nmap). `PhaseOptions.script_scan` (`-sC`) queda en el trait pero esta versión
no lo usa — parsear salida de scripts NSE es un formato distinto por script y
se deja fuera hasta que haga falta de verdad.

**IPv6 diferido.** `plan()` filtra `ctx.targets` a IPv4; un target v6 en
alcance no genera invocación todavía. El guard ya es dual-stack — el hueco es
solo que el primer adaptador real aún no reparte argv entre `-6` y v4.

**Vocabulario sin ampliar.** `host.discovered`, `host.os_guess`,
`service.open`, `service.version_disclosed` bastan para nmap v1; no hace
falta tocar el enum de §5.5.

**Parsing:** `roxmltree` (DOM de solo lectura) sobre la salida de `-oX -`.

**Fixtures:** `fixtures/nmap/*.xml` se escriben a mano con direcciones RFC
5737, porque el laboratorio Windows de §8.1 todavía no existe. `tools/
gen-fixtures/` se construye igual en esta fase — toma un XML y una tabla de
sustitución de direcciones — pero sus propios tests son sintético→sintético
(RFC 5737 a RFC 5737): el check de fixtures recorre todo el repositorio, no
solo `fixtures/`, así que no hay manera de commitear ni siquiera un "antes"
con IPs reales para probarlo. Queda listo y testeado para cuando el
laboratorio exista.

---

## 8. Privilegios

### 8.1 El hecho que ordena la decisión

El Mac portátil es la **única** máquina que pisa una auditoría. El sobremesa
Windows no va a escanear la red de un cliente: un descubrimiento interno exige
estar en el segmento. Por tanto la capacidad completa importa en macOS, y el
esfuerzo de la ruta privilegiada va ahí. Windows se compila en CI desde el
primer día para que no se pudra, pero no recibe trabajo de elevación.

El sobremesa Windows tiene otro papel, más valioso: es el **laboratorio** donde
se levantan VMs (SMB abierto, servidor web antiguo, TLS 1.0) de las que salen
los fixtures sintéticos realistas. Red propia, datos de nadie.

### 8.2 Qué necesita privilegios

Requieren root en macOS: `-sS`, `-O`, descubrimiento ARP (que es lo que hace
útil `nmap -sn` en un segmento local), `--traceroute`, y por completo `arp-scan`
y `masscan`.

No lo requieren: `-sT`, `-sV` sobre connect, `-sn` por sondas TCP, y todo
httpx / nuclei / whatweb / testssl / ssh-audit / enum4linux-ng / dns-sd.

**El coste real de no elevar:** el descubrimiento pasa de ARP (ve todo lo que
tiene interfaz en el segmento) a sondas TCP (ve lo que responde). Un host
silencioso —impresora con puertos cerrados, cámara, PLC— desaparece del
inventario. Es un agujero en el entregable, no una limitación cosmética.

### 8.3 El discriminador es la cancelación

Si nmap corre como root y la app no, **la app no puede matarlo**: `kill(2)`
devuelve `EPERM`. La cancelación real deja de funcionar en cuanto se eleva,
salvo que se diseñe explícitamente. Esto, y no el número de diálogos de
contraseña, es lo que separa las alternativas.

Windows no mejora el problema: un proceso de integridad media no puede abrir uno
de integridad alta con `PROCESS_TERMINATE`, y además `ShellExecuteEx` con el
verbo `runas` no permite redirigir stdio, así que recuperar el XML exigiría un
named pipe o un fichero temporal.

### 8.4 Alternativas evaluadas

**A · Sin privilegios.** `-sT`, `-sn` por TCP, más una recuperación parcial
barata: leer la caché ARP del sistema (`arp -an`) tras el barrido, que devuelve
MAC y fabricante de lo que el sistema ya ha visto, sin pedir nada. Streaming,
cancelación y trazabilidad triviales y correctos. El adaptador `arp-scan` nace
muerto y el inventario tiene el agujero de §8.2.

**B · Elevación por ejecución** vía `osascript … with administrator privileges`.
El diálogo lo pinta el sistema y **la contraseña nunca pasa por el proceso** —
cumple "nunca almacenar credenciales" en sentido fuerte: ni siquiera se tocan.
Nada queda instalado. La cancelación se resuelve con un wrapper centinela: el
proceso root vigila un fichero, la app lo crea, el wrapper mata a su hijo. El
riesgo de interpolación en AppleScript se contiene con ruta absoluta resuelta en
preflight, argv construido solo por el adaptador (nunca desde texto libre de la
UI) y un quoter propio con tests.

**C · Helper privilegiado launchd + XPC (`SMAppService`).** La forma canónica en
macOS: cancelación real por API, una sola autenticación. A cambio deja un
demonio root instalado permanentemente, exige firma Developer ID para arrancar,
y en un repositorio público de seguridad invita —con razón— al escrutinio.
Superficie desproporcionada para v1. **Descartada.**

### 8.5 Decisión

**A por defecto. B como fase condicional y opt-in por ejecución.** Ninguna fase
se ejecuta elevada sin que el operador lo pida explícitamente en esa ejecución.
La app nunca corre entera como root.

Dos detalles que se mantienen pase lo que pase, porque son gratis:

- **`-oX -` a stdout, nunca `-oX fichero`.** El XML lo captura el proceso no
  privilegiado y lo escribe él. Aunque nmap corra como root, en `raw/` no
  aparece jamás un fichero propiedad de root que luego exija autenticarse otra
  vez para purgar.
- **`in_scope` se evalúa antes de construir el argv.** Elevar no amplía el
  alcance: son ejes independientes y el guard es el mismo objeto en ambos
  caminos.

### 8.6 Spike previo (Fase 0) — ✅ completado 2026-08-27

Existía una vía que **no se daba por buena sin verificar**: ChmodBPF (el
`launchd` que instala Wireshark) abre `/dev/bpf*` a un grupo y, combinado con
`--send-eth`, podría permitir SYN y ARP sin root en el segmento local. Su
equivalente en Windows es instalar Npcap **sin** la opción de restringir el
driver a administradores, que es una casilla soportada del instalador y no un
apaño — ese lado de la pregunta sigue sin probarse, porque no es donde se hacen
las auditorías.

Era la misma pregunta en las dos plataformas: *¿se pueden tener raw packets sin
ser root?* Se resolvió empíricamente en la red propia del consultor, sin
cliente y sin esperar a nadie. **Resultado: no.** Con ChmodBPF instalado y el
usuario en el grupo `access_bpf`, `nmap -sn -PR --send-eth` sin `sudo` encontró
2 de 5 hosts reales del segmento, sin MAC ni fabricante en ninguno, y tardó más
de cuatro veces lo que la misma orden con `sudo` — la firma de una sonda de
reserva, no de ARP real. Evidencia completa y análisis en
[ADR-0004](adr/0004-privilegios-en-macos.md).

B deja de ser opcional y sube en el plan de fases (§14) a justo detrás de la
Fase 5.

---

## 9. Ejecución, streaming y cancelación (Fase 5)

### 9.1 Módulos

Tres responsabilidades, tres ficheros:

- **`exec.rs`** (ya existe desde la Fase 3, con la verja). Gana la mecánica de
  proceso: lanzar el hijo en su propio grupo de procesos, leer stdout/stderr
  por líneas de forma asíncrona, matar el grupo al cancelar. Sin SQL — sigue
  siendo el módulo de "esto es lo que hay que comprobar/ejecutar", no el de
  "esto es lo que se guarda".
- **`runs.rs`** (nuevo). Toda la persistencia: crear y cerrar filas de
  `tool_run`, hacer upsert de `host`/`service`, insertar `observation`, y
  `load_known_state()` para reconstruir el `KnownState` que alimenta el
  `plan()` de la siguiente fase. Son funciones sobre una `Connection`, sin
  lanzar ningún proceso — testeables igual que `scope.rs`.
- **`orchestrator.rs`** (nuevo). El pegamento con estado: arma el
  `PlanContext`, llama `adapter.plan()`, y por cada `Invocation` encadena
  verja → spawn → emitir eventos → parsear → persistir. Aquí vive el ciclo de
  vida completo de una fase de ejecución.

### 9.2 Streaming

El núcleo lee stdout y stderr por líneas y emite eventos Tauri `run:log`,
`run:progress` y `run:done`. Las líneas se agrupan en lotes para no saturar el
puente; el buffer de log en la UI está acotado, con la salida completa siempre
disponible en `raw/`.

### 9.3 Progreso

`progress_from` indica al núcleo de qué flujo salen las líneas de progreso;
`parse_progress` las interpreta. Es específico de cada herramienta y por eso
vive en el adaptador.

### 9.4 Cancelación

El hijo se lanza en su propio grupo de procesos (`setpgid` al arrancar, en
Unix). Cancelar envía `SIGTERM` al grupo y `SIGKILL` tras un plazo de gracia.
En Windows, sin un equivalente igual de limpio a un grupo de procesos POSIX,
la cancelación es `Child::kill()` sin paso amable — coherente con que Windows
ya no recibe tampoco el trabajo de elevación (§8.1). El `tool_run` queda con
`status='cancelled'`, y la salida parcial se conserva marcada como tal — una
recolección interrumpida sigue siendo evidencia, y borrarla sería peor que
guardarla mal etiquetada. La orquestación usa `tokio` (`process`, `io-util`,
`time`, `sync`) sobre el runtime que Tauri ya trae — las tareas se lanzan con
`tauri::async_runtime::spawn`, sin montar un segundo runtime.

### 9.5 Timeouts

Cada `Invocation` trae el suyo; agotarlo es una cancelación con causa
registrada, vía `tokio::time::timeout`.

### 9.6 Tres huecos que cierra esta fase

Todos ledgereados en revisiones de fases anteriores como "requisito de la
Fase 5":

- **`verja()` deja de fiarse de `Invocation.needs_privilege`.** Gana un
  parámetro `effective_privileged: bool` que el orquestador rellena con
  `preflight::running_privileged()` real, no con lo que el adaptador declaró
  de sí mismo.
- **`validate_binary` deja de arriesgarse a un falso rechazo por symlinks de
  Homebrew.** No se canoniza (eso rompería los tests actuales, que usan rutas
  que no existen en disco) — el orquestador resuelve el binario **una sola
  vez** y usa esa misma `PathBuf` tanto para lanzar como para comparar. El
  hueco desaparece por construcción.
- **Revalidación de versión antes de ejecutar.** Justo antes de cada `spawn`,
  se repite `--version` contra ese mismo binario y se compara con
  `min_version` otra vez: si la versión cambió entre el preflight y ahora
  (un `brew upgrade` de por medio), no se lanza.

### 9.7 Confirmación antes de ejecutar

Antes de lanzar cualquier fase, el operador ve el argv exacto que va a
correr — la misma línea que quedará en `tool_run.argv_json` — y confirma
explícitamente. Barato de construir, y coherente con la regla de
trazabilidad: nada se ejecuta sin que el operador haya visto qué es.

### 9.8 Alcance de la Fase 5

Pantalla de ejecución en vivo (lanzar, ver el log en tiempo real, progreso,
cancelar) más la capa de persistencia que la hace posible. **Una pantalla de
resultados navegable —tablas de hosts y servicios— queda fuera de esta fase**
y se hace cuando la Fase de exportadores ya necesite leer esos mismos datos
para componer `resumen.md`. La Fase 5 termina en: se lanzó, se vio en vivo, se
puede cancelar, y al terminar se ve un recuento (N hosts, N servicios, N
observaciones) — no una tabla explorable.

### 9.9 De dónde salen los objetivos de cada fase

`Scope` valida una dirección o un nombre concretos; no expande un CIDR
completo en la lista de direcciones que contiene, así que no hay manera de
"lanzar contra todo el alcance autorizado" automáticamente sin construir antes
esa enumeración, y esta fase no la construye.

El operador escribe los objetivos de la ejecución (una o varias direcciones u
hostnames) en la propia pantalla. Ese texto se valida con
`Scope::validate_target` — la misma función que ya resuelve hostnames y exige
que **todas** sus direcciones caigan dentro del alcance — **en cada fase que
se lanza, no solo en la primera**: el operador puede editar la lista entre una
fase y la siguiente, y aunque no la toque, se re-evalúa igual. Así el alcance
se comprueba antes de construir el argv en todos los casos, sin excepción,
tal y como exige §6.

`Phase::PortSweep` y `Phase::Services` no piden objetivos nuevos al operador
—los derivan de `ctx.known.hosts`/`ctx.known.services`, que es precisamente
para lo que existe `scoped_target_de` (Fase 4)— pero sí necesitan que
`ctx.targets` seguir conteniendo la lista vigente, para que esa función pueda
seguir verificando que cada host conocido sigue estando entre los objetivos
autorizados de esta ejecución.

---

## 10. Exportación, purga y política de datos

### 10.1 Artefactos

En `<carpeta elegida>/<codename>/`:

```
raw/                salida original de cada herramienta, sin tocar
hosts.csv
services.csv
observations.json
toolruns.json       trazabilidad completa
scope.json          alcance declarado y exclusiones aplicadas
resumen.md          ← el fichero de trabajo
```

`scope.json` se añade a la lista original: el alcance autorizado forma parte de
la trazabilidad tanto como el comando ejecutado, y en `resumen.md` solo aparece
en prosa.

### 10.2 `resumen.md`

Es el fichero que se abre para redactar el informe del cliente. Un solo archivo,
autocontenido, sin dependencias.

```
# <codename> — Informe de recolección
   metadatos: fechas, autorizante, referencia del documento,
   alcance declarado, herramientas y versiones empleadas

## 1. Cobertura          rangos, hosts vivos, puertos abiertos, duración
## 2. Inventario de hosts tabla: IP · hostname · MAC · fabricante · SO · etiquetas
## 3. Servicios por host  una subsección por host
## 4. Observaciones       agrupadas por kind, dentro por host
## 5. Trazabilidad        seq · herramienta · versión · comando · inicio ·
                          duración · exit · sha256 del raw
## 6. Notas de cobertura  qué NO se hizo y por qué
```

La sección 6 se genera desde la matriz de capacidades: fases deshabilitadas por
herramienta ausente, modo sin privilegios y qué implica, exclusiones de alcance
aplicadas, ejecuciones canceladas o con timeout. Es lo que permite matizar el
informe del cliente con honestidad, y por eso se genera sola en vez de confiarse
a la memoria.

### 10.3 Purga

Secuencia: cerrar la conexión → borrar recursivamente el directorio del
engagement → verificar ausencia → marcar la lápida en `index.db`.

**La carpeta de exportación NO se purga.** Es el entregable y vive fuera del
control de la app. La UI lo dice explícitamente en el diálogo de purga, para que
nadie confunda "he purgado" con "he borrado el trabajo".

**Auditoría de privacidad** (Fase 7): una prueba que ejecuta un engagement
completo contra objetivos sintéticos, purga, y después rastrea `$TMPDIR`,
`~/Library/Caches`, `~/Library/Logs`, ficheros `-wal`/`-shm` y el directorio de
la app buscando cualquier resto. `DATA-POLICY.md` documenta qué se guarda, dónde
y durante cuánto tiempo, incluida la lápida.

---

## 11. Datos sintéticos: regla mecánica

Los fixtures usan **exclusivamente**:

- IPv4: rangos de documentación RFC 5737 — `192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`
- IPv6: `2001:db8::/32` (RFC 3849)
- Hostnames: `.example`, `example.com`, `example.org` (RFC 2606)
- MAC: direcciones localmente administradas (`02:…`, `06:…`, `0a:…`, `0e:…`)

**CI rechaza cualquier IP fuera de esos rangos en `fixtures/`.** Es una regla
comprobable con una expresión regular, y por eso convierte "cero datos de
clientes" de una intención en una propiedad verificada. Rangos RFC 1918 quedan
prohibidos en fixtures precisamente porque un `192.168.1.x` real y uno inventado
son indistinguibles a simple vista.

`tools/gen-fixtures/` produce salidas sintéticas conformes a esta regla,
partiendo de escaneos del laboratorio propio con las direcciones reescritas.

---

## 12. Modelo de amenazas de la propia app

| # | Amenaza | Mitigación |
|---|---|---|
| T1 | Escanear algo fuera de alcance | Guard central, `ScopedTarget` infabricable, verja sobre el argv, IPs en vez de hostnames |
| T2 | Datos de cliente que sobreviven al encargo | Directorio por engagement, purga verificable, `temp_store=MEMORY`, auditoría de restos |
| T3 | Datos de cliente en el repositorio público | Fixtures solo con rangos RFC, comprobación en CI, `.gitignore` del app-data dir |
| T4 | Invocación en modo intrusivo | `allowed_flags` por herramienta, con marca `needs_privilege`; el proceso no arranca si un flag falta o no cumple su condición |
| T5 | Binario suplantado | Ruta absoluta resuelta en preflight y versión revalidada antes de cada ejecución |
| T6 | Inyección de comandos | Argv como array, sin shell; en la ruta elevada, quoter propio con tests |
| T7 | Exfiltración por telemetría | No existe; CI falla si aparece un cliente HTTP en los lockfiles (§13) |
| T8 | Abuso de la elevación | Por ejecución, opt-in, sin credenciales almacenadas, sin demonio persistente |
| T9 | Ficheros root en el directorio del engagement | `-oX -`; el proceso no privilegiado escribe el fichero |
| T10 | Datos en claro en disco robado | FileVault, comprobado y avisado en preflight (ADR-0003) |

---

## 13. Testing y CI

**Tests que importan:**

- `scope_guard.rs` — enforcement de alcance (§6), incluida la paridad TS↔Rust.
- `parsers/` — un test por adaptador contra fixtures. Como `parse` es pura, son
  baratos y deterministas.
- `purge.rs` — tras purgar, el path no existe y no queda nada en otros sitios.
- Verja — un adaptador de prueba que intenta colar una IP interpolada, una
  bandera no permitida y un binario distinto: los tres deben fallar.
- Quoter de AppleScript — la Fase 0 confirmó que la elevación hace falta, así
  que esto entra sí o sí, en la fase de elevación (§14).

**CI (GitHub Actions):** lint · typecheck · tests · build en macOS y Windows ·
paridad de claves i18n es/en · regla de rangos RFC en `fixtures/` · **ausencia de
cliente HTTP**: `Cargo.lock` y `package-lock.json` no pueden contener `reqwest`,
`ureq`, `isahc`, `axios` ni `node-fetch`, y `hyper` solo como dependencia
transitiva de servidor. Una excepción exige justificarse en el PR: la app no
habla con la red, solo lo hacen las herramientas que lanza.

**i18n:** es-ES y en-US desde la Fase 1, con paridad de claves como en `saldio`.
El coste marginal es bajo haciéndolo desde el principio y muy alto
retrofiteándolo.

---

## 14. Plan de fases

| Fase | Contenido |
|---|---|
| **0** | ✅ **Spike de privilegios** (macOS ChmodBPF + `--send-eth`; Windows Npcap sin restricción). Completado 2026-08-27: ChmodBPF no basta, hace falta elevación — ver [ADR-0004](adr/0004-privilegios-en-macos.md) |
| 1 | ✅ Scaffold Tauri + modelo de datos + migraciones + i18n + ADRs |
| 2 | ✅ Alcance + guard `in_scope` + tests + espejo TS con test de paridad |
| 3 | ✅ Trait de adaptador + verja + detección de herramientas + pantalla de preflight |
| 4 | ✅ Adaptador nmap (descubrimiento y servicios), parser XML, fixtures sintéticos, `gen-fixtures` |
| 5 | UI de ejecución: streaming, progreso, cancelación |
| 6 | Elevación de privilegios — antes condicional ("Fase 9"); el spike de la Fase 0 la confirmó necesaria, así que sube aquí, justo detrás de la Fase 5 |
| 7 | Exportadores + `resumen.md` |
| 8 | Purga + auditoría de privacidad |
| 9 | Adaptadores httpx y nuclei |
| 10 | Empaquetado, firma y notarización en macOS |

Un commit por fase, `npm run check` en verde al final de cada una, parada a
revisión antes de continuar.

---

## 15. Fuera de alcance en v1

- Explotación, fuerza bruta y cualquier prueba destructiva — permanentemente.
- Puntuación de severidad o riesgo generada por la app.
- Empaquetado de binarios de terceros (ADR-0001).
- Helper privilegiado persistente (§8.4 C).
- Cifrado de la base a nivel de aplicación (ADR-0003).
- Adaptadores más allá de nmap, httpx y nuclei: rustscan, masscan, whatweb,
  testssl, sslscan, enum4linux-ng, ssh-audit, avahi-browse, arp-scan. La
  arquitectura los admite sin refactor; ese es el criterio de éxito de §7.
- Sincronización, cuentas, servidor propio, telemetría — permanentemente.
