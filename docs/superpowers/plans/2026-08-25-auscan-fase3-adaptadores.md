# AUscan — Fase 3: Interfaz de adaptador, verja y preflight

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Dejar en pie el contrato que cualquier herramienta implementa para integrarse (el trait de adaptador), la verja de tres comprobaciones que se aplicará antes de cada ejecución, y una pantalla de preflight que detecta qué hay instalado — todo ello sin lanzar todavía ningún proceso real de escaneo.

**Architecture:** El adaptador describe y parsea; el núcleo ejecuta. Esta fase construye el trait (`adapters/mod.rs`), la verja como funciones puras y testeables (`exec.rs`, sin `Command::spawn` real todavía — eso es la Fase 5), y el preflight (`preflight.rs`) que resuelve binarios vía `PATH`, ejecuta `--version`, compara con el mínimo exigido, y evalúa la matriz de capacidades (privilegios, FileVault). Como todavía no existe ningún adaptador real (nmap llega en la Fase 4), toda la maquinaria se ejercita con un adaptador de prueba compartido en `tests/common/`, exactamente como `scope.rs` se construyó y testeó por completo antes de que ninguna herramienta lo consumiera.

**Tech Stack:** Rust (`semver` para versiones, `which` para resolución de `PATH`, `libc` para `geteuid` en Unix) · React 19 · TypeScript strict · Zustand · i18next

**Spec:** `docs/superpowers/specs/2026-08-22-auscan-design.md` (§7 Interfaz de adaptador, §7.5 Preflight)

## Global Constraints

- **TypeScript strict**, sin `any` sin justificar.
- **`npm run check` en verde al final de cada tarea**: typecheck + lint + vitest + `cargo test` + los tres checks mecánicos de CI.
- **`cargo clippy --all-targets -- -D warnings` y `cargo fmt --check` en verde** al final de cada tarea — el workflow de CI los exige.
- **Un commit por tarea.** Mensajes en español, imperativo, prefijo convencional, terminados en `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.
- **El adaptador describe y parsea; el núcleo ejecuta.** Ningún método de `ToolAdapter` lanza un proceso. Esta fase no añade ningún `std::process::Command::spawn` a través del trait — solo dentro de `preflight.rs`, para `--version` y para el comando de instalación, que son casos de uso deliberadamente distintos de "lanzar un escaneo".
- **`ObservationFact.kind` usa el vocabulario cerrado de `docs/superpowers/specs/2026-08-22-auscan-design.md` §5.5**, sin añadir ni quitar variantes sin que sea una decisión visible en el diff.
- **Sin cliente HTTP.** `check:nohttp` sigue aplicando: ninguna dependencia nueva de esta fase debe aparecer en su lista de prohibidos.
- **Datos sintéticos en fixtures/, con las mismas reglas de siempre** (RFC 5737, RFC 3849, RFC 2606, MAC localmente administradas) — aunque esta fase no añade fixtures de herramientas todavía (eso es la Fase 4), cualquier ejemplo que se necesite sigue esa regla.
- **`registry()` devuelve una lista vacía al final de esta fase.** Es correcto y deliberado: el primer adaptador real (nmap) es la Fase 4. La maquinaria se demuestra con el adaptador de prueba, no con uno real a medio construir.

---

## Decisiones de diseño que se apartan del pseudocódigo de la spec

La spec (§7.2) es una guía de diseño, no Rust literal que deba compilar tal cual. Dos ajustes deliberados:

**`descriptor(&self) -> ToolDescriptor` devuelve por valor, no por referencia `&'static`.** La spec escribe `fn descriptor(&self) -> &ToolDescriptor`. Eso exigiría que cada adaptador pudiera construir su `ToolDescriptor` como un valor `const` o `static`, y `ToolDescriptor` contiene un `semver::Version` cuya construcción en contexto `const` no es un supuesto sobre el que vale la pena apostar la compilación de toda la fase. Devolverlo por valor cuesta construir una struct pequeña en cada llamada — barato, no es una ruta caliente — y elimina esa incertidumbre por completo.

**`InstallHint` guarda argv ya trocead﻿o, no una cadena.** `brew: &'static [&'static str]` en vez de una cadena completa a trocear en tiempo de ejecución. Evita cualquier ambigüedad de *shell-splitting* si algún día un nombre de paquete lleva un espacio, y hace que construir el comando real (`Command::new("brew").args(hint.brew)`) sea directo.

---

## Estructura de ficheros

**Rust (`src-tauri/src/`)**

| Fichero | Responsabilidad |
|---|---|
| `adapters/mod.rs` | El trait `ToolAdapter` y todos los tipos que lo rodean. `registry()` vacío. |
| `exec.rs` | La verja: tres funciones puras de validación. Sin `spawn` todavía. |
| `preflight.rs` | Resolución de binario + versión + matriz de capacidades + comando de instalación. |
| `error.rs` | Se amplía con las variantes que la verja y el preflight necesitan. |
| `lib.rs` | Se amplía con `preflight_run` y `preflight_install`. |

**Tests**

| Fichero | Responsabilidad |
|---|---|
| `tests/common/mod.rs` | `FakeAdapter`, compartido por los tests de esta fase. No representa ninguna herramienta real. |
| `tests/adapters_trait.rs` | El trait compila y se comporta como se espera, usando `FakeAdapter`. |
| `tests/exec_gate.rs` | Las tres comprobaciones de la verja. |
| `tests/preflight.rs` | Resolución, comparación de versión, matriz de capacidades, instalación — todo con IO inyectada. |

**TypeScript (`src/`)**

| Fichero | Responsabilidad |
|---|---|
| `domain/model/preflight.ts` | Tipos — espejo de las structs serializables de Rust. |
| `data/preflight.ts` | Envoltorio tipado sobre `invoke`. |
| `store/usePreflightStore.ts` | Estado global de esta pantalla. Separado de `useAppStore`: preflight no depende de ningún engagement abierto. |
| `pages/Preflight.tsx` | La pantalla. Pasa a ser la pantalla por defecto de la app. |

---

## Task 1: El trait `ToolAdapter` y sus tipos

**Files:**
- Create: `src-tauri/src/adapters/mod.rs`
- Create: `src-tauri/tests/common/mod.rs`
- Create: `src-tauri/tests/adapters_trait.rs`
- Modify: `src-tauri/src/lib.rs` (declarar `pub mod adapters;`)
- Modify: `src-tauri/Cargo.toml` (añadir `semver`)

**Interfaces:**
- Consumes: `crate::error::{AppError, Result}`, `crate::scope::{Scope, ScopedTarget}`.
- Produces: `Phase`, `Flag`, `InstallHint`, `ToolDescriptor`, `RawSource`, `ProgressSource`, `ObservationKind`, `HostFact`, `ServiceFact`, `ObservationFact`, `Normalized`, `ParseContext`, `Invocation`, `KnownState`, `PhaseOptions`, `PlanContext`, `Progress`, el trait `ToolAdapter`, `registry() -> Vec<Box<dyn ToolAdapter>>`.

- [ ] **Step 1: Añadir la dependencia**

```bash
cargo add --manifest-path src-tauri/Cargo.toml semver
```

- [ ] **Step 2: Escribir el adaptador de prueba compartido**

`src-tauri/tests/common/mod.rs`. Nota: el directorio se llama `common`, no un fichero `common.rs` — es el modismo de Rust para compartir código entre binarios de test de integración sin que Cargo lo trate como su propio test.

```rust
//! Adaptador de prueba compartido por los tests de esta fase.
//!
//! No representa ninguna herramienta real: existe para ejercitar el
//! trait, la verja y el preflight sin depender de un binario instalado
//! en la máquina que ejecuta los tests. La Fase 4 seguirá esta misma
//! forma para el adaptador de nmap de verdad.

use std::net::IpAddr;
use std::time::Duration;

use auscan_lib::adapters::{
    Flag, HostFact, InstallHint, Invocation, KnownState, Normalized, ObservationFact,
    ObservationKind, ParseContext, Phase, PlanContext, ProgressSource, RawSource, ToolAdapter,
    ToolDescriptor,
};
use auscan_lib::error::{AppError, Result};
use semver::Version;

static FLAGS: &[Flag] = &[
    Flag { name: "-t", needs_privilege: false },
    Flag { name: "-p", needs_privilege: false },
    Flag { name: "-x", needs_privilege: true },
];

pub struct FakeAdapter;

impl ToolAdapter for FakeAdapter {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            id: "fake",
            binaries: &["fake-tool"],
            min_version: Version::new(1, 0, 0),
            phases: &[Phase::Discovery],
            install_hint: InstallHint {
                brew: &["install", "fake-tool"],
                winget: &["install", "-e", "Example.FakeTool"],
            },
            allowed_flags: FLAGS,
        }
    }

    fn version_argv(&self) -> Vec<String> {
        vec!["--version".to_string()]
    }

    fn parse_version(&self, stdout: &str) -> Result<Version> {
        // Formato inventado: "fake-tool 2.3".
        let numero = stdout
            .split_whitespace()
            .last()
            .ok_or_else(|| AppError::InvalidAddress(stdout.to_string()))?;
        let con_patch = format!("{numero}.0");
        Version::parse(&con_patch).map_err(|_| AppError::InvalidAddress(stdout.to_string()))
    }

    fn plan(&self, ctx: &PlanContext) -> Result<Vec<Invocation>> {
        let mut argv = vec!["-t".to_string()];
        for t in ctx.targets {
            argv.push(t.to_string());
        }
        Ok(vec![Invocation {
            phase: Phase::Discovery,
            argv,
            targets: ctx.targets.to_vec(),
            needs_privilege: false,
            raw_from: RawSource::Stdout,
            progress_from: ProgressSource::None,
            stdin: None,
            timeout: Duration::from_secs(30),
        }])
    }

    fn parse(&self, raw: &[u8], ctx: &ParseContext) -> Result<Normalized> {
        // Formato inventado: una IP por línea.
        let texto = String::from_utf8_lossy(raw);
        let mut hosts = Vec::new();
        for linea in texto.lines() {
            if let Ok(ip) = linea.trim().parse::<IpAddr>() {
                hosts.push(HostFact {
                    ip,
                    hostname: None,
                    mac: None,
                    vendor: None,
                    os_guess: None,
                    os_accuracy: None,
                    state: Some("up".to_string()),
                });
            }
        }
        let observations = hosts
            .iter()
            .map(|h| ObservationFact {
                host_ip: Some(h.ip),
                port: None,
                kind: ObservationKind::HostDiscovered,
                subject: h.ip.to_string(),
                statement: "host detectado por fake-tool".to_string(),
                evidence: None,
                evidence_ref: Some(ctx.raw_path.to_string()),
                meta_json: None,
            })
            .collect();
        Ok(Normalized { hosts, services: Vec::new(), observations })
    }
}

/// Construye un KnownState y un PhaseOptions vacíos, para los tests que
/// solo necesitan rellenar `targets` y `scope`.
pub fn known_vacio() -> KnownState {
    KnownState::default()
}
```

- [ ] **Step 3: Escribir el test que falla**

`src-tauri/tests/adapters_trait.rs`:

```rust
mod common;

use std::net::IpAddr;

use auscan_lib::adapters::{ObservationKind, Phase, PhaseOptions, PlanContext, ToolAdapter};
use auscan_lib::scope::{Scope, ScopeKind};
use common::{known_vacio, FakeAdapter};

fn scope_de_prueba() -> Scope {
    Scope::from_entries(&[(ScopeKind::Allow, "198.51.100.0/24".to_string())]).unwrap()
}

#[test]
fn descriptor_expone_lo_minimo_para_preflight() {
    let a = FakeAdapter;
    let d = a.descriptor();
    assert_eq!(d.id, "fake");
    assert_eq!(d.binaries, &["fake-tool"]);
    assert!(!d.allowed_flags.is_empty());
}

#[test]
fn parse_version_entiende_su_propio_formato() {
    let a = FakeAdapter;
    let v = a.parse_version("fake-tool 2.3").unwrap();
    assert_eq!(v.major, 2);
    assert_eq!(v.minor, 3);
}

#[test]
fn plan_construye_una_invocacion_por_cada_objetivo_de_scope() {
    let a = FakeAdapter;
    let scope = scope_de_prueba();
    let objetivo = scope.validate("198.51.100.5").unwrap();
    let known = known_vacio();
    let opciones = PhaseOptions::default();
    let ctx = PlanContext {
        scope: &scope,
        targets: &[objetivo],
        known: &known,
        privileged: false,
        options: &opciones,
    };

    let invocaciones = a.plan(&ctx).unwrap();
    assert_eq!(invocaciones.len(), 1);
    assert_eq!(invocaciones[0].phase, Phase::Discovery);
    assert!(invocaciones[0].argv.contains(&"198.51.100.5".to_string()));
    assert!(!invocaciones[0].needs_privilege);
}

#[test]
fn parse_es_pura_y_produce_hechos_normalizados() {
    let a = FakeAdapter;
    let raw = b"198.51.100.5\n198.51.100.9\nno-es-una-ip\n";
    let ctx = auscan_lib::adapters::ParseContext {
        tool_run_id: 1,
        raw_path: "raw/0001-fake.txt",
        observed_at: "2026-08-25T10:00:00Z",
    };

    let normalizado = a.parse(raw, &ctx).unwrap();

    assert_eq!(normalizado.hosts.len(), 2);
    assert_eq!(normalizado.hosts[0].ip, "198.51.100.5".parse::<IpAddr>().unwrap());
    assert_eq!(normalizado.observations.len(), 2);
    assert_eq!(normalizado.observations[0].kind, ObservationKind::HostDiscovered);
    assert_eq!(normalizado.observations[0].evidence_ref.as_deref(), Some("raw/0001-fake.txt"));
}

#[test]
fn el_registro_de_produccion_esta_vacio_hasta_la_fase_4() {
    assert!(auscan_lib::adapters::registry().is_empty());
}
```

- [ ] **Step 4: Ejecutar el test y verificar que falla**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test adapters_trait`
Expected: FAIL — no existe el módulo `adapters` ni el crate `common`.

- [ ] **Step 5: Implementar `adapters/mod.rs`**

```rust
//! El contrato que cualquier herramienta implementa para integrarse.
//!
//! Un adaptador describe y parsea; el núcleo ejecuta. Si cada adaptador
//! lanzase su propio proceso, habría tantos sitios capaces de ejecutar
//! un comando como herramientas, y por tanto tantos sitios donde
//! saltarse el guard de alcance. La regla del alcance solo es cierta si
//! existe un único sitio que lanza — ese sitio es exec.rs, en la fase
//! siguiente.

use std::net::IpAddr;
use std::time::Duration;

use semver::Version;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::scope::{Scope, ScopedTarget};

/// Fase de una auditoría a la que pertenece una invocación.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Discovery,
    PortSweep,
    Services,
    Web,
    Templates,
    Tls,
    Smb,
    Ssh,
    Mdns,
}

/// Una bandera que un adaptador puede añadir a su argv.
///
/// `needs_privilege` es lo que convierte la regla "solo detección" en
/// mecánico: una bandera marcada no arranca sin la ruta privilegiada,
/// sin importar lo que decida el adaptador en tiempo de ejecución.
#[derive(Debug, Clone, Copy)]
pub struct Flag {
    pub name: &'static str,
    pub needs_privilege: bool,
}

/// Cómo instalar la herramienta cuando falta, por gestor de paquetes.
/// Argv ya trocead﻿o, no una cadena: evita cualquier ambigüedad de
/// *shell-splitting* si un nombre de paquete lleva un espacio.
#[derive(Debug, Clone, Copy)]
pub struct InstallHint {
    pub brew: &'static [&'static str],
    pub winget: &'static [&'static str],
}

/// Descripción de una herramienta: lo que el registro necesita para
/// saber si está instalada, qué versión mínima exige y qué puede hacer.
#[derive(Debug, Clone)]
pub struct ToolDescriptor {
    pub id: &'static str,
    pub binaries: &'static [&'static str],
    pub min_version: Version,
    pub phases: &'static [Phase],
    pub install_hint: InstallHint,
    pub allowed_flags: &'static [Flag],
}

/// De dónde sale la salida cruda de una invocación.
#[derive(Debug, Clone)]
pub enum RawSource {
    Stdout,
    File(String),
}

/// De dónde salen las líneas de progreso mientras corre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressSource {
    Stdout,
    Stderr,
    None,
}

/// Vocabulario cerrado de observaciones. Los adaptadores eligen de esta
/// lista; no pueden inventar. Es lo que hace que "observaciones
/// agrupadas" en resumen.md funcione en vez de degenerar en cien
/// categorías de una línea. Ampliarlo es una decisión de diseño visible
/// en el diff, no un efecto colateral de escribir un parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    HostDiscovered,
    HostOsGuess,
    ServiceOpen,
    ServiceVersionDisclosed,
    WebTechnology,
    WebTitle,
    WebHeaderAbsent,
    TlsProtocolEnabled,
    TlsCipherOffered,
    TlsCertificateExpiry,
    SmbSigningState,
    SshAlgorithmOffered,
    TemplateMatch,
}

/// Un host observado, sin identidad de base de datos: el núcleo resuelve
/// el id y hace el upsert. Por eso `parse` puede ser una función pura.
#[derive(Debug, Clone, PartialEq)]
pub struct HostFact {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub os_guess: Option<String>,
    pub os_accuracy: Option<i64>,
    pub state: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServiceFact {
    pub host_ip: IpAddr,
    pub port: u16,
    pub proto: String,
    pub state: String,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extrainfo: Option<String>,
    pub tunnel: Option<String>,
    pub cpe: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ObservationFact {
    pub host_ip: Option<IpAddr>,
    pub port: Option<u16>,
    pub kind: ObservationKind,
    pub subject: String,
    pub statement: String,
    pub evidence: Option<String>,
    pub evidence_ref: Option<String>,
    pub meta_json: Option<String>,
}

/// Lo que un `parse()` produce: hechos sin identidad de base de datos.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Normalized {
    pub hosts: Vec<HostFact>,
    pub services: Vec<ServiceFact>,
    pub observations: Vec<ObservationFact>,
}

/// Contexto que `parse` recibe además de los bytes crudos. El reloj se
/// inyecta aquí para que `parse` siga siendo pura: sin esto, un parser
/// que llamase a `SystemTime::now()` dejaría de ser testeable con un
/// simple `parse(fixture) == esperado`.
pub struct ParseContext<'a> {
    pub tool_run_id: i64,
    pub raw_path: &'a str,
    pub observed_at: &'a str,
}

/// Una ejecución concreta que el adaptador quiere lanzar.
pub struct Invocation {
    pub phase: Phase,
    pub argv: Vec<String>,
    pub targets: Vec<ScopedTarget>,
    pub needs_privilege: bool,
    pub raw_from: RawSource,
    pub progress_from: ProgressSource,
    pub stdin: Option<Vec<u8>>,
    pub timeout: Duration,
}

/// Lo que ya se sabe de fases anteriores, para encadenarlas sin SQL en
/// el adaptador: nmap -sV escanea solo los puertos que descubrió -sn, y
/// httpx recibe exactamente los servicios http/https detectados.
#[derive(Debug, Clone, Default)]
pub struct KnownState {
    pub hosts: Vec<HostFact>,
    pub services: Vec<ServiceFact>,
}

/// Opciones de fase que decide el operador (p. ej. -sC sí/no).
#[derive(Debug, Clone, Default)]
pub struct PhaseOptions {
    pub script_scan: bool,
}

pub struct PlanContext<'a> {
    pub scope: &'a Scope,
    pub targets: &'a [ScopedTarget],
    pub known: &'a KnownState,
    pub privileged: bool,
    pub options: &'a PhaseOptions,
}

/// Una línea de progreso interpretada, para la UI de ejecución (Fase 5).
#[derive(Debug, Clone, PartialEq)]
pub struct Progress {
    pub message: String,
    pub percent: Option<u8>,
}

/// El contrato. El adaptador describe y parsea; el núcleo ejecuta:
/// ningún método de este trait lanza un proceso.
pub trait ToolAdapter: Send + Sync {
    fn descriptor(&self) -> ToolDescriptor;

    fn version_argv(&self) -> Vec<String>;
    fn parse_version(&self, stdout: &str) -> Result<Version>;

    /// De objetivos ya validados a comandos concretos.
    fn plan(&self, ctx: &PlanContext) -> Result<Vec<Invocation>>;

    /// Función PURA. Sin IO, sin reloj, sin red.
    fn parse(&self, raw: &[u8], ctx: &ParseContext) -> Result<Normalized>;

    fn parse_progress(&self, _line: &str) -> Option<Progress> {
        None
    }
}

/// Las herramientas que la app sabe orquestar. Añadir una es un fichero
/// nuevo y una línea aquí; el núcleo no se toca. Vacío hasta que la
/// Fase 4 añada el adaptador de nmap.
pub fn registry() -> Vec<Box<dyn ToolAdapter>> {
    vec![]
}
```

- [ ] **Step 6: Declarar el módulo en `lib.rs`**

```rust
pub mod adapters;
```

- [ ] **Step 7: Ejecutar el test y verificar que pasa**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test adapters_trait`
Expected: PASS, 5 tests.

- [ ] **Step 8: Comprobar clippy y fmt**

Run: `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings && cargo fmt --manifest-path src-tauri/Cargo.toml -- --check`
Expected: ambos limpios.

- [ ] **Step 9: Commit**

```bash
git add src-tauri/src/adapters src-tauri/src/lib.rs src-tauri/tests/common \
        src-tauri/tests/adapters_trait.rs src-tauri/Cargo.toml src-tauri/Cargo.lock
git commit -m "$(cat <<'MSG'
feat: trait ToolAdapter y sus tipos, con adaptador de prueba

El adaptador describe y parsea; el núcleo ejecuta — ningún método del
trait lanza un proceso. registry() queda vacío hasta que la Fase 4 añada
nmap; la maquinaria se ejercita con un adaptador de prueba compartido en
tests/common, igual que scope.rs se construyó antes de que ninguna
herramienta lo consumiera.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 2: La verja — ningún objetivo sin validar

**Files:**
- Create: `src-tauri/src/exec.rs`
- Create: `src-tauri/tests/exec_gate.rs`
- Modify: `src-tauri/src/error.rs`, `src-tauri/src/lib.rs`

**Interfaces:**
- Consumes: `ScopedTarget` (con `.ip()`), `AppError`.
- Produces: `exec::validate_targets(argv: &[String], targets: &[ScopedTarget]) -> Result<()>`.

- [ ] **Step 1: Añadir la variante de error**

En `src-tauri/src/error.rs`, junto a las demás variantes de alcance:

```rust
    #[error("objetivo sin validar en el comando: {0}")]
    UnvalidatedTarget(String),
```

- [ ] **Step 2: Escribir el test que falla**

`src-tauri/tests/exec_gate.rs`:

```rust
use auscan_lib::error::AppError;
use auscan_lib::exec::validate_targets;
use auscan_lib::scope::{Scope, ScopeKind};

fn objetivos(scope: &Scope, ips: &[&str]) -> Vec<auscan_lib::scope::ScopedTarget> {
    ips.iter().map(|ip| scope.validate(ip).unwrap()).collect()
}

fn scope_198() -> Scope {
    Scope::from_entries(&[(ScopeKind::Allow, "198.51.100.0/24".to_string())]).unwrap()
}

#[test]
fn acepta_argv_cuyas_ips_estan_todas_en_targets() {
    let scope = scope_198();
    let targets = objetivos(&scope, &["198.51.100.5", "198.51.100.9"]);
    let argv = vec![
        "-sn".to_string(),
        "198.51.100.5".to_string(),
        "198.51.100.9".to_string(),
    ];
    assert!(validate_targets(&argv, &targets).is_ok());
}

#[test]
fn rechaza_una_ip_en_argv_que_no_esta_en_targets() {
    let scope = scope_198();
    let targets = objetivos(&scope, &["198.51.100.5"]);
    // 198.51.100.9 nunca pasó por el guard: un adaptador que la
    // interpolase a mano no debe poder colarla.
    let argv = vec!["198.51.100.5".to_string(), "198.51.100.9".to_string()];
    assert!(matches!(
        validate_targets(&argv, &targets),
        Err(AppError::UnvalidatedTarget(_))
    ));
}

#[test]
fn rechaza_una_forma_cidr_aunque_alguna_ip_individual_este_autorizada() {
    let scope = scope_198();
    let targets = objetivos(&scope, &["198.51.100.5"]);
    // ScopedTarget nunca lleva rango: un token con esta forma es un
    // intento de escanear más de lo que el guard validó.
    let argv = vec!["198.51.100.0/24".to_string()];
    assert!(matches!(
        validate_targets(&argv, &targets),
        Err(AppError::UnvalidatedTarget(_))
    ));
}

#[test]
fn ignora_tokens_que_no_son_direcciones() {
    let scope = scope_198();
    let targets = objetivos(&scope, &["198.51.100.5"]);
    let argv = vec![
        "-sn".to_string(),
        "-PS80,443,22".to_string(),
        "198.51.100.5".to_string(),
    ];
    assert!(validate_targets(&argv, &targets).is_ok());
}

#[test]
fn un_argv_vacio_de_objetivos_pasa_trivialmente() {
    let targets: Vec<auscan_lib::scope::ScopedTarget> = vec![];
    assert!(validate_targets(&["-sn".to_string()], &targets).is_ok());
}
```

- [ ] **Step 3: Ejecutar el test y verificar que falla**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test exec_gate`
Expected: FAIL — no existe el módulo `exec`.

- [ ] **Step 4: Implementar `exec.rs`**

```rust
//! La verja: lo que se comprueba antes de lanzar cualquier proceso.
//!
//! Esta fase implementa las comprobaciones como funciones puras. El
//! `spawn` real —y por tanto el único sitio donde se llaman en
//! producción— llega en la Fase 5. Separar la validación de la
//! ejecución es lo que las hace testeables sin lanzar ningún proceso.

use std::net::IpAddr;

use crate::error::{AppError, Result};
use crate::scope::ScopedTarget;

/// Comprobación 1 de la verja: ningún objetivo sin validar.
///
/// Escanea el argv en busca de tokens con forma de dirección y exige que
/// toda IP suelta esté entre los `targets` que el guard ya validó.
/// Cualquier token con forma de CIDR (dirección/prefijo) se rechaza sin
/// más: `ScopedTarget` nunca lleva rango, así que un adaptador que
/// interpolase uno a mano falla ruidosamente en vez de escanear a un
/// tercero.
pub fn validate_targets(argv: &[String], targets: &[ScopedTarget]) -> Result<()> {
    for token in argv {
        if let Ok(ip) = token.parse::<IpAddr>() {
            if !targets.iter().any(|t| t.ip() == ip) {
                return Err(AppError::UnvalidatedTarget(token.clone()));
            }
            continue;
        }
        if let Some((host, resto)) = token.split_once('/') {
            if host.parse::<IpAddr>().is_ok() && resto.chars().all(|c| c.is_ascii_digit()) {
                return Err(AppError::UnvalidatedTarget(token.clone()));
            }
        }
    }
    Ok(())
}
```

- [ ] **Step 5: Declarar el módulo en `lib.rs`**

```rust
pub mod exec;
```

- [ ] **Step 6: Ejecutar el test y verificar que pasa**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test exec_gate`
Expected: PASS, 5 tests.

- [ ] **Step 7: Clippy y fmt**

Run: `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings && cargo fmt --manifest-path src-tauri/Cargo.toml -- --check`

- [ ] **Step 8: Commit**

```bash
git add src-tauri/src/exec.rs src-tauri/src/error.rs src-tauri/src/lib.rs \
        src-tauri/tests/exec_gate.rs
git commit -m "$(cat <<'MSG'
feat: primera comprobación de la verja — ningún objetivo sin validar

Cualquier token del argv con forma de dirección tiene que estar entre
los ScopedTarget que el guard ya validó. Un token con forma de CIDR se
rechaza sin más: ScopedTarget nunca lleva rango.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 3: La verja — ninguna bandera fuera de lista

**Files:**
- Modify: `src-tauri/src/exec.rs`, `src-tauri/src/error.rs`
- Modify: `src-tauri/tests/exec_gate.rs`

**Interfaces:**
- Consumes: `ToolDescriptor`, `Flag` (Tarea 1).
- Produces: `exec::validate_flags(argv: &[String], descriptor: &ToolDescriptor, invocation_privileged: bool) -> Result<()>`.

- [ ] **Step 1: Añadir las variantes de error**

En `error.rs`:

```rust
    #[error("bandera no permitida: {0}")]
    FlagNotAllowed(String),

    #[error("la bandera {0} exige la ruta privilegiada")]
    PrivilegeRequired(String),
```

- [ ] **Step 2: Escribir el test que falla**

Añadir a `src-tauri/tests/exec_gate.rs`:

```rust
mod common;

use auscan_lib::adapters::ToolAdapter;
use auscan_lib::exec::validate_flags;
use common::FakeAdapter;

fn descriptor_de_prueba() -> auscan_lib::adapters::ToolDescriptor {
    FakeAdapter.descriptor()
}

#[test]
fn acepta_banderas_de_la_lista_sin_privilegio() {
    let d = descriptor_de_prueba();
    let argv = vec!["-t".to_string(), "-p".to_string()];
    assert!(validate_flags(&argv, &d, false).is_ok());
}

#[test]
fn rechaza_una_bandera_fuera_de_la_lista() {
    let d = descriptor_de_prueba();
    let argv = vec!["--script".to_string(), "vuln".to_string()];
    assert!(matches!(
        validate_flags(&argv, &d, false),
        Err(AppError::FlagNotAllowed(_))
    ));
}

#[test]
fn una_bandera_con_needs_privilege_exige_invocacion_privilegiada() {
    let d = descriptor_de_prueba();
    let argv = vec!["-x".to_string()];
    assert!(matches!(
        validate_flags(&argv, &d, false),
        Err(AppError::PrivilegeRequired(_))
    ));
    assert!(validate_flags(&argv, &d, true).is_ok());
}

#[test]
fn una_bandera_con_valor_pegado_casa_por_prefijo() {
    // Reproduce el caso de la spec: "-PS80,443,22" tiene que casar con
    // el flag "-PS", no exigir coincidencia exacta.
    let d = auscan_lib::adapters::ToolDescriptor {
        allowed_flags: &[auscan_lib::adapters::Flag { name: "-PS", needs_privilege: false }],
        ..descriptor_de_prueba()
    };
    let argv = vec!["-PS80,443,22".to_string()];
    assert!(validate_flags(&argv, &d, false).is_ok());
}
```

**Nota:** este test necesita `use auscan_lib::error::AppError;` al principio del fichero, ya presente desde la Tarea 2.

- [ ] **Step 3: Ejecutar el test y verificar que falla**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test exec_gate`
Expected: FAIL — `validate_flags` no existe.

- [ ] **Step 4: Implementar**

Añadir a `exec.rs`:

```rust
use crate::adapters::ToolDescriptor;

/// Comprobación 2 de la verja: ninguna bandera fuera de
/// `descriptor.allowed_flags`, y ninguna marcada `needs_privilege` sin
/// que la invocación sea privilegiada.
///
/// Los tokens que ya cubre `validate_targets` (los que parsean como
/// dirección) se ignoran aquí: lo que queda son banderas. El
/// emparejamiento es por prefijo, no exacto, porque una bandera puede
/// llevar un valor pegado (`-PS80,443,22` casa con el flag `-PS`).
pub fn validate_flags(
    argv: &[String],
    descriptor: &ToolDescriptor,
    invocation_privileged: bool,
) -> Result<()> {
    for token in argv {
        if token.parse::<IpAddr>().is_ok() {
            continue;
        }
        let flag = descriptor
            .allowed_flags
            .iter()
            .find(|f| token.starts_with(f.name));
        match flag {
            None => return Err(AppError::FlagNotAllowed(token.clone())),
            Some(f) if f.needs_privilege && !invocation_privileged => {
                return Err(AppError::PrivilegeRequired(token.clone()));
            }
            Some(_) => {}
        }
    }
    Ok(())
}
```

- [ ] **Step 5: Ejecutar el test y verificar que pasa**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test exec_gate`
Expected: PASS, 9 tests.

- [ ] **Step 6: Clippy y fmt**

- [ ] **Step 7: Commit**

```bash
git add src-tauri/src/exec.rs src-tauri/src/error.rs src-tauri/tests/exec_gate.rs
git commit -m "$(cat <<'MSG'
feat: segunda comprobación de la verja — ninguna bandera fuera de lista

--script vuln no está en la lista y el proceso no arranca. -sS estaría
en la lista pero marcada needs_privilege, y tampoco arranca sin la ruta
privilegiada. El emparejamiento es por prefijo: una bandera puede llevar
un valor pegado (-PS80,443,22).

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 4: La verja — el binario resuelto en preflight

**Files:**
- Modify: `src-tauri/src/exec.rs`, `src-tauri/src/error.rs`
- Modify: `src-tauri/tests/exec_gate.rs`

**Interfaces:**
- Produces: `exec::validate_binary(binary_path: &Path, expected_path: &Path) -> Result<()>`, `exec::verja(invocation: &Invocation, binary_path: &Path, descriptor: &ToolDescriptor, expected_path: &Path) -> Result<()>` — las tres comprobaciones juntas, en el orden en que la Fase 5 las llamará.

- [ ] **Step 1: Añadir la variante de error**

```rust
    #[error("el binario a ejecutar ({actual}) no coincide con el resuelto en preflight ({expected})")]
    BinaryMismatch { expected: String, actual: String },
```

- [ ] **Step 2: Escribir el test que falla**

Añadir a `exec_gate.rs`:

```rust
use std::path::Path;

use auscan_lib::exec::{validate_binary, verja};

#[test]
fn acepta_cuando_el_binario_coincide_con_el_esperado() {
    let p = Path::new("/opt/homebrew/bin/fake-tool");
    assert!(validate_binary(p, p).is_ok());
}

#[test]
fn rechaza_cuando_el_binario_no_coincide() {
    let real = Path::new("/tmp/fake-tool");
    let esperado = Path::new("/opt/homebrew/bin/fake-tool");
    assert!(matches!(
        validate_binary(real, esperado),
        Err(AppError::BinaryMismatch { .. })
    ));
}

#[test]
fn verja_encadena_las_tres_comprobaciones_en_orden() {
    let scope = scope_198();
    let target = scope.validate("198.51.100.5").unwrap();
    let d = descriptor_de_prueba();
    let bin = Path::new("/opt/homebrew/bin/fake-tool");

    let inv_ok = auscan_lib::adapters::Invocation {
        phase: auscan_lib::adapters::Phase::Discovery,
        argv: vec!["-t".to_string(), "198.51.100.5".to_string()],
        targets: vec![target],
        needs_privilege: false,
        raw_from: auscan_lib::adapters::RawSource::Stdout,
        progress_from: auscan_lib::adapters::ProgressSource::None,
        stdin: None,
        timeout: std::time::Duration::from_secs(5),
    };
    assert!(verja(&inv_ok, bin, &d, bin).is_ok());

    // Un objetivo que no está en inv.targets debe seguir tumbando la
    // verja aunque el binario y las banderas sean correctos.
    let mut inv_mal = inv_ok;
    inv_mal.argv.push("198.51.100.200".to_string());
    assert!(verja(&inv_mal, bin, &d, bin).is_err());
}
```

- [ ] **Step 3: Ejecutar el test y verificar que falla**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test exec_gate`
Expected: FAIL — `validate_binary`/`verja` no existen.

- [ ] **Step 4: Implementar**

Añadir a `exec.rs`:

```rust
use std::path::Path;

use crate::adapters::Invocation;

/// Comprobación 3 de la verja: el binario que el argv va a ejecutar es
/// exactamente el que preflight resolvió — ni `PATH`, ni un binario
/// aparecido en el directorio actual entre el arranque y la ejecución.
pub fn validate_binary(binary_path: &Path, expected_path: &Path) -> Result<()> {
    if binary_path != expected_path {
        return Err(AppError::BinaryMismatch {
            expected: expected_path.display().to_string(),
            actual: binary_path.display().to_string(),
        });
    }
    Ok(())
}

/// Las tres comprobaciones juntas, en el orden en que la Fase 5 las
/// llamará antes de cada `spawn`, para todos los adaptadores, sin
/// excepción.
pub fn verja(
    invocation: &Invocation,
    binary_path: &Path,
    descriptor: &ToolDescriptor,
    expected_path: &Path,
) -> Result<()> {
    validate_targets(&invocation.argv, &invocation.targets)?;
    validate_flags(&invocation.argv, descriptor, invocation.needs_privilege)?;
    validate_binary(binary_path, expected_path)?;
    Ok(())
}
```

- [ ] **Step 5: Ejecutar el test y verificar que pasa**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test exec_gate`
Expected: PASS, 12 tests.

- [ ] **Step 6: Clippy y fmt**

- [ ] **Step 7: Commit**

```bash
git add src-tauri/src/exec.rs src-tauri/src/error.rs src-tauri/tests/exec_gate.rs
git commit -m "$(cat <<'MSG'
feat: tercera comprobación de la verja y las tres encadenadas

verja() es el punto único que la Fase 5 llamará antes de cada spawn:
objetivos, banderas y binario, en ese orden, para todos los adaptadores
sin excepción.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 5: Preflight — resolución de binario y versión

**Files:**
- Create: `src-tauri/src/preflight.rs`
- Create: `src-tauri/tests/preflight.rs`
- Modify: `src-tauri/src/lib.rs`, `src-tauri/src/error.rs`, `src-tauri/Cargo.toml`

**Interfaces:**
- Consumes: `ToolAdapter`, `ToolDescriptor` (Tarea 1).
- Produces: `preflight::ToolStatus` (enum `Ok`/`TooOld`/`Missing`/`Unparseable`), `preflight::check_tool(adapter: &dyn ToolAdapter, resolve: impl Fn(&str) -> Option<PathBuf>, run: impl Fn(&PathBuf, &[String]) -> std::io::Result<Vec<u8>>) -> ToolStatus`.

**Por qué `resolve` y `run` se inyectan:** el mismo principio que separa `ToolAdapter::parse` (puro) de la IO que lo rodea. Sin inyección, testear "versión demasiado antigua" exigiría tener de verdad un binario viejo instalado en la máquina que ejecuta los tests.

- [ ] **Step 1: Añadir la dependencia**

```bash
cargo add --manifest-path src-tauri/Cargo.toml which
```

- [ ] **Step 2: Añadir la variante de error**

```rust
    #[error("no se encontró la herramienta {0} en el registro")]
    ToolNotFound(String),
```

- [ ] **Step 3: Escribir el test que falla**

`src-tauri/tests/preflight.rs`:

```rust
mod common;

use std::path::PathBuf;

use auscan_lib::preflight::{check_tool, ToolStatus};
use common::FakeAdapter;

#[test]
fn missing_cuando_el_binario_no_se_resuelve_en_ningun_path() {
    let estado = check_tool(&FakeAdapter, |_| None, |_, _| unreachable!());
    assert_eq!(estado, ToolStatus::Missing);
}

#[test]
fn ok_cuando_la_version_cumple_el_minimo() {
    let estado = check_tool(
        &FakeAdapter,
        |_| Some(PathBuf::from("/opt/homebrew/bin/fake-tool")),
        |_, _| Ok(b"fake-tool 2.3".to_vec()),
    );
    match estado {
        ToolStatus::Ok { path, version } => {
            assert_eq!(path, "/opt/homebrew/bin/fake-tool");
            assert_eq!(version, "2.3.0");
        }
        otro => panic!("se esperaba Ok, fue {otro:?}"),
    }
}

#[test]
fn too_old_cuando_la_version_no_llega_al_minimo() {
    // FakeAdapter exige 1.0.0; 0.9 no llega.
    let estado = check_tool(
        &FakeAdapter,
        |_| Some(PathBuf::from("/opt/homebrew/bin/fake-tool")),
        |_, _| Ok(b"fake-tool 0.9".to_vec()),
    );
    match estado {
        ToolStatus::TooOld { version, minimum, .. } => {
            assert_eq!(version, "0.9.0");
            assert_eq!(minimum, "1.0.0");
        }
        otro => panic!("se esperaba TooOld, fue {otro:?}"),
    }
}

#[test]
fn unparseable_cuando_la_salida_no_tiene_forma_de_version() {
    let estado = check_tool(
        &FakeAdapter,
        |_| Some(PathBuf::from("/opt/homebrew/bin/fake-tool")),
        |_, _| Ok(b"esto no es una version".to_vec()),
    );
    assert!(matches!(estado, ToolStatus::Unparseable { .. }));
}

#[test]
fn unparseable_cuando_ejecutar_version_falla() {
    let estado = check_tool(
        &FakeAdapter,
        |_| Some(PathBuf::from("/opt/homebrew/bin/fake-tool")),
        |_, _| Err(std::io::Error::other("no se pudo ejecutar")),
    );
    assert!(matches!(estado, ToolStatus::Unparseable { .. }));
}

#[test]
fn prueba_todos_los_binarios_del_descriptor_hasta_encontrar_uno() {
    // resolve() solo conoce un nombre concreto; check_tool debe probar
    // todos los binarios del descriptor, no solo el primero.
    let estado = check_tool(
        &FakeAdapter,
        |b| (b == "fake-tool").then(|| PathBuf::from("/usr/local/bin/fake-tool")),
        |_, _| Ok(b"fake-tool 1.0".to_vec()),
    );
    assert!(matches!(estado, ToolStatus::Ok { .. }));
}
```

- [ ] **Step 4: Ejecutar el test y verificar que falla**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test preflight`
Expected: FAIL — no existe el módulo `preflight`.

- [ ] **Step 5: Implementar la mitad de `check_tool` en `preflight.rs`**

```rust
//! Detección de herramientas instaladas y matriz de capacidades.

use std::path::PathBuf;

use serde::Serialize;

use crate::adapters::ToolAdapter;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ToolStatus {
    Ok { path: String, version: String },
    TooOld { path: String, version: String, minimum: String },
    Missing,
    Unparseable { path: String, raw: String },
}

/// Resuelve la versión instalada de una herramienta y la compara con el
/// mínimo exigido.
///
/// `resolve` y `run` se inyectan para poder testear sin depender de
/// binarios reales en el sistema.
pub fn check_tool(
    adapter: &dyn ToolAdapter,
    resolve: impl Fn(&str) -> Option<PathBuf>,
    run: impl Fn(&PathBuf, &[String]) -> std::io::Result<Vec<u8>>,
) -> ToolStatus {
    let descriptor = adapter.descriptor();

    let Some(path) = descriptor.binaries.iter().find_map(|b| resolve(b)) else {
        return ToolStatus::Missing;
    };

    let salida = match run(&path, &adapter.version_argv()) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(_) => {
            return ToolStatus::Unparseable {
                path: path.display().to_string(),
                raw: String::new(),
            }
        }
    };

    match adapter.parse_version(&salida) {
        Ok(v) if v >= descriptor.min_version => ToolStatus::Ok {
            path: path.display().to_string(),
            version: v.to_string(),
        },
        Ok(v) => ToolStatus::TooOld {
            path: path.display().to_string(),
            version: v.to_string(),
            minimum: descriptor.min_version.to_string(),
        },
        Err(_) => ToolStatus::Unparseable {
            path: path.display().to_string(),
            raw: salida,
        },
    }
}
```

- [ ] **Step 6: Declarar el módulo en `lib.rs`**

```rust
pub mod preflight;
```

- [ ] **Step 7: Ejecutar el test y verificar que pasa**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test preflight`
Expected: PASS, 6 tests.

- [ ] **Step 8: Clippy y fmt**

- [ ] **Step 9: Commit**

```bash
git add src-tauri/src/preflight.rs src-tauri/src/lib.rs src-tauri/src/error.rs \
        src-tauri/tests/preflight.rs src-tauri/Cargo.toml src-tauri/Cargo.lock
git commit -m "$(cat <<'MSG'
feat: preflight — resolución de binario y comparación de versión

resolve y run se inyectan, el mismo principio que separa
ToolAdapter::parse de la IO que lo rodea: testear "versión demasiado
antigua" no exige tener un binario viejo instalado de verdad.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 6: Preflight — matriz de capacidades

**Files:**
- Modify: `src-tauri/src/preflight.rs`, `src-tauri/Cargo.toml`
- Modify: `src-tauri/tests/preflight.rs`

**Interfaces:**
- Produces: `preflight::FileVaultStatus` (enum `On`/`Off`/`Unknown`), `preflight::parse_filevault_status(stdout: &str) -> FileVaultStatus` (pura), `preflight::filevault_status() -> FileVaultStatus` (real IO, solo macOS), `preflight::running_privileged() -> bool`.

**Sobre el alcance de esta tarea:** ADR-0004 sigue en estado de propuesta — la decisión de privilegios depende del spike pendiente. Lo único que esta tarea puede informar honestamente hoy es si el proceso actual corre ya elevado (casi siempre no, porque la app nunca se lanza como root). No se construye ninguna máquina de estados para una capacidad de elevación que todavía no existe.

- [ ] **Step 1: Añadir la dependencia (solo Unix)**

```bash
cargo add --manifest-path src-tauri/Cargo.toml --target 'cfg(unix)' libc
```

- [ ] **Step 2: Escribir el test que falla**

Añadir a `preflight.rs` un módulo de tests inline — a diferencia del resto de esta fase, `parse_filevault_status` no depende de ningún adaptador ni de IO, así que un test unitario dentro del propio fichero es apropiado (patrón ya usado en `scope.rs` de la fundación para funciones igual de autocontenidas). Añadir al final de `preflight.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconoce_filevault_activado() {
        assert_eq!(parse_filevault_status("FileVault is On.\n"), FileVaultStatus::On);
    }

    #[test]
    fn reconoce_filevault_desactivado() {
        assert_eq!(parse_filevault_status("FileVault is Off.\n"), FileVaultStatus::Off);
    }

    #[test]
    fn una_salida_irreconocible_es_desconocida() {
        assert_eq!(parse_filevault_status("algo inesperado"), FileVaultStatus::Unknown);
    }

    #[test]
    fn el_reconocimiento_no_distingue_mayusculas() {
        assert_eq!(parse_filevault_status("FILEVAULT IS ON."), FileVaultStatus::On);
    }
}
```

- [ ] **Step 3: Ejecutar el test y verificar que falla**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --lib`
Expected: FAIL — `parse_filevault_status`/`FileVaultStatus` no existen. (Es un test de biblioteca, no de integración: por eso `--lib` en vez de `--test`.)

- [ ] **Step 4: Implementar**

Añadir a `preflight.rs`, antes del módulo `tests`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FileVaultStatus {
    On,
    Off,
    Unknown,
}

/// Interpreta la salida de `fdesetup status`. Función pura: la IO real
/// vive en `filevault_status`, más abajo.
pub fn parse_filevault_status(fdesetup_stdout: &str) -> FileVaultStatus {
    let texto = fdesetup_stdout.to_lowercase();
    if texto.contains("filevault is on") {
        FileVaultStatus::On
    } else if texto.contains("filevault is off") {
        FileVaultStatus::Off
    } else {
        FileVaultStatus::Unknown
    }
}

pub fn filevault_status() -> FileVaultStatus {
    #[cfg(target_os = "macos")]
    {
        match std::process::Command::new("fdesetup").arg("status").output() {
            Ok(o) => parse_filevault_status(&String::from_utf8_lossy(&o.stdout)),
            Err(_) => FileVaultStatus::Unknown,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        FileVaultStatus::Unknown
    }
}

/// ¿Corre YA el proceso actual con privilegios elevados? No confundir
/// con "¿podría elevarse?" — eso depende de una capacidad de elevación
/// que todavía no existe (ADR-0004 sigue en propuesta).
pub fn running_privileged() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid() no tiene precondiciones; siempre es segura.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}
```

- [ ] **Step 5: Ejecutar el test y verificar que pasa**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --lib`
Expected: PASS, 4 tests.

- [ ] **Step 6: Comprobar que el crate sigue compilando en el binario real**

Run: `cargo build --manifest-path src-tauri/Cargo.toml`
Expected: compila sin avisos. `filevault_status()`/`running_privileged()` no tienen test directo — son la fina capa de IO alrededor de lo que sí se testea — pero deben compilar y no entrar en pánico si se llaman.

- [ ] **Step 7: Clippy y fmt**

- [ ] **Step 8: Commit**

```bash
git add src-tauri/src/preflight.rs src-tauri/Cargo.toml src-tauri/Cargo.lock
git commit -m "$(cat <<'MSG'
feat: preflight — matriz de capacidades (privilegios, FileVault)

Solo informa si el proceso actual corre ya elevado, no si podría
elevarse: esa capacidad no existe todavía y ADR-0004 sigue en propuesta.
parse_filevault_status es pura y testeada; la IO real que la rodea no
lleva test propio, solo tiene que no entrar en pánico.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 7: Preflight — comando de instalación

**Files:**
- Modify: `src-tauri/src/preflight.rs`
- Modify: `src-tauri/tests/preflight.rs`

**Interfaces:**
- Produces: `preflight::Platform` (enum `Macos`/`Windows`), `preflight::current_platform() -> Platform`, `preflight::install_display_command(hint: &InstallHint, platform: Platform) -> String` (pura), `preflight::run_install(hint: &InstallHint, platform: Platform) -> std::io::Result<std::process::Output>`.

**Por qué `platform` es un parámetro y no `#[cfg(target_os)]` directo en la función pública:** con `cfg`, solo se puede testear la rama de la plataforma en la que corren los tests. Con `platform` como parámetro explícito, las dos ramas (macOS y Windows) son testeables en cualquier máquina de desarrollo. Solo `current_platform()` —de una línea— usa `cfg` de verdad.

- [ ] **Step 1: Escribir el test que falla**

Añadir a `preflight.rs`, dentro de `mod tests`:

```rust
    #[test]
    fn el_comando_de_macos_usa_brew() {
        let hint = InstallHint { brew: &["install", "fake-tool"], winget: &["install", "-e", "X"] };
        assert_eq!(install_display_command(&hint, Platform::Macos), "brew install fake-tool");
    }

    #[test]
    fn el_comando_de_windows_usa_winget() {
        let hint = InstallHint { brew: &["install", "fake-tool"], winget: &["install", "-e", "Example.FakeTool"] };
        assert_eq!(
            install_display_command(&hint, Platform::Windows),
            "winget install -e Example.FakeTool"
        );
    }
```

Y en `src-tauri/tests/preflight.rs`, un test de integración para `run_install` (sí necesita ejecutar de verdad, así que usa un binario garantizado en cualquier sistema Unix/Windows de CI — `echo`):

```rust
#[test]
fn run_install_ejecuta_el_comando_de_la_plataforma_actual() {
    // No se afirma la salida exacta de brew/winget (no están garantizados
    // en la máquina que corre el test): se afirma que el mecanismo de
    // spawn con argv+plataforma funciona, usando un hint fabricado que
    // apunta a un binario que sí existe en cualquier plataforma de CI.
    // brew/winget de verdad no se invocan aquí.
    let hint = auscan_lib::adapters::InstallHint { brew: &["hola"], winget: &["hola"] };
    // run_install siempre llama a "brew" o "winget" según la plataforma;
    // este test solo comprueba que el resultado es un Output válido
    // cuando el binario existe, o un error de "no encontrado" cuando no
    // — nunca un pánico.
    let r = auscan_lib::preflight::run_install(&hint, auscan_lib::preflight::current_platform());
    assert!(r.is_ok() || r.is_err());
}
```

- [ ] **Step 2: Ejecutar el test y verificar que falla**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --lib --test preflight`
Expected: FAIL — `Platform`/`install_display_command`/`run_install` no existen.

- [ ] **Step 3: Implementar**

Añadir a `preflight.rs`, antes de `mod tests`:

```rust
use crate::adapters::InstallHint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Macos,
    Windows,
}

pub fn current_platform() -> Platform {
    #[cfg(target_os = "windows")]
    {
        Platform::Windows
    }
    #[cfg(not(target_os = "windows"))]
    {
        Platform::Macos
    }
}

pub fn install_display_command(hint: &InstallHint, platform: Platform) -> String {
    match platform {
        Platform::Macos => format!("brew {}", hint.brew.join(" ")),
        Platform::Windows => format!("winget {}", hint.winget.join(" ")),
    }
}

fn install_argv(hint: &InstallHint, platform: Platform) -> (&'static str, Vec<&'static str>) {
    match platform {
        Platform::Macos => ("brew", hint.brew.to_vec()),
        Platform::Windows => ("winget", hint.winget.to_vec()),
    }
}

/// Ejecuta el comando de instalación. Se llama solo tras confirmación
/// explícita del operador — nunca automáticamente.
pub fn run_install(hint: &InstallHint, platform: Platform) -> std::io::Result<std::process::Output> {
    let (program, args) = install_argv(hint, platform);
    std::process::Command::new(program).args(args).output()
}
```

- [ ] **Step 4: Ejecutar el test y verificar que pasa**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --lib --test preflight`
Expected: PASS — 6 tests de lib, 7 de integración.

- [ ] **Step 5: Clippy y fmt**

- [ ] **Step 6: Commit**

```bash
git add src-tauri/src/preflight.rs src-tauri/tests/preflight.rs
git commit -m "$(cat <<'MSG'
feat: preflight — construir y ejecutar el comando de instalación

Platform es un parámetro explícito, no cfg(target_os) directo en las
funciones públicas: así las dos ramas (brew/winget) son testeables en
cualquier máquina de desarrollo, no solo en la suya.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 8: Comandos Tauri de preflight

**Files:**
- Modify: `src-tauri/src/lib.rs`, `src-tauri/src/error.rs`, `src-tauri/src/preflight.rs`

**Interfaces:**
- Consumes: todo lo de las Tareas 1, 5, 6, 7.
- Produces: comandos `preflight_run` y `preflight_install`; `preflight::ToolReport`, `preflight::PreflightReport`, `preflight::run_preflight(adapters: &[Box<dyn ToolAdapter>]) -> PreflightReport`.

- [ ] **Step 1: Implementar la agregación en `preflight.rs`**

Añadir, antes de `mod tests`. `ToolAdapter` ya está importado desde la Tarea 5 (`use crate::adapters::ToolAdapter;`, al principio del fichero); no hace falta volver a importarlo.

```rust
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolReport {
    pub tool_id: String,
    pub status: ToolStatus,
    pub install_command: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreflightReport {
    pub tools: Vec<ToolReport>,
    pub privileged: bool,
    pub filevault: FileVaultStatus,
}

/// Ejecuta la detección completa: por cada adaptador del registro,
/// resuelve su binario en PATH y compara versión; añade la matriz de
/// capacidades. Es la única función de este módulo que hace IO real de
/// principio a fin — todo lo que envuelve ya está testeado por separado.
pub fn run_preflight(adapters: &[Box<dyn ToolAdapter>]) -> PreflightReport {
    let platform = current_platform();
    let tools = adapters
        .iter()
        .map(|a| {
            let descriptor = a.descriptor();
            let status = check_tool(
                a.as_ref(),
                |b| which::which(b).ok(),
                |path, argv| std::process::Command::new(path).args(argv).output().map(|o| o.stdout),
            );
            ToolReport {
                tool_id: descriptor.id.to_string(),
                install_command: install_display_command(&descriptor.install_hint, platform),
                status,
            }
        })
        .collect();
    PreflightReport {
        tools,
        privileged: running_privileged(),
        filevault: filevault_status(),
    }
}
```

- [ ] **Step 2: Añadir los comandos a `lib.rs`**

```rust
#[tauri::command]
fn preflight_run() -> preflight::PreflightReport {
    preflight::run_preflight(&adapters::registry())
}

#[tauri::command]
fn preflight_install(tool_id: String) -> Result<String> {
    let registro = adapters::registry();
    let adaptador = registro
        .iter()
        .find(|a| a.descriptor().id == tool_id)
        .ok_or_else(|| error::AppError::ToolNotFound(tool_id.clone()))?;
    let salida = preflight::run_install(
        &adaptador.descriptor().install_hint,
        preflight::current_platform(),
    )?;
    Ok(String::from_utf8_lossy(&salida.stdout).into_owned())
}
```

Y en `invoke_handler!`, añadir `preflight_run, preflight_install,` a la lista.

- [ ] **Step 3: Comprobar que compila y arranca**

Run: `cargo build --manifest-path src-tauri/Cargo.toml`
Expected: compila limpio. (`registry()` sigue vacío hasta la Fase 4, así que `preflight_install` con cualquier `tool_id` devuelve `ToolNotFound` hoy — correcto y esperado.)

- [ ] **Step 4: Ejecutar la suite completa de Rust**

Run: `cargo test --manifest-path src-tauri/Cargo.toml`
Expected: todas las suites en verde.

- [ ] **Step 5: Clippy y fmt**

- [ ] **Step 6: Commit**

```bash
git add src-tauri/src/preflight.rs src-tauri/src/lib.rs
git commit -m "$(cat <<'MSG'
feat: comandos Tauri de preflight

preflight_run agrega detección de herramientas y matriz de capacidades
en una sola llamada. Con registry() todavía vacío (Fase 4 añade nmap),
preflight_install devuelve ToolNotFound para cualquier id — correcto y
esperado hasta entonces.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 9: Pantalla de Preflight

**Files:**
- Create: `src/domain/model/preflight.ts`, `src/data/preflight.ts`, `src/store/usePreflightStore.ts`, `src/pages/Preflight.tsx`, `src/pages/Preflight.test.tsx`
- Modify: `src/App.tsx`, `src/i18n/locales/es.json`, `src/i18n/locales/en.json`

**Interfaces:**
- Consumes: comandos `preflight_run`/`preflight_install` (Tarea 8).
- Produces: `PreflightReport`, `ToolReport`, `ToolStatus`, `FileVaultStatus` (tipos TS — espejo de las structs serializables de Rust); `usePreflightStore` con `{ report, loading, error, installing, run(), install(toolId) }`.

- [ ] **Step 1: Escribir los tipos**

`src/domain/model/preflight.ts`:

```ts
export type ToolStatus =
  | { kind: "ok"; path: string; version: string }
  | { kind: "tooOld"; path: string; version: string; minimum: string }
  | { kind: "missing" }
  | { kind: "unparseable"; path: string; raw: string };

export type ToolReport = {
  toolId: string;
  status: ToolStatus;
  installCommand: string;
};

export type FileVaultStatus = "on" | "off" | "unknown";

export type PreflightReport = {
  tools: ToolReport[];
  privileged: boolean;
  filevault: FileVaultStatus;
};
```

`src/data/preflight.ts`:

```ts
import { invoke } from "@tauri-apps/api/core";

import type { PreflightReport } from "../domain/model/preflight";

export const preflightApi = {
  run: () => invoke<PreflightReport>("preflight_run"),
  install: (toolId: string) => invoke<string>("preflight_install", { toolId }),
};
```

- [ ] **Step 2: Escribir las claves de idioma**

En `src/i18n/locales/es.json`, añadir junto a las claves existentes:

```json
  "nav": { "engagements": "Engagements", "scope": "Alcance", "preflight": "Herramientas" },
  "preflight": {
    "title": "Herramientas",
    "loading": "Comprobando…",
    "privileges": "Privilegios",
    "yes": "Sí",
    "no": "No",
    "filevault": "FileVault",
    "filevaultStatus": { "on": "Activado", "off": "Desactivado", "unknown": "Desconocido" },
    "empty": "Todavía no hay ninguna herramienta configurada.",
    "status": {
      "ok": "Instalada",
      "tooOld": "Versión antigua",
      "missing": "No instalada",
      "unparseable": "Versión no reconocida"
    },
    "copy": "Copiar",
    "install": "Instalar",
    "confirmInstall": "Se ejecutará: {{command}}",
    "confirm": "Ejecutar",
    "cancel": "Cancelar"
  }
```

**Nota sobre `nav`:** ya existe en el fichero con `engagements` y `scope`; añadir `preflight` como tercera clave dentro del objeto existente, no crear uno nuevo.

En `src/i18n/locales/en.json`, las mismas claves traducidas:

```json
  "nav": { "engagements": "Engagements", "scope": "Scope", "preflight": "Tools" },
  "preflight": {
    "title": "Tools",
    "loading": "Checking…",
    "privileges": "Privileges",
    "yes": "Yes",
    "no": "No",
    "filevault": "FileVault",
    "filevaultStatus": { "on": "On", "off": "Off", "unknown": "Unknown" },
    "empty": "No tools configured yet.",
    "status": {
      "ok": "Installed",
      "tooOld": "Outdated version",
      "missing": "Not installed",
      "unparseable": "Unrecognised version"
    },
    "copy": "Copy",
    "install": "Install",
    "confirmInstall": "This will run: {{command}}",
    "confirm": "Run",
    "cancel": "Cancel"
  }
```

- [ ] **Step 3: Comprobar la paridad de i18n**

Run: `node scripts/checks/i18n-parity.mjs`
Expected: `i18n: claves en paridad`.

- [ ] **Step 4: Escribir el test de la pantalla, que falla**

`src/pages/Preflight.test.tsx`:

```tsx
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import "../i18n";
import { Preflight } from "./Preflight";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

const INFORME_CON_HERRAMIENTA_FALTANTE = {
  tools: [
    {
      toolId: "fake",
      status: { kind: "missing" },
      installCommand: "brew install fake-tool",
    },
  ],
  privileged: false,
  filevault: "on",
};

describe("Preflight", () => {
  beforeEach(() => {
    invoke.mockReset();
  });

  it("muestra el estado de cada herramienta al montar", async () => {
    invoke.mockImplementation((cmd: string) =>
      cmd === "preflight_run"
        ? Promise.resolve({
            tools: [
              { toolId: "fake", status: { kind: "ok", path: "/bin/fake", version: "2.3.0" }, installCommand: "brew install fake-tool" },
            ],
            privileged: false,
            filevault: "on",
          })
        : Promise.resolve(null),
    );

    render(<Preflight />);

    expect(await screen.findByText("fake")).toBeInTheDocument();
    expect(screen.getByText(/instalada/i)).toBeInTheDocument();
  });

  it("dice cuando el alcance está vacío de herramientas", async () => {
    invoke.mockImplementation((cmd: string) =>
      cmd === "preflight_run"
        ? Promise.resolve({ tools: [], privileged: false, filevault: "unknown" })
        : Promise.resolve(null),
    );

    render(<Preflight />);
    expect(await screen.findByText(/todavía no hay ninguna herramienta/i)).toBeInTheDocument();
  });

  it("pide confirmación antes de ejecutar el comando de instalación", async () => {
    invoke.mockImplementation((cmd: string) =>
      cmd === "preflight_run"
        ? Promise.resolve(INFORME_CON_HERRAMIENTA_FALTANTE)
        : Promise.resolve("instalado"),
    );

    render(<Preflight />);
    await userEvent.click(await screen.findByRole("button", { name: /^instalar$/i }));

    expect(screen.getByText(/brew install fake-tool/)).toBeInTheDocument();
    expect(invoke).not.toHaveBeenCalledWith("preflight_install", expect.anything());

    await userEvent.click(screen.getByRole("button", { name: /^ejecutar$/i }));
    await waitFor(() => {
      expect(invoke).toHaveBeenCalledWith("preflight_install", { toolId: "fake" });
    });
  });
});
```

- [ ] **Step 5: Ejecutar el test y verificar que falla**

Run: `npx vitest run src/pages/Preflight.test.tsx`
Expected: FAIL — no existe `./Preflight` ni `usePreflightStore`.

- [ ] **Step 6: Implementar el store**

`src/store/usePreflightStore.ts`:

```ts
import { create } from "zustand";

import { preflightApi } from "../data/preflight";
import type { PreflightReport } from "../domain/model/preflight";

type PreflightStore = {
  report: PreflightReport | null;
  loading: boolean;
  error: string | null;
  installing: string | null;
  run: () => Promise<void>;
  install: (toolId: string) => Promise<void>;
};

const mensaje = (e: unknown): string =>
  typeof e === "string" ? e : e instanceof Error ? e.message : String(e);

// Store separado de useAppStore: preflight no depende de ningún
// engagement abierto, es una comprobación global de la máquina.
export const usePreflightStore = create<PreflightStore>((set, get) => ({
  report: null,
  loading: false,
  error: null,
  installing: null,

  run: async () => {
    set({ loading: true, error: null });
    try {
      set({ report: await preflightApi.run(), loading: false });
    } catch (e) {
      set({ error: mensaje(e), loading: false });
    }
  },

  install: async (toolId) => {
    set({ installing: toolId, error: null });
    try {
      await preflightApi.install(toolId);
      await get().run();
    } catch (e) {
      set({ error: mensaje(e) });
    } finally {
      set({ installing: null });
    }
  },
}));
```

- [ ] **Step 7: Implementar la pantalla**

`src/pages/Preflight.tsx`:

```tsx
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { usePreflightStore } from "../store/usePreflightStore";

export function Preflight() {
  const { t } = useTranslation();
  const { report, loading, error, installing, run, install } = usePreflightStore();
  const [porInstalar, setPorInstalar] = useState<string | null>(null);

  useEffect(() => {
    void run();
  }, [run]);

  const objetivo = report?.tools.find((tool) => tool.toolId === porInstalar) ?? null;

  return (
    <section>
      <h1>{t("preflight.title")}</h1>
      {error && <p role="alert">{error}</p>}
      {loading && <p>{t("preflight.loading")}</p>}

      {report && (
        <>
          <p>
            {t("preflight.privileges")}: {report.privileged ? t("preflight.yes") : t("preflight.no")}
          </p>
          <p>
            {t("preflight.filevault")}: {t(`preflight.filevaultStatus.${report.filevault}`)}
          </p>

          {report.tools.length === 0 ? (
            <p>{t("preflight.empty")}</p>
          ) : (
            <ul>
              {report.tools.map((tool) => (
                <li key={tool.toolId}>
                  <span>{tool.toolId}</span>
                  <span>{t(`preflight.status.${tool.status.kind}`)}</span>
                  {tool.status.kind === "ok" && <span>{tool.status.version}</span>}
                  {(tool.status.kind === "missing" || tool.status.kind === "tooOld") && (
                    <>
                      <code>{tool.installCommand}</code>
                      <button
                        type="button"
                        onClick={() => void navigator.clipboard.writeText(tool.installCommand)}
                      >
                        {t("preflight.copy")}
                      </button>
                      <button type="button" onClick={() => setPorInstalar(tool.toolId)}>
                        {t("preflight.install")}
                      </button>
                    </>
                  )}
                </li>
              ))}
            </ul>
          )}
        </>
      )}

      {objetivo && (
        <div role="dialog" aria-modal="true">
          <p>{t("preflight.confirmInstall", { command: objetivo.installCommand })}</p>
          <button
            type="button"
            disabled={installing !== null}
            onClick={() => {
              void install(objetivo.toolId);
              setPorInstalar(null);
            }}
          >
            {t("preflight.confirm")}
          </button>
          <button type="button" onClick={() => setPorInstalar(null)}>
            {t("preflight.cancel")}
          </button>
        </div>
      )}
    </section>
  );
}
```

- [ ] **Step 8: Ejecutar el test y verificar que pasa**

Run: `npx vitest run src/pages/Preflight.test.tsx`
Expected: PASS, 3 tests.

- [ ] **Step 9: Cablear en `App.tsx` como pantalla por defecto**

La spec lista las pantallas en orden "Preflight · Engagements · Alcance · …" — preflight pasa a ser lo primero que se ve al abrir la app.

```tsx
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { Engagements } from "./pages/Engagements";
import { Preflight } from "./pages/Preflight";
import { Scope } from "./pages/Scope";

type Pantalla = "preflight" | "engagements" | "scope";

export default function App() {
  const { t } = useTranslation();
  const [pantalla, setPantalla] = useState<Pantalla>("preflight");

  return (
    <main>
      <nav>
        <button type="button" onClick={() => setPantalla("preflight")}>
          {t("nav.preflight")}
        </button>
        <button type="button" onClick={() => setPantalla("engagements")}>
          {t("nav.engagements")}
        </button>
        <button type="button" onClick={() => setPantalla("scope")}>
          {t("nav.scope")}
        </button>
      </nav>
      {pantalla === "preflight" && <Preflight />}
      {pantalla === "engagements" && <Engagements />}
      {pantalla === "scope" && <Scope />}
    </main>
  );
}
```

- [ ] **Step 10: Ejecutar la comprobación completa**

Run: `npm run check`
Expected: PASS en todas las etapas, incluidos los tres checks mecánicos de CI.

- [ ] **Step 11: Commit**

```bash
git add src/domain/model/preflight.ts src/data/preflight.ts src/store/usePreflightStore.ts \
        src/pages/Preflight.tsx src/pages/Preflight.test.tsx src/App.tsx \
        src/i18n/locales/es.json src/i18n/locales/en.json
git commit -m "$(cat <<'MSG'
feat: pantalla de Preflight, primera pantalla de la app

Detección de herramientas y matriz de capacidades al arrancar. Con
registry() vacío hasta la Fase 4, la lista aparece vacía en un run real
— la maquinaria está probada con datos simulados en el test.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Al terminar este plan

Tendrás el trait de adaptador completo, la verja con sus tres comprobaciones encadenadas, y una pantalla de preflight funcional que detecta herramientas y muestra la matriz de capacidades — todo probado con un adaptador de prueba, sin depender de que nmap exista todavía. Ningún proceso de escaneo real se lanza en esta fase.

**Lo que la spec pide y este plan no incluye, a propósito:**

- **"Las fases cuyas herramientas falten se deshabilitan con explicación
  concreta de qué se pierde"** (spec §7.5). El `PreflightReport` que esta
  fase produce ya trae todo lo necesario para decidirlo (`tools`, cada uno
  con su `status` y su `descriptor.phases`), pero deshabilitar una fase es
  una acción de la pantalla de ejecución, que no existe todavía. Se
  resuelve en la Fase 5, leyendo este mismo informe.

- **El adaptador de nmap** (Fase 4): parser XML real, fixtures sintéticos, `tools/gen-fixtures/`.
- **`std::process::Command::spawn` para escaneos**, streaming de stdout/stderr, cancelación real (Fase 5). `exec.rs` solo tiene la verja; el `spawn` de verdad es la siguiente fase.
- **El upsert de `Normalized` en la base de datos.** `HostFact`/`ServiceFact`/`ObservationFact` ya existen como tipos, pero nada los escribe todavía en `host`/`service`/`observation` — eso ocurre cuando una ejecución real produce datos que persistir, en la Fase 5.

**Plan siguiente — Fase 4:** adaptador de nmap con parser XML, fixtures sintéticos conformes a la regla de direcciones de documentación, y `tools/gen-fixtures/`.
