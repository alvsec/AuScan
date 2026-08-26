# Fase 4 — Adaptador de nmap: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Construir el primer adaptador real (`nmap`) — descriptor, planificación de invocaciones por fase, parser XML puro — más el rediseño de `validate_flags` que la Fase 3 dejó ledgereado como bloqueante, y la herramienta `gen-fixtures`. Al final de esta fase, `adapters::registry()` conoce nmap de verdad, pero nada lo ejecuta todavía: eso es la Fase 5.

**Architecture:** Un solo `struct Nmap` en `src-tauri/src/adapters/nmap.rs` implementa `ToolAdapter` para tres fases (`Discovery`, `PortSweep`, `Services`), encadenadas por `PlanContext.known`. `plan()` es puro (construye `Vec<Invocation>` a partir de objetivos ya validados); `parse()` es puro (XML → `Normalized` vía `roxmltree`, sin IO). `exec.rs::validate_flags` pasa de emparejamiento por prefijo a igualdad exacta, con un nuevo campo `Flag.takes_value` para banderas cuyo valor viaja en el siguiente token del argv.

**Tech Stack:** Rust · `roxmltree` (parser XML de solo lectura) · `regex` (solo para `gen-fixtures`) · fixtures XML sintéticos con direcciones RFC 5737.

**Spec:** `docs/superpowers/specs/2026-08-22-auscan-design.md` (§5.5 vocabulario de `kind`, §7.2 el trait, §7.3 la verja, §7.6 decisiones de nmap v1, §8.2 qué necesita privilegios, §11 regla de fixtures sintéticos)

## Global Constraints

- `cargo clippy --all-targets -- -D warnings` y `cargo fmt --check` deben salir limpios al final de cada tarea.
- Commits en español, modo imperativo, con trailer `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.
- Ninguna dirección fuera de RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) o MAC localmente administrada (segundo nibble del primer octeto en `2`/`6`/`a`/`e`) en NINGÚN fichero del repositorio — el check de fixtures recorre todo lo que `git ls-files` conoce, no solo `fixtures/`. Esto incluye literales dentro de código Rust de test.
- No se amplía el vocabulario de `ObservationKind` (§5.5): nmap v1 usa únicamente `HostDiscovered`, `HostOsGuess`, `ServiceOpen`, `ServiceVersionDisclosed`.
- IPv6 fuera de alcance para el adaptador nmap en esta fase: `plan()` filtra a IPv4 en todas las fases.
- `PhaseOptions.script_scan` (`-sC`) no se usa todavía en `plan()`.
- Solo se registran `ServiceFact`/observaciones para puertos en estado `"open"`; puertos `closed`/`filtered` se leen y se descartan.
- `adapters::registry()` debe devolver exactamente `vec![Box::new(nmap::Nmap)]` al terminar la Fase 4.
- `ObservationFact.statement`/`.subject` van en español, igual que el resto de la app y que la plantilla de `resumen.md` (§10.2 de la spec).

---

## Task 1: Rediseñar `Flag`/`PlanContext` y `validate_flags` a igualdad exacta

Cierra el hueco que la revisión final de la Fase 3 dejó ledgereado: el emparejamiento por prefijo permitía que `-sS` colase bajo un `allowed_flags` que solo pretendía permitir `-s`, y que una IP sin validar se colase pegada a una bandera (`-p198.51.100.200`). Este rediseño tiene que aterrizar ANTES del adaptador de nmap porque nmap es la primera herramienta con banderas reales que colisionan por prefijo (`-s`/`-sS`, `-P`/`-PS`/`-PR`, `-o`/`-oX`).

**Files:**
- Modify: `src-tauri/src/adapters/mod.rs` (struct `Flag`, struct `PlanContext`)
- Modify: `src-tauri/src/exec.rs` (`validate_flags`)
- Modify: `src-tauri/tests/common/mod.rs` (array `FLAGS`)
- Modify: `src-tauri/tests/adapters_trait.rs` (construcción de `PlanContext`)
- Modify: `src-tauri/tests/exec_gate.rs` (tests de `validate_flags`)

**Interfaces:**
- Produces: `pub struct Flag { pub name: &'static str, pub needs_privilege: bool, pub takes_value: bool }` — `takes_value` es lo que consumirán los adaptadores de fases posteriores (Task 2-4) para banderas como `-p` u `-oX`.
- Produces: `pub struct PlanContext<'a> { pub phase: Phase, pub scope: &'a Scope, pub targets: &'a [ScopedTarget], pub known: &'a KnownState, pub privileged: bool, pub options: &'a PhaseOptions }` — Task 2-4 leen `ctx.phase` para decidir qué invocaciones construir.
- Produces: `pub fn validate_flags(argv: &[String], descriptor: &ToolDescriptor, invocation_privileged: bool) -> Result<()>` — misma firma que ya existía, semántica interna nueva.

- [ ] **Step 1: Añadir `takes_value` a `Flag` y `phase` a `PlanContext`**

En `src-tauri/src/adapters/mod.rs`, reemplaza:

```rust
#[derive(Debug, Clone, Copy)]
pub struct Flag {
    pub name: &'static str,
    pub needs_privilege: bool,
}
```

por:

```rust
#[derive(Debug, Clone, Copy)]
pub struct Flag {
    pub name: &'static str,
    pub needs_privilege: bool,
    /// El siguiente token del argv es un valor opaco de esta bandera
    /// ("1-1000", "80,443"): `validate_flags` lo salta sin intentar
    /// casarlo como otra bandera ni como una dirección.
    pub takes_value: bool,
}
```

Y reemplaza:

```rust
pub struct PlanContext<'a> {
    pub scope: &'a Scope,
    pub targets: &'a [ScopedTarget],
    pub known: &'a KnownState,
    pub privileged: bool,
    pub options: &'a PhaseOptions,
}
```

por:

```rust
pub struct PlanContext<'a> {
    /// Qué fase pide el operador ahora mismo. Sin esto, `plan()` no
    /// puede distinguir "todavía no se hizo el barrido de puertos" de
    /// "se hizo y no encontró nada": ambos casos dejan `known` igual de
    /// vacío en el campo relevante.
    pub phase: Phase,
    pub scope: &'a Scope,
    pub targets: &'a [ScopedTarget],
    pub known: &'a KnownState,
    pub privileged: bool,
    pub options: &'a PhaseOptions,
}
```

- [ ] **Step 2: Arreglar los sitios que construyen `Flag`/`PlanContext` para que el crate compile**

En `src-tauri/tests/common/mod.rs`, reemplaza el array `FLAGS`:

```rust
static FLAGS: &[Flag] = &[
    Flag {
        name: "-t",
        needs_privilege: false,
        takes_value: false,
    },
    Flag {
        name: "-p",
        needs_privilege: false,
        takes_value: true,
    },
    Flag {
        name: "-x",
        needs_privilege: true,
        takes_value: false,
    },
];
```

En `src-tauri/tests/adapters_trait.rs`, en `plan_construye_una_invocacion_por_cada_objetivo_de_scope`, añade `phase` como primer campo de la construcción de `PlanContext`:

```rust
let ctx = PlanContext {
    phase: Phase::Discovery,
    scope: &scope,
    targets: &[objetivo],
    known: &known,
    privileged: false,
    options: &opciones,
};
```

Run: `cargo build --manifest-path src-tauri/Cargo.toml`
Expected: FAIL — `src-tauri/tests/exec_gate.rs:134` todavía construye un `Flag` sin `takes_value` (lo arregla el paso siguiente).

- [ ] **Step 3: Reescribir `validate_flags` a igualdad exacta**

En `src-tauri/src/exec.rs`, reemplaza la función completa (doc-comment incluido):

```rust
/// Comprobación 2 de la verja: ninguna bandera fuera de
/// `descriptor.allowed_flags`, y ninguna marcada `needs_privilege` sin
/// que la invocación sea privilegiada.
///
/// El emparejamiento es por igualdad EXACTA, nunca por prefijo: antes de
/// este rediseño, `"-sS".starts_with("-s")` colaba `-sS` bajo un
/// `allowed_flags` que solo pretendía permitir `-s`, y
/// `"-p198.51.100.200"` colaba una IP sin validar pegada a `-p`. Una
/// bandera marcada `takes_value` consume el siguiente token del argv
/// como valor opaco, sin intentar casarlo como otra bandera: así el
/// valor nunca puede confundirse con un flag ni con una dirección.
///
/// **Límite conocido:** `invocation_privileged` lo pone quien llama, a
/// partir de `Invocation.needs_privilege` — y ese campo hoy lo fija el
/// propio adaptador, sin que nada lo verifique contra el privilegio real
/// del proceso (`preflight::running_privileged()` o equivalente). Sigue
/// siendo un requisito de la Fase 5, sin cambios respecto a la Fase 3.
pub fn validate_flags(
    argv: &[String],
    descriptor: &ToolDescriptor,
    invocation_privileged: bool,
) -> Result<()> {
    let mut i = 0;
    while i < argv.len() {
        let token = &argv[i];
        if token.trim().parse::<IpAddr>().is_ok() {
            i += 1;
            continue;
        }
        let flag = descriptor.allowed_flags.iter().find(|f| f.name == token);
        match flag {
            None => return Err(AppError::FlagNotAllowed(token.clone())),
            Some(f) if f.needs_privilege && !invocation_privileged => {
                return Err(AppError::PrivilegeRequired(token.clone()));
            }
            Some(f) if f.takes_value => i += 2,
            Some(_) => i += 1,
        }
    }
    Ok(())
}
```

- [ ] **Step 4: Arreglar y ampliar los tests de `validate_flags` en `exec_gate.rs`**

En `src-tauri/tests/exec_gate.rs`, reemplaza `acepta_banderas_de_la_lista_sin_privilegio`:

```rust
#[test]
fn acepta_banderas_de_la_lista_sin_privilegio() {
    let d = descriptor_de_prueba();
    let argv = vec!["-t".to_string(), "-p".to_string(), "8080".to_string()];
    assert!(validate_flags(&argv, &d, false).is_ok());
}
```

Elimina por completo `una_bandera_con_valor_pegado_casa_por_prefijo` (probaba el comportamiento antiguo, que ahora es justo el que no queremos) y sustitúyela por estas tres:

```rust
#[test]
fn una_bandera_de_valor_exige_un_token_separado_para_el_valor() {
    // Nuevo contrato: el valor de una bandera `takes_value` es SIEMPRE
    // un token de argv aparte, nunca pegado al nombre de la bandera.
    let d = descriptor_de_prueba();
    let argv = vec!["-p".to_string(), "80,443,22".to_string()];
    assert!(validate_flags(&argv, &d, false).is_ok());
}

#[test]
fn una_ip_pegada_a_una_bandera_de_valor_ya_no_se_cuela() {
    // Antes del rediseño, "-p198.51.100.200" casaba por prefijo con
    // "-p". Ahora ese token completo tiene que igualar EXACTAMENTE una
    // entrada de allowed_flags, y no lo hace.
    let d = descriptor_de_prueba();
    let argv = vec!["-p198.51.100.200".to_string()];
    assert!(matches!(
        validate_flags(&argv, &d, false),
        Err(AppError::FlagNotAllowed(_))
    ));
}

#[test]
fn una_bandera_permitida_mas_corta_ya_no_deja_pasar_una_mas_larga() {
    // Reproduce el caso real de nmap que motivó el rediseño: "-s" y
    // "-sS" ya no pueden confundirse porque el emparejamiento es exacto.
    let d = auscan_lib::adapters::ToolDescriptor {
        allowed_flags: &[auscan_lib::adapters::Flag {
            name: "-s",
            needs_privilege: false,
            takes_value: false,
        }],
        ..descriptor_de_prueba()
    };
    let argv = vec!["-sS".to_string()];
    assert!(matches!(
        validate_flags(&argv, &d, false),
        Err(AppError::FlagNotAllowed(_))
    ));
}
```

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test exec_gate`
Expected: PASS — los 16 tests de `exec_gate.rs` (13 anteriores menos 1 eliminado más 3 nuevos, más el resto sin tocar) en verde.

- [ ] **Step 5: `clippy`, `fmt`, suite completa**

Run: `cargo fmt --manifest-path src-tauri/Cargo.toml` luego `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings` luego `cargo test --manifest-path src-tauri/Cargo.toml`
Expected: los tres en verde, sin warnings.

- [ ] **Step 6: Commit**

```bash
git add src-tauri/src/adapters/mod.rs src-tauri/src/exec.rs src-tauri/tests/common/mod.rs src-tauri/tests/adapters_trait.rs src-tauri/tests/exec_gate.rs
git commit -m "$(cat <<'EOF'
fix: validate_flags compara por igualdad exacta, no por prefijo

Añade Flag.takes_value para banderas cuyo valor viaja en un token
separado del argv, y PlanContext.phase para que plan() sepa qué fase
le piden. Cierra el hueco ledgereado en la revisión final de la Fase
3: "-sS" ya no cuela bajo un allowed_flags pensado para "-s", y una IP
ya no puede colarse pegada a una bandera de valor.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: `adapters/nmap.rs` — descriptor, versión, y fase Discovery

Primer adaptador real. Este task cubre solo `Discovery`: descubrimiento de hosts vivos, sin puertos ni SO. Registra `Nmap` en `adapters::registry()`.

**Files:**
- Create: `src-tauri/src/adapters/nmap.rs`
- Create: `fixtures/nmap/0001-discovery-sin-privilegio.xml`
- Create: `fixtures/nmap/0002-discovery-privilegiado.xml`
- Create: `src-tauri/tests/parsers/nmap_discovery.rs` (usa `tests/parsers/` per la estructura de la spec — crea también `src-tauri/tests/parsers/mod.rs` si Cargo lo exige para el directorio)
- Modify: `src-tauri/src/adapters/mod.rs` (`pub mod nmap;`, `registry()`)
- Modify: `src-tauri/src/error.rs` (`AppError::ParseFailed`)
- Modify: `src-tauri/Cargo.toml` (dependencia `roxmltree`)
- Modify: `src-tauri/tests/adapters_trait.rs` (reemplaza el test del registro vacío)

**Interfaces:**
- Consumes: `Flag { name, needs_privilege, takes_value }`, `PlanContext { phase, scope, targets, known, privileged, options }` (Task 1).
- Produces: `pub struct Nmap;` implementando `ToolAdapter`. `descriptor().id == "nmap"`. Tasks 3-4 extienden `descriptor().phases`, `descriptor().allowed_flags`, `plan()` y `parse()` de este mismo fichero.

- [ ] **Step 1: Añadir la dependencia `roxmltree` y el error `ParseFailed`**

En `src-tauri/Cargo.toml`, bajo `[dependencies]`, añade:

```toml
roxmltree = "0.20"
```

En `src-tauri/src/error.rs`, añade una variante nueva (antes de las `#[error(transparent)]` finales):

```rust
    #[error("no se pudo interpretar la salida de la herramienta: {0}")]
    ParseFailed(String),
```

- [ ] **Step 2: Escribir los fixtures de Discovery**

Crea `fixtures/nmap/0001-discovery-sin-privilegio.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sn -PS80,443,22 -PA80 -n -oX - 198.51.100.5 198.51.100.9 198.51.100.12" start="1755000000" startstr="Tue Aug 12 10:00:00 2026" version="7.94" xmloutputversion="1.05">
<scaninfo type="ping" protocol="tcp" numservices="0" services=""/>
<verbose level="0"/>
<debugging level="0"/>
<host starttime="1755000000" endtime="1755000002">
<status state="up" reason="syn-ack" reason_ttl="0"/>
<address addr="198.51.100.5" addrtype="ipv4"/>
<hostnames>
<hostname name="host5.example" type="PTR"/>
</hostnames>
<times srtt="1200" rttvar="600" to="100000"/>
</host>
<host starttime="1755000002" endtime="1755000004">
<status state="up" reason="syn-ack" reason_ttl="0"/>
<address addr="198.51.100.9" addrtype="ipv4"/>
<hostnames>
</hostnames>
<times srtt="1100" rttvar="550" to="100000"/>
</host>
<host starttime="1755000004" endtime="1755000006">
<status state="down" reason="no-response" reason_ttl="0"/>
<address addr="198.51.100.12" addrtype="ipv4"/>
<hostnames>
</hostnames>
</host>
<runstats>
<finished time="1755000006" timestr="Tue Aug 12 10:00:06 2026" elapsed="6.00" summary="Nmap done at Tue Aug 12 10:00:06 2026; 3 IP addresses (2 hosts up) scanned in 6.00 seconds" exit="success"/>
<hosts up="2" down="1" total="3"/>
</runstats>
</nmaprun>
```

Crea `fixtures/nmap/0002-discovery-privilegiado.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sn -PR -n -oX - 198.51.100.0/29" start="1755000100" startstr="Tue Aug 12 10:01:40 2026" version="7.94" xmloutputversion="1.05">
<scaninfo type="arp" protocol="arp" numservices="0" services=""/>
<verbose level="0"/>
<debugging level="0"/>
<host starttime="1755000100" endtime="1755000101">
<status state="up" reason="arp-response" reason_ttl="0"/>
<address addr="198.51.100.5" addrtype="ipv4"/>
<address addr="02:1a:2b:00:00:05" addrtype="mac" vendor="Synthetic Devices"/>
<hostnames>
</hostnames>
<times srtt="10" rttvar="5" to="100000"/>
</host>
<runstats>
<finished time="1755000101" timestr="Tue Aug 12 10:01:41 2026" elapsed="1.00" summary="Nmap done at Tue Aug 12 10:01:41 2026; 1 IP address (1 host up) scanned in 1.00 seconds" exit="success"/>
<hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
```

- [ ] **Step 3: Crear `nmap.rs` con descriptor, versión y `plan()`/`parse()` de Discovery**

Crea `src-tauri/src/adapters/nmap.rs`:

```rust
//! Adaptador de nmap. Primera herramienta real orquestada por AUscan.
//!
//! Encadena tres fases (`Discovery`, `PortSweep`, `Services`) con un solo
//! `ToolAdapter`, usando `ctx.phase` para saber cuál pide el operador y
//! `ctx.known` para saber qué hay de fases anteriores. IPv6 queda fuera
//! de esta versión: `plan()` filtra a IPv4 en todas las fases.

use std::net::IpAddr;
use std::time::Duration;

use semver::Version;

use crate::adapters::{
    Flag, HostFact, InstallHint, Invocation, Normalized, ObservationFact, ObservationKind,
    ParseContext, Phase, PlanContext, ProgressSource, RawSource, ToolAdapter, ToolDescriptor,
};
use crate::error::{AppError, Result};
use crate::scope::ScopedTarget;

const ALLOWED_FLAGS: &[Flag] = &[
    Flag {
        name: "-sn",
        needs_privilege: false,
        takes_value: false,
    },
    // Los puertos de sondeo de -PS/-PA van pegados al nombre a
    // propósito: nmap los interpreta como parte del mismo token, no
    // como un valor en un token separado (a diferencia de -p). Como el
    // valor no varía nunca en esta fase, se declaran como literales
    // completos en vez de como banderas `takes_value`.
    Flag {
        name: "-PS80,443,22",
        needs_privilege: false,
        takes_value: false,
    },
    Flag {
        name: "-PA80",
        needs_privilege: false,
        takes_value: false,
    },
    Flag {
        name: "-PR",
        needs_privilege: true,
        takes_value: false,
    },
    Flag {
        name: "-n",
        needs_privilege: false,
        takes_value: false,
    },
    Flag {
        name: "-oX",
        needs_privilege: false,
        takes_value: true,
    },
];

pub struct Nmap;

impl ToolAdapter for Nmap {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            id: "nmap",
            binaries: &["nmap"],
            min_version: Version::new(7, 80, 0),
            phases: &[Phase::Discovery],
            install_hint: InstallHint {
                brew: &["install", "nmap"],
                winget: &["install", "-e", "Insecure.Nmap"],
            },
            allowed_flags: ALLOWED_FLAGS,
        }
    }

    fn version_argv(&self) -> Vec<String> {
        vec!["--version".to_string()]
    }

    fn parse_version(&self, stdout: &str) -> Result<Version> {
        // "Nmap version 7.94 ( https://nmap.org )" — nmap usa versiones
        // de dos componentes; semver exige tres, así que se completa con
        // ".0" salvo que ya venga con patch (versiones futuras podrían
        // añadirlo).
        let primera = stdout.lines().next().unwrap_or("");
        let numero = primera
            .strip_prefix("Nmap version ")
            .and_then(|resto| resto.split_whitespace().next())
            .ok_or_else(|| AppError::ParseFailed(stdout.to_string()))?;
        let con_patch = if numero.matches('.').count() == 1 {
            format!("{numero}.0")
        } else {
            numero.to_string()
        };
        Version::parse(&con_patch).map_err(|_| AppError::ParseFailed(stdout.to_string()))
    }

    fn plan(&self, ctx: &PlanContext) -> Result<Vec<Invocation>> {
        match ctx.phase {
            Phase::Discovery => {
                let v4_targets: Vec<ScopedTarget> = ctx
                    .targets
                    .iter()
                    .filter(|t| t.ip().is_ipv4())
                    .copied()
                    .collect();
                if v4_targets.is_empty() {
                    return Ok(vec![]);
                }
                let mut argv = if ctx.privileged {
                    vec!["-sn".to_string(), "-PR".to_string(), "-n".to_string()]
                } else {
                    vec![
                        "-sn".to_string(),
                        "-PS80,443,22".to_string(),
                        "-PA80".to_string(),
                        "-n".to_string(),
                    ]
                };
                argv.push("-oX".to_string());
                argv.push("-".to_string());
                for t in &v4_targets {
                    argv.push(t.to_string());
                }
                Ok(vec![Invocation {
                    phase: Phase::Discovery,
                    argv,
                    targets: v4_targets,
                    needs_privilege: ctx.privileged,
                    raw_from: RawSource::Stdout,
                    progress_from: ProgressSource::None,
                    stdin: None,
                    timeout: Duration::from_secs(300),
                }])
            }
            _ => Ok(vec![]),
        }
    }

    fn parse(&self, raw: &[u8], ctx: &ParseContext) -> Result<Normalized> {
        let texto = std::str::from_utf8(raw).map_err(|e| AppError::ParseFailed(e.to_string()))?;
        let doc =
            roxmltree::Document::parse(texto).map_err(|e| AppError::ParseFailed(e.to_string()))?;
        let root = doc.root_element();

        let mut hosts = Vec::new();
        let mut observations = Vec::new();

        for host_node in root.children().filter(|n| n.has_tag_name("host")) {
            let estado = host_node
                .children()
                .find(|n| n.has_tag_name("status"))
                .and_then(|s| s.attribute("state"));
            if estado != Some("up") {
                continue;
            }

            let addr_node = host_node
                .children()
                .filter(|n| n.has_tag_name("address"))
                .find(|n| n.attribute("addrtype") == Some("ipv4"))
                .ok_or_else(|| {
                    AppError::ParseFailed(format!("host sin dirección ipv4 en {}", ctx.raw_path))
                })?;
            let ip: IpAddr = addr_node
                .attribute("addr")
                .ok_or_else(|| {
                    AppError::ParseFailed(format!("host sin atributo addr en {}", ctx.raw_path))
                })?
                .parse()
                .map_err(|_| {
                    AppError::ParseFailed(format!("dirección ipv4 inválida en {}", ctx.raw_path))
                })?;

            let mac_node = host_node
                .children()
                .filter(|n| n.has_tag_name("address"))
                .find(|n| n.attribute("addrtype") == Some("mac"));
            let mac = mac_node
                .and_then(|n| n.attribute("addr"))
                .map(|s| s.to_lowercase());
            let vendor = mac_node
                .and_then(|n| n.attribute("vendor"))
                .map(|s| s.to_string());

            let hostname = host_node
                .children()
                .find(|n| n.has_tag_name("hostnames"))
                .and_then(|hn| hn.children().find(|n| n.has_tag_name("hostname")))
                .and_then(|h| h.attribute("name"))
                .map(|s| s.to_string());

            hosts.push(HostFact {
                ip,
                hostname,
                mac,
                vendor,
                os_guess: None,
                os_accuracy: None,
                state: Some("up".to_string()),
            });

            observations.push(ObservationFact {
                host_ip: Some(ip),
                port: None,
                kind: ObservationKind::HostDiscovered,
                subject: ip.to_string(),
                statement: "Host activo".to_string(),
                evidence: Some(texto[addr_node.range()].to_string()),
                evidence_ref: Some(format!(
                    "{}#L{}",
                    ctx.raw_path,
                    linea_de(texto, addr_node.range().start)
                )),
                meta_json: None,
            });
        }

        Ok(Normalized {
            hosts,
            services: Vec::new(),
            observations,
        })
    }
}

fn linea_de(texto: &str, offset: usize) -> usize {
    texto[..offset].bytes().filter(|&b| b == b'\n').count() + 1
}
```

En `src-tauri/src/adapters/mod.rs`, añade `pub mod nmap;` junto al resto de módulos del fichero (arriba, cerca de los `use`), y reemplaza `registry()`:

```rust
/// Las herramientas que la app sabe orquestar. Añadir una es un fichero
/// nuevo y una línea aquí; el núcleo no se toca.
pub fn registry() -> Vec<Box<dyn ToolAdapter>> {
    vec![Box::new(nmap::Nmap)]
}
```

- [ ] **Step 4: Reemplazar el test del registro vacío**

En `src-tauri/tests/adapters_trait.rs`, reemplaza `el_registro_de_produccion_esta_vacio_hasta_la_fase_4`:

```rust
#[test]
fn el_registro_de_produccion_incluye_nmap() {
    let registro = auscan_lib::adapters::registry();
    assert_eq!(registro.len(), 1);
    assert_eq!(registro[0].descriptor().id, "nmap");
}
```

- [ ] **Step 5: Tests de `version_argv`/`parse_version` y de `plan()` para Discovery**

Crea `src-tauri/tests/parsers/mod.rs` (vacío, solo para que Cargo trate `tests/parsers/` como módulo compartido si hiciera falta en el futuro):

```rust
// Directorio de tests de parsers, un fichero por adaptador.
```

Crea `src-tauri/tests/parsers/nmap_discovery.rs`:

```rust
use std::net::IpAddr;

use auscan_lib::adapters::{
    KnownState, ObservationKind, ParseContext, Phase, PhaseOptions, PlanContext, ToolAdapter,
};
use auscan_lib::adapters::nmap::Nmap;
use auscan_lib::scope::{Scope, ScopeKind};

fn scope_198() -> Scope {
    Scope::from_entries(&[(ScopeKind::Allow, "198.51.100.0/24".to_string())]).unwrap()
}

#[test]
fn version_argv_pide_version_larga() {
    assert_eq!(Nmap.version_argv(), vec!["--version".to_string()]);
}

#[test]
fn parse_version_entiende_la_salida_real_de_nmap() {
    let salida = "Nmap version 7.94 ( https://nmap.org )\nPlatform: x86_64-apple-darwin23.1.0\n";
    let v = Nmap.parse_version(salida).unwrap();
    assert_eq!((v.major, v.minor, v.patch), (7, 94, 0));
}

#[test]
fn parse_version_no_duplica_el_patch_si_ya_viene() {
    let v = Nmap.parse_version("Nmap version 8.1.2 ( https://nmap.org )\n").unwrap();
    assert_eq!((v.major, v.minor, v.patch), (8, 1, 2));
}

#[test]
fn plan_discovery_sin_privilegio_usa_sondas_tcp() {
    let scope = scope_198();
    let objetivo = scope.validate("198.51.100.5").unwrap();
    let known = KnownState::default();
    let opciones = PhaseOptions::default();
    let ctx = PlanContext {
        phase: Phase::Discovery,
        scope: &scope,
        targets: &[objetivo],
        known: &known,
        privileged: false,
        options: &opciones,
    };
    let invocaciones = Nmap.plan(&ctx).unwrap();
    assert_eq!(invocaciones.len(), 1);
    let inv = &invocaciones[0];
    assert_eq!(inv.phase, Phase::Discovery);
    assert!(!inv.needs_privilege);
    assert_eq!(
        inv.argv,
        vec![
            "-sn", "-PS80,443,22", "-PA80", "-n", "-oX", "-", "198.51.100.5"
        ]
    );
}

#[test]
fn plan_discovery_privilegiado_usa_arp() {
    let scope = scope_198();
    let objetivo = scope.validate("198.51.100.5").unwrap();
    let known = KnownState::default();
    let opciones = PhaseOptions::default();
    let ctx = PlanContext {
        phase: Phase::Discovery,
        scope: &scope,
        targets: &[objetivo],
        known: &known,
        privileged: true,
        options: &opciones,
    };
    let invocaciones = Nmap.plan(&ctx).unwrap();
    assert_eq!(invocaciones.len(), 1);
    let inv = &invocaciones[0];
    assert!(inv.needs_privilege);
    assert_eq!(inv.argv, vec!["-sn", "-PR", "-n", "-oX", "-", "198.51.100.5"]);
}

#[test]
fn plan_discovery_sin_objetivos_no_produce_invocaciones() {
    let scope = scope_198();
    let known = KnownState::default();
    let opciones = PhaseOptions::default();
    let ctx = PlanContext {
        phase: Phase::Discovery,
        scope: &scope,
        targets: &[],
        known: &known,
        privileged: false,
        options: &opciones,
    };
    assert!(Nmap.plan(&ctx).unwrap().is_empty());
}

#[test]
fn plan_de_una_fase_que_nmap_no_atiende_produce_vacio() {
    let scope = scope_198();
    let objetivo = scope.validate("198.51.100.5").unwrap();
    let known = KnownState::default();
    let opciones = PhaseOptions::default();
    let ctx = PlanContext {
        phase: Phase::Web,
        scope: &scope,
        targets: &[objetivo],
        known: &known,
        privileged: false,
        options: &opciones,
    };
    assert!(Nmap.plan(&ctx).unwrap().is_empty());
}

fn parse_ctx() -> ParseContext<'static> {
    ParseContext {
        tool_run_id: 1,
        raw_path: "raw/0001-nmap-sn.xml",
        observed_at: "2026-08-26T10:00:00Z",
    }
}

#[test]
fn parse_discovery_sin_privilegio_solo_incluye_hosts_arriba() {
    let raw = include_bytes!("../../../fixtures/nmap/0001-discovery-sin-privilegio.xml");
    let ctx = parse_ctx();
    let normalizado = Nmap.parse(raw, &ctx).unwrap();

    assert_eq!(
        normalizado.hosts,
        vec![
            auscan_lib::adapters::HostFact {
                ip: "198.51.100.5".parse::<IpAddr>().unwrap(),
                hostname: Some("host5.example".to_string()),
                mac: None,
                vendor: None,
                os_guess: None,
                os_accuracy: None,
                state: Some("up".to_string()),
            },
            auscan_lib::adapters::HostFact {
                ip: "198.51.100.9".parse::<IpAddr>().unwrap(),
                hostname: None,
                mac: None,
                vendor: None,
                os_guess: None,
                os_accuracy: None,
                state: Some("up".to_string()),
            },
        ]
    );
    assert!(normalizado.services.is_empty());
    assert_eq!(normalizado.observations.len(), 2);
    for o in &normalizado.observations {
        assert_eq!(o.kind, ObservationKind::HostDiscovered);
        assert_eq!(o.statement, "Host activo");
        assert!(o.evidence.as_deref().unwrap().contains("addr="));
        assert!(o
            .evidence_ref
            .as_deref()
            .unwrap()
            .starts_with("raw/0001-nmap-sn.xml#L"));
    }
}

#[test]
fn parse_discovery_privilegiado_incluye_mac_y_fabricante() {
    let raw = include_bytes!("../../../fixtures/nmap/0002-discovery-privilegiado.xml");
    let ctx = parse_ctx();
    let normalizado = Nmap.parse(raw, &ctx).unwrap();

    assert_eq!(normalizado.hosts.len(), 1);
    let h = &normalizado.hosts[0];
    assert_eq!(h.ip, "198.51.100.5".parse::<IpAddr>().unwrap());
    assert_eq!(h.mac.as_deref(), Some("02:1a:2b:00:00:05"));
    assert_eq!(h.vendor.as_deref(), Some("Synthetic Devices"));
}
```

Run: `cargo test --manifest-path src-tauri/Cargo.toml`
Expected: FAIL antes de compilar limpio si algo no cuadra; PASS una vez todo el árbol compila (revisa cualquier discrepancia de nombres antes de continuar — el reviewer de esta tarea comprobará el diff completo).

- [ ] **Step 6: `clippy`, `fmt`, commit**

Run: `cargo fmt --manifest-path src-tauri/Cargo.toml` luego `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings` luego `cargo test --manifest-path src-tauri/Cargo.toml`

```bash
git add src-tauri/src/adapters/nmap.rs src-tauri/src/adapters/mod.rs src-tauri/src/error.rs src-tauri/Cargo.toml src-tauri/Cargo.lock src-tauri/tests/adapters_trait.rs src-tauri/tests/parsers/
git add fixtures/nmap/0001-discovery-sin-privilegio.xml fixtures/nmap/0002-discovery-privilegiado.xml
git commit -m "$(cat <<'EOF'
feat: adaptador de nmap — descriptor, versión y fase de descubrimiento

Primer adaptador real del registro. plan() construye la invocación de
-sn según haya o no privilegio (ARP vs sondas TCP); parse() interpreta
el XML de nmap con roxmltree y produce hosts vivos más su observación
host.discovered. PortSweep y Services llegan en las próximas tareas.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Fase PortSweep — barrido de puertos y `service.open`

Extiende `Nmap` para encadenar el barrido de puertos sobre los hosts que Discovery encontró vivos. Introduce la primera bandera `needs_privilege: true` de verdad usada en un test de la verja completa (`-sS`), cerrando el hueco Minor de la Fase 3 en el que `FakeAdapter` nunca ejercitaba ese camino.

**Files:**
- Modify: `src-tauri/src/adapters/nmap.rs`
- Create: `fixtures/nmap/0003-portsweep.xml`
- Create: `src-tauri/tests/parsers/nmap_portsweep.rs`
- Modify: `src-tauri/tests/exec_gate.rs` (test de la verja con el descriptor real de nmap)

**Interfaces:**
- Consumes: `KnownState { hosts, services }` (ya existente), `ScopedTarget::ip()` (ya existente).
- Produces: extiende `descriptor().phases` a `&[Phase::Discovery, Phase::PortSweep]` y `allowed_flags` con `-Pn`, `-sT`, `-sS`. Añade la función privada `scoped_target_de`, que Task 4 reutiliza.

- [ ] **Step 1: Fixture de PortSweep**

Crea `fixtures/nmap/0003-portsweep.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -Pn -n -sT -oX - 198.51.100.5" start="1755000200" startstr="Tue Aug 12 10:03:20 2026" version="7.94" xmloutputversion="1.05">
<scaninfo type="connect" protocol="tcp" numservices="1000" services="1-1000"/>
<verbose level="0"/>
<debugging level="0"/>
<host starttime="1755000200" endtime="1755000210">
<status state="up" reason="user-set" reason_ttl="0"/>
<address addr="198.51.100.5" addrtype="ipv4"/>
<hostnames>
</hostnames>
<ports>
<extraports state="closed" count="997"/>
<port protocol="tcp" portid="22">
<state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="ssh" method="table" conf="3"/>
</port>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="http" method="table" conf="3"/>
</port>
<port protocol="tcp" portid="8080">
<state state="closed" reason="conn-refused" reason_ttl="64"/>
<service name="http-proxy" method="table" conf="3"/>
</port>
</ports>
<times srtt="1000" rttvar="500" to="100000"/>
</host>
<runstats>
<finished time="1755000210" timestr="Tue Aug 12 10:03:30 2026" elapsed="10.00" summary="Nmap done at Tue Aug 12 10:03:30 2026; 1 IP address (1 host up) scanned in 10.00 seconds" exit="success"/>
<hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
```

- [ ] **Step 2: Extender descriptor, `plan()` y `parse()` en `nmap.rs`**

Cambia la constante `ALLOWED_FLAGS` en `src-tauri/src/adapters/nmap.rs`, añadiendo estas tres entradas al final del array (antes del cierre `];`):

```rust
    Flag {
        name: "-Pn",
        needs_privilege: false,
        takes_value: false,
    },
    Flag {
        name: "-sT",
        needs_privilege: false,
        takes_value: false,
    },
    Flag {
        name: "-sS",
        needs_privilege: true,
        takes_value: false,
    },
```

Cambia `phases: &[Phase::Discovery]` a `phases: &[Phase::Discovery, Phase::PortSweep]`.

En el bloque `use crate::adapters::{ ... };` que ya existe (de la Task 2), añade `ServiceFact` a la lista entre llaves, junto a `RawSource` (orden alfabético: `..., ProgressSource, RawSource, ServiceFact, ToolAdapter, ...`). No añadas una línea `use` nueva y separada para el mismo módulo — `cargo fmt` no fusiona automáticamente dos `use` distintos del mismo path, y `clippy` puede avisar de la redundancia.

Añade también esta función privada al final del fichero, junto a `linea_de`:

```rust
fn scoped_target_de(ctx: &PlanContext, ip: IpAddr) -> Result<ScopedTarget> {
    ctx.targets
        .iter()
        .find(|t| t.ip() == ip)
        .copied()
        .ok_or_else(|| AppError::UnvalidatedTarget(ip.to_string()))
}
```

En `plan()`, cambia el `match ctx.phase` para añadir la rama `PortSweep` antes del `_`:

```rust
            Phase::PortSweep => {
                let ips: Vec<IpAddr> = ctx
                    .known
                    .hosts
                    .iter()
                    .map(|h| h.ip)
                    .filter(|ip| ip.is_ipv4())
                    .collect();
                if ips.is_empty() {
                    return Ok(vec![]);
                }
                let targets = ips
                    .iter()
                    .map(|ip| scoped_target_de(ctx, *ip))
                    .collect::<Result<Vec<_>>>()?;
                let mut argv = vec!["-Pn".to_string(), "-n".to_string()];
                argv.push(if ctx.privileged { "-sS" } else { "-sT" }.to_string());
                argv.push("-oX".to_string());
                argv.push("-".to_string());
                for ip in &ips {
                    argv.push(ip.to_string());
                }
                Ok(vec![Invocation {
                    phase: Phase::PortSweep,
                    argv,
                    targets,
                    needs_privilege: ctx.privileged,
                    raw_from: RawSource::Stdout,
                    progress_from: ProgressSource::None,
                    stdin: None,
                    timeout: Duration::from_secs(1800),
                }])
            }
```

En `parse()`, reemplaza el cuerpo completo de la función por esta versión (añade el manejo de `<ports>` dentro del bucle de hosts, después del bloque de `hostname` y antes de `hosts.push(...)`; y cambia `services: Vec::new()` por la variable acumulada):

```rust
    fn parse(&self, raw: &[u8], ctx: &ParseContext) -> Result<Normalized> {
        let texto = std::str::from_utf8(raw).map_err(|e| AppError::ParseFailed(e.to_string()))?;
        let doc =
            roxmltree::Document::parse(texto).map_err(|e| AppError::ParseFailed(e.to_string()))?;
        let root = doc.root_element();

        let mut hosts = Vec::new();
        let mut services = Vec::new();
        let mut observations = Vec::new();

        for host_node in root.children().filter(|n| n.has_tag_name("host")) {
            let estado = host_node
                .children()
                .find(|n| n.has_tag_name("status"))
                .and_then(|s| s.attribute("state"));
            if estado != Some("up") {
                continue;
            }

            let addr_node = host_node
                .children()
                .filter(|n| n.has_tag_name("address"))
                .find(|n| n.attribute("addrtype") == Some("ipv4"))
                .ok_or_else(|| {
                    AppError::ParseFailed(format!("host sin dirección ipv4 en {}", ctx.raw_path))
                })?;
            let ip: IpAddr = addr_node
                .attribute("addr")
                .ok_or_else(|| {
                    AppError::ParseFailed(format!("host sin atributo addr en {}", ctx.raw_path))
                })?
                .parse()
                .map_err(|_| {
                    AppError::ParseFailed(format!("dirección ipv4 inválida en {}", ctx.raw_path))
                })?;

            let mac_node = host_node
                .children()
                .filter(|n| n.has_tag_name("address"))
                .find(|n| n.attribute("addrtype") == Some("mac"));
            let mac = mac_node
                .and_then(|n| n.attribute("addr"))
                .map(|s| s.to_lowercase());
            let vendor = mac_node
                .and_then(|n| n.attribute("vendor"))
                .map(|s| s.to_string());

            let hostname = host_node
                .children()
                .find(|n| n.has_tag_name("hostnames"))
                .and_then(|hn| hn.children().find(|n| n.has_tag_name("hostname")))
                .and_then(|h| h.attribute("name"))
                .map(|s| s.to_string());

            hosts.push(HostFact {
                ip,
                hostname,
                mac,
                vendor,
                os_guess: None,
                os_accuracy: None,
                state: Some("up".to_string()),
            });

            observations.push(ObservationFact {
                host_ip: Some(ip),
                port: None,
                kind: ObservationKind::HostDiscovered,
                subject: ip.to_string(),
                statement: "Host activo".to_string(),
                evidence: Some(texto[addr_node.range()].to_string()),
                evidence_ref: Some(format!(
                    "{}#L{}",
                    ctx.raw_path,
                    linea_de(texto, addr_node.range().start)
                )),
                meta_json: None,
            });

            if let Some(ports_node) = host_node.children().find(|n| n.has_tag_name("ports")) {
                for port_node in ports_node.children().filter(|n| n.has_tag_name("port")) {
                    let proto = port_node.attribute("protocol").unwrap_or("tcp").to_string();
                    let portid: u16 = port_node
                        .attribute("portid")
                        .and_then(|s| s.parse().ok())
                        .ok_or_else(|| {
                            AppError::ParseFailed(format!(
                                "puerto sin portid en {}",
                                ctx.raw_path
                            ))
                        })?;
                    let pstate = port_node
                        .children()
                        .find(|n| n.has_tag_name("state"))
                        .and_then(|s| s.attribute("state"))
                        .unwrap_or("unknown")
                        .to_string();
                    if pstate != "open" {
                        continue;
                    }
                    let service_node = port_node.children().find(|n| n.has_tag_name("service"));
                    let service = service_node
                        .and_then(|s| s.attribute("name"))
                        .map(|s| s.to_string());

                    services.push(ServiceFact {
                        host_ip: ip,
                        port: portid,
                        proto: proto.clone(),
                        state: pstate.clone(),
                        service: service.clone(),
                        product: None,
                        version: None,
                        extrainfo: None,
                        tunnel: None,
                        cpe: None,
                        banner: None,
                    });

                    observations.push(ObservationFact {
                        host_ip: Some(ip),
                        port: Some(portid),
                        kind: ObservationKind::ServiceOpen,
                        subject: format!("{ip}:{portid}/{proto}"),
                        statement: format!(
                            "Puerto abierto: {}",
                            service.as_deref().unwrap_or("desconocido")
                        ),
                        evidence: Some(texto[port_node.range()].to_string()),
                        evidence_ref: Some(format!(
                            "{}#L{}",
                            ctx.raw_path,
                            linea_de(texto, port_node.range().start)
                        )),
                        meta_json: None,
                    });
                }
            }
        }

        Ok(Normalized {
            hosts,
            services,
            observations,
        })
    }
```

- [ ] **Step 3: Tests de `plan()`/`parse()` para PortSweep**

Crea `src-tauri/tests/parsers/nmap_portsweep.rs`:

```rust
use std::net::IpAddr;

use auscan_lib::adapters::nmap::Nmap;
use auscan_lib::adapters::{
    HostFact, KnownState, ObservationKind, ParseContext, Phase, PhaseOptions, PlanContext,
    ToolAdapter,
};
use auscan_lib::scope::{Scope, ScopeKind};

fn scope_198() -> Scope {
    Scope::from_entries(&[(ScopeKind::Allow, "198.51.100.0/24".to_string())]).unwrap()
}

fn host_de_prueba(ip: &str) -> HostFact {
    HostFact {
        ip: ip.parse::<IpAddr>().unwrap(),
        hostname: None,
        mac: None,
        vendor: None,
        os_guess: None,
        os_accuracy: None,
        state: Some("up".to_string()),
    }
}

#[test]
fn plan_portsweep_sin_privilegio_usa_connect_scan() {
    let scope = scope_198();
    let objetivo = scope.validate("198.51.100.5").unwrap();
    let known = KnownState {
        hosts: vec![host_de_prueba("198.51.100.5")],
        services: vec![],
    };
    let opciones = PhaseOptions::default();
    let ctx = PlanContext {
        phase: Phase::PortSweep,
        scope: &scope,
        targets: &[objetivo],
        known: &known,
        privileged: false,
        options: &opciones,
    };
    let invocaciones = Nmap.plan(&ctx).unwrap();
    assert_eq!(invocaciones.len(), 1);
    assert_eq!(
        invocaciones[0].argv,
        vec!["-Pn", "-n", "-sT", "-oX", "-", "198.51.100.5"]
    );
    assert!(!invocaciones[0].needs_privilege);
}

#[test]
fn plan_portsweep_privilegiado_usa_syn_scan() {
    let scope = scope_198();
    let objetivo = scope.validate("198.51.100.5").unwrap();
    let known = KnownState {
        hosts: vec![host_de_prueba("198.51.100.5")],
        services: vec![],
    };
    let opciones = PhaseOptions::default();
    let ctx = PlanContext {
        phase: Phase::PortSweep,
        scope: &scope,
        targets: &[objetivo],
        known: &known,
        privileged: true,
        options: &opciones,
    };
    let invocaciones = Nmap.plan(&ctx).unwrap();
    assert_eq!(
        invocaciones[0].argv,
        vec!["-Pn", "-n", "-sS", "-oX", "-", "198.51.100.5"]
    );
    assert!(invocaciones[0].needs_privilege);
}

#[test]
fn plan_portsweep_sin_hosts_conocidos_no_produce_nada() {
    let scope = scope_198();
    let objetivo = scope.validate("198.51.100.5").unwrap();
    let known = KnownState::default();
    let opciones = PhaseOptions::default();
    let ctx = PlanContext {
        phase: Phase::PortSweep,
        scope: &scope,
        targets: &[objetivo],
        known: &known,
        privileged: false,
        options: &opciones,
    };
    assert!(Nmap.plan(&ctx).unwrap().is_empty());
}

#[test]
fn parse_portsweep_omite_los_puertos_cerrados() {
    let raw = include_bytes!("../../../fixtures/nmap/0003-portsweep.xml");
    let ctx = ParseContext {
        tool_run_id: 2,
        raw_path: "raw/0002-nmap-portsweep.xml",
        observed_at: "2026-08-26T10:05:00Z",
    };
    let normalizado = Nmap.parse(raw, &ctx).unwrap();

    assert_eq!(normalizado.hosts.len(), 1);
    assert_eq!(
        normalizado.services,
        vec![
            auscan_lib::adapters::ServiceFact {
                host_ip: "198.51.100.5".parse::<IpAddr>().unwrap(),
                port: 22,
                proto: "tcp".to_string(),
                state: "open".to_string(),
                service: Some("ssh".to_string()),
                product: None,
                version: None,
                extrainfo: None,
                tunnel: None,
                cpe: None,
                banner: None,
            },
            auscan_lib::adapters::ServiceFact {
                host_ip: "198.51.100.5".parse::<IpAddr>().unwrap(),
                port: 80,
                proto: "tcp".to_string(),
                state: "open".to_string(),
                service: Some("http".to_string()),
                product: None,
                version: None,
                extrainfo: None,
                tunnel: None,
                cpe: None,
                banner: None,
            },
        ]
    );
    // El puerto 8080, cerrado en el fixture, no debe aparecer.
    assert!(!normalizado.services.iter().any(|s| s.port == 8080));

    let observaciones_puerto: Vec<_> = normalizado
        .observations
        .iter()
        .filter(|o| o.kind == ObservationKind::ServiceOpen)
        .collect();
    assert_eq!(observaciones_puerto.len(), 2);
}
```

Run: `cargo test --manifest-path src-tauri/Cargo.toml`
Expected: PASS.

- [ ] **Step 4: Test de la verja con el descriptor real de nmap**

En `src-tauri/tests/exec_gate.rs`, añade este test. `ToolAdapter` ya está importado arriba del fichero (`use auscan_lib::adapters::ToolAdapter;`); solo hace falta el `use` local de `Nmap`, que no lo está:

```rust
#[test]
fn verja_rechaza_syn_scan_sin_privilegio_con_el_descriptor_real_de_nmap() {
    use auscan_lib::adapters::nmap::Nmap;

    let scope = scope_198();
    let target = scope.validate("198.51.100.5").unwrap();
    let d = Nmap.descriptor();
    let bin = Path::new("/opt/homebrew/bin/nmap");

    let inv = auscan_lib::adapters::Invocation {
        phase: auscan_lib::adapters::Phase::PortSweep,
        argv: vec![
            "-Pn".to_string(),
            "-n".to_string(),
            "-sS".to_string(),
            "-oX".to_string(),
            "-".to_string(),
            "198.51.100.5".to_string(),
        ],
        targets: vec![target],
        needs_privilege: false,
        raw_from: auscan_lib::adapters::RawSource::Stdout,
        progress_from: auscan_lib::adapters::ProgressSource::None,
        stdin: None,
        timeout: std::time::Duration::from_secs(60),
    };
    // -sS exige privilegio; la invocación dice que no lo tiene.
    assert!(matches!(
        verja(&inv, bin, &d, bin),
        Err(AppError::PrivilegeRequired(_))
    ));

    let mut inv_ok = inv;
    inv_ok.needs_privilege = true;
    assert!(verja(&inv_ok, bin, &d, bin).is_ok());
}
```

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test exec_gate`
Expected: PASS.

- [ ] **Step 5: `clippy`, `fmt`, commit**

Run: `cargo fmt --manifest-path src-tauri/Cargo.toml` luego `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings` luego `cargo test --manifest-path src-tauri/Cargo.toml`

```bash
git add src-tauri/src/adapters/nmap.rs fixtures/nmap/0003-portsweep.xml src-tauri/tests/parsers/nmap_portsweep.rs src-tauri/tests/exec_gate.rs
git commit -m "$(cat <<'EOF'
feat: adaptador de nmap — fase de barrido de puertos

plan() encadena PortSweep sobre los hosts que Discovery encontró
vivos (-sT sin privilegio, -sS con privilegio); parse() añade el
manejo de <ports> y descarta los puertos que no están abiertos. Añade
el primer test de la verja contra el descriptor real de nmap, con una
bandera needs_privilege de verdad (-sS) en vez del adaptador de
prueba.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Fase Services — versión de servicio, SO, y `service.version_disclosed`

Cierra el adaptador de nmap v1: escaneo de versión por host sobre los puertos abiertos exactos que PortSweep encontró, más detección de sistema operativo cuando hay privilegio.

**Files:**
- Modify: `src-tauri/src/adapters/nmap.rs`
- Create: `fixtures/nmap/0004-services.xml`
- Create: `src-tauri/tests/parsers/nmap_services.rs`

**Interfaces:**
- Consumes: `scoped_target_de` (Task 3).
- Produces: `descriptor().phases` completo (`Discovery`, `PortSweep`, `Services`); `plan()`/`parse()` completos para nmap v1.

- [ ] **Step 1: Fixture de Services**

Crea `fixtures/nmap/0004-services.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -Pn -n -sV -O -p 22,80,443 -oX - 198.51.100.5" start="1755000300" startstr="Tue Aug 12 10:05:00 2026" version="7.94" xmloutputversion="1.05">
<scaninfo type="syn" protocol="tcp" numservices="3" services="22,80,443"/>
<verbose level="0"/>
<debugging level="0"/>
<host starttime="1755000300" endtime="1755000320">
<status state="up" reason="user-set" reason_ttl="0"/>
<address addr="198.51.100.5" addrtype="ipv4"/>
<hostnames>
<hostname name="host5.example" type="PTR"/>
</hostnames>
<ports>
<port protocol="tcp" portid="22">
<state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="ssh" product="OpenSSH" version="9.6" extrainfo="Ubuntu Linux; protocol 2.0" method="probed" conf="10"/>
</port>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="http" product="nginx" version="1.24.0" method="probed" conf="10"/>
</port>
<port protocol="tcp" portid="443">
<state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="https" product="nginx" version="1.24.0" tunnel="ssl" method="probed" conf="10">
<cpe>cpe:/a:nginx:nginx:1.24.0</cpe>
</service>
</port>
</ports>
<os>
<osmatch name="Linux 5.0 - 6.1" accuracy="95" line="12345">
<osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="95"/>
</osmatch>
<osmatch name="Linux 4.15 - 5.6" accuracy="90" line="54321">
<osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="4.X" accuracy="90"/>
</osmatch>
</os>
<times srtt="1000" rttvar="500" to="100000"/>
</host>
<runstats>
<finished time="1755000320" timestr="Tue Aug 12 10:05:20 2026" elapsed="20.00" summary="Nmap done at Tue Aug 12 10:05:20 2026; 1 IP address (1 host up) scanned in 20.00 seconds" exit="success"/>
<hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
```

- [ ] **Step 2: Extender descriptor, `plan()` y `parse()`**

En `src-tauri/src/adapters/nmap.rs`, añade a `ALLOWED_FLAGS`:

```rust
    Flag {
        name: "-sV",
        needs_privilege: false,
        takes_value: false,
    },
    Flag {
        name: "-p",
        needs_privilege: false,
        takes_value: true,
    },
    Flag {
        name: "-O",
        needs_privilege: true,
        takes_value: false,
    },
```

Cambia `phases` a `&[Phase::Discovery, Phase::PortSweep, Phase::Services]`.

Añade `use std::collections::BTreeMap;` al bloque de imports.

En `plan()`, añade la rama `Services` antes del `_`:

```rust
            Phase::Services => {
                let mut por_host: BTreeMap<IpAddr, Vec<u16>> = BTreeMap::new();
                for s in ctx.known.services.iter().filter(|s| s.state == "open") {
                    por_host.entry(s.host_ip).or_default().push(s.port);
                }
                let mut invocaciones = Vec::new();
                for (ip, mut puertos) in por_host {
                    puertos.sort_unstable();
                    puertos.dedup();
                    let target = scoped_target_de(ctx, ip)?;
                    let lista = puertos
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(",");
                    let mut argv = vec!["-Pn".to_string(), "-n".to_string(), "-sV".to_string()];
                    if ctx.privileged {
                        argv.push("-O".to_string());
                    }
                    argv.push("-p".to_string());
                    argv.push(lista);
                    argv.push("-oX".to_string());
                    argv.push("-".to_string());
                    argv.push(ip.to_string());
                    invocaciones.push(Invocation {
                        phase: Phase::Services,
                        argv,
                        targets: vec![target],
                        needs_privilege: ctx.privileged,
                        raw_from: RawSource::Stdout,
                        progress_from: ProgressSource::None,
                        stdin: None,
                        timeout: Duration::from_secs(900),
                    });
                }
                Ok(invocaciones)
            }
```

En `parse()`, primero añade el bloque de detección de SO justo antes de `hosts.push(HostFact { ... })` (sustituye `os_guess: None, os_accuracy: None,` dentro de ese `HostFact` por `os_guess: os_guess.clone(), os_accuracy,` una vez añadido este bloque):

```rust
            let osmatch_node = host_node
                .children()
                .find(|n| n.has_tag_name("os"))
                .and_then(|os| os.children().find(|n| n.has_tag_name("osmatch")));
            let os_guess = osmatch_node
                .and_then(|m| m.attribute("name"))
                .map(|s| s.to_string());
            let os_accuracy = osmatch_node
                .and_then(|m| m.attribute("accuracy"))
                .and_then(|s| s.parse::<i64>().ok());
```

Justo después del bloque que empuja la observación `HostDiscovered` (y antes del bloque `if let Some(ports_node) = ...`), añade:

```rust
            if let (Some(m), Some(nombre), Some(precision)) =
                (osmatch_node, &os_guess, os_accuracy)
            {
                observations.push(ObservationFact {
                    host_ip: Some(ip),
                    port: None,
                    kind: ObservationKind::HostOsGuess,
                    subject: ip.to_string(),
                    statement: format!("SO estimado: {nombre} (confianza {precision}%)"),
                    evidence: Some(texto[m.range()].to_string()),
                    evidence_ref: Some(format!(
                        "{}#L{}",
                        ctx.raw_path,
                        linea_de(texto, m.range().start)
                    )),
                    meta_json: None,
                });
            }
```

Dentro del bucle `for port_node in ports_node.children()...`, reemplaza el bloque que extrae `service` y construye `ServiceFact`/observación por:

```rust
                    let service_node = port_node.children().find(|n| n.has_tag_name("service"));
                    let service = service_node
                        .and_then(|s| s.attribute("name"))
                        .map(|s| s.to_string());
                    let product = service_node
                        .and_then(|s| s.attribute("product"))
                        .map(|s| s.to_string());
                    let version = service_node
                        .and_then(|s| s.attribute("version"))
                        .map(|s| s.to_string());
                    let extrainfo = service_node
                        .and_then(|s| s.attribute("extrainfo"))
                        .map(|s| s.to_string());
                    let tunnel = service_node
                        .and_then(|s| s.attribute("tunnel"))
                        .map(|s| s.to_string());
                    let cpe = service_node
                        .and_then(|sn| sn.children().find(|n| n.has_tag_name("cpe")))
                        .and_then(|c| c.text())
                        .map(|s| s.to_string());

                    services.push(ServiceFact {
                        host_ip: ip,
                        port: portid,
                        proto: proto.clone(),
                        state: pstate.clone(),
                        service: service.clone(),
                        product: product.clone(),
                        version: version.clone(),
                        extrainfo,
                        tunnel,
                        cpe,
                        banner: None,
                    });

                    observations.push(ObservationFact {
                        host_ip: Some(ip),
                        port: Some(portid),
                        kind: ObservationKind::ServiceOpen,
                        subject: format!("{ip}:{portid}/{proto}"),
                        statement: format!(
                            "Puerto abierto: {}",
                            service.as_deref().unwrap_or("desconocido")
                        ),
                        evidence: Some(texto[port_node.range()].to_string()),
                        evidence_ref: Some(format!(
                            "{}#L{}",
                            ctx.raw_path,
                            linea_de(texto, port_node.range().start)
                        )),
                        meta_json: None,
                    });

                    if let Some(p) = &product {
                        let estamento = match &version {
                            Some(v) => format!("{p} {v}"),
                            None => p.clone(),
                        };
                        observations.push(ObservationFact {
                            host_ip: Some(ip),
                            port: Some(portid),
                            kind: ObservationKind::ServiceVersionDisclosed,
                            subject: format!("{ip}:{portid}/{proto}"),
                            statement: estamento,
                            evidence: service_node.map(|sn| texto[sn.range()].to_string()),
                            evidence_ref: Some(format!(
                                "{}#L{}",
                                ctx.raw_path,
                                linea_de(texto, port_node.range().start)
                            )),
                            meta_json: None,
                        });
                    }
```

- [ ] **Step 3: Tests de `plan()`/`parse()` para Services**

Crea `src-tauri/tests/parsers/nmap_services.rs`:

```rust
use std::net::IpAddr;

use auscan_lib::adapters::nmap::Nmap;
use auscan_lib::adapters::{
    KnownState, ObservationKind, ParseContext, Phase, PhaseOptions, PlanContext, ServiceFact,
    ToolAdapter,
};
use auscan_lib::scope::{Scope, ScopeKind};

fn scope_198() -> Scope {
    Scope::from_entries(&[(ScopeKind::Allow, "198.51.100.0/24".to_string())]).unwrap()
}

fn servicio_abierto(ip: &str, port: u16) -> ServiceFact {
    ServiceFact {
        host_ip: ip.parse::<IpAddr>().unwrap(),
        port,
        proto: "tcp".to_string(),
        state: "open".to_string(),
        service: None,
        product: None,
        version: None,
        extrainfo: None,
        tunnel: None,
        cpe: None,
        banner: None,
    }
}

#[test]
fn plan_services_agrupa_por_host_y_ordena_los_puertos() {
    let scope = scope_198();
    let objetivo = scope.validate("198.51.100.5").unwrap();
    let known = KnownState {
        hosts: vec![],
        services: vec![
            servicio_abierto("198.51.100.5", 443),
            servicio_abierto("198.51.100.5", 22),
        ],
    };
    let opciones = PhaseOptions::default();
    let ctx = PlanContext {
        phase: Phase::Services,
        scope: &scope,
        targets: &[objetivo],
        known: &known,
        privileged: false,
        options: &opciones,
    };
    let invocaciones = Nmap.plan(&ctx).unwrap();
    assert_eq!(invocaciones.len(), 1);
    assert_eq!(
        invocaciones[0].argv,
        vec!["-Pn", "-n", "-sV", "-p", "22,443", "-oX", "-", "198.51.100.5"]
    );
}

#[test]
fn plan_services_privilegiado_añade_deteccion_de_so() {
    let scope = scope_198();
    let objetivo = scope.validate("198.51.100.5").unwrap();
    let known = KnownState {
        hosts: vec![],
        services: vec![servicio_abierto("198.51.100.5", 22)],
    };
    let opciones = PhaseOptions::default();
    let ctx = PlanContext {
        phase: Phase::Services,
        scope: &scope,
        targets: &[objetivo],
        known: &known,
        privileged: true,
        options: &opciones,
    };
    let invocaciones = Nmap.plan(&ctx).unwrap();
    assert_eq!(
        invocaciones[0].argv,
        vec!["-Pn", "-n", "-sV", "-O", "-p", "22", "-oX", "-", "198.51.100.5"]
    );
}

#[test]
fn plan_services_ignora_puertos_no_abiertos() {
    let scope = scope_198();
    let objetivo = scope.validate("198.51.100.5").unwrap();
    let mut cerrado = servicio_abierto("198.51.100.5", 8080);
    cerrado.state = "closed".to_string();
    let known = KnownState {
        hosts: vec![],
        services: vec![cerrado],
    };
    let opciones = PhaseOptions::default();
    let ctx = PlanContext {
        phase: Phase::Services,
        scope: &scope,
        targets: &[objetivo],
        known: &known,
        privileged: false,
        options: &opciones,
    };
    assert!(Nmap.plan(&ctx).unwrap().is_empty());
}

#[test]
fn parse_services_completa_producto_version_y_so() {
    let raw = include_bytes!("../../../fixtures/nmap/0004-services.xml");
    let ctx = ParseContext {
        tool_run_id: 3,
        raw_path: "raw/0003-nmap-services.xml",
        observed_at: "2026-08-26T10:06:00Z",
    };
    let normalizado = Nmap.parse(raw, &ctx).unwrap();

    assert_eq!(normalizado.hosts.len(), 1);
    let h = &normalizado.hosts[0];
    assert_eq!(h.os_guess.as_deref(), Some("Linux 5.0 - 6.1"));
    assert_eq!(h.os_accuracy, Some(95));

    assert_eq!(normalizado.services.len(), 3);
    let https = normalizado
        .services
        .iter()
        .find(|s| s.port == 443)
        .unwrap();
    assert_eq!(https.product.as_deref(), Some("nginx"));
    assert_eq!(https.version.as_deref(), Some("1.24.0"));
    assert_eq!(https.tunnel.as_deref(), Some("ssl"));
    assert_eq!(https.cpe.as_deref(), Some("cpe:/a:nginx:nginx:1.24.0"));

    let ssh = normalizado.services.iter().find(|s| s.port == 22).unwrap();
    assert_eq!(ssh.extrainfo.as_deref(), Some("Ubuntu Linux; protocol 2.0"));

    let version_disclosed = normalizado
        .observations
        .iter()
        .filter(|o| o.kind == ObservationKind::ServiceVersionDisclosed)
        .count();
    assert_eq!(version_disclosed, 3);

    let os_guess_obs = normalizado
        .observations
        .iter()
        .filter(|o| o.kind == ObservationKind::HostOsGuess)
        .count();
    assert_eq!(os_guess_obs, 1);
}
```

Run: `cargo test --manifest-path src-tauri/Cargo.toml`
Expected: PASS.

- [ ] **Step 4: `clippy`, `fmt`, commit**

Run: `cargo fmt --manifest-path src-tauri/Cargo.toml` luego `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings` luego `cargo test --manifest-path src-tauri/Cargo.toml`

```bash
git add src-tauri/src/adapters/nmap.rs fixtures/nmap/0004-services.xml src-tauri/tests/parsers/nmap_services.rs
git commit -m "$(cat <<'EOF'
feat: adaptador de nmap — fase de servicios, versión y SO

plan() agrupa por host los puertos abiertos que PortSweep encontró y
lanza -sV (más -O si hay privilegio) con la lista exacta de puertos
de ese host. parse() completa producto/versión/túnel/cpe y el
primer osmatch, y emite service.version_disclosed y host.os_guess.
Cierra el adaptador de nmap v1: las tres fases de la spec §7.6 están
implementadas.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: `gen-fixtures` — reescritura de direcciones para fixtures futuros

Herramienta mínima que sustituye direcciones IPv4/MAC de un fichero según una tabla explícita, y falla si encuentra alguna que la tabla no cubre. No se usa todavía sobre datos reales (el laboratorio Windows de la spec §8.1 no existe aún); queda lista y testeada para cuando exista.

**Files:**
- Create: `src-tauri/src/gen_fixtures.rs`
- Create: `tools/gen-fixtures/main.rs`
- Modify: `src-tauri/src/lib.rs` (`pub mod gen_fixtures;`)
- Modify: `src-tauri/Cargo.toml` (dependencia `regex`, target `[[bin]]`)

**Interfaces:**
- Produces: `pub fn reescribir(texto: &str, tabla: &HashMap<String, String>) -> Result<String, Vec<String>>` — función pura, sin dependencia del resto de la app.

- [ ] **Step 1: Dependencia y target de binario**

En `src-tauri/Cargo.toml`, bajo `[dependencies]`:

```toml
regex = "1"
```

Al final del fichero (después de `[target."cfg(unix)".dependencies]`):

```toml

[[bin]]
name = "gen-fixtures"
path = "../tools/gen-fixtures/main.rs"
```

- [ ] **Step 2: Escribir el test que falla**

Crea `src-tauri/src/gen_fixtures.rs`:

```rust
//! Sustitución de direcciones para producir fixtures sintéticos a partir
//! de una captura real. Función pura: sin ella no hay manera de testear
//! la sustitución sin escribir ficheros reales de por medio.
//!
//! IPv6 queda fuera a propósito — mismo alcance que el adaptador de
//! nmap en esta fase.

use std::collections::HashMap;

use regex::Regex;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sustituye_todas_las_apariciones_de_una_ip_mapeada() {
        let texto = "addr=\"203.0.113.9\" otro=\"203.0.113.9\"";
        let mut tabla = HashMap::new();
        tabla.insert("203.0.113.9".to_string(), "198.51.100.20".to_string());
        let resultado = reescribir(texto, &tabla).unwrap();
        assert_eq!(resultado, "addr=\"198.51.100.20\" otro=\"198.51.100.20\"");
    }
}
```

Run: `cargo test --manifest-path src-tauri/Cargo.toml --lib gen_fixtures`
Expected: FAIL — `reescribir` no existe todavía.

- [ ] **Step 3: Implementar `reescribir` y el resto de los tests**

Reemplaza el contenido de `src-tauri/src/gen_fixtures.rs` por:

```rust
//! Sustitución de direcciones para producir fixtures sintéticos a partir
//! de una captura real. Función pura: sin ella no hay manera de testear
//! la sustitución sin escribir ficheros reales de por medio.
//!
//! IPv6 queda fuera a propósito — mismo alcance que el adaptador de
//! nmap en esta fase.

use std::collections::HashMap;

use regex::Regex;

fn patron_ipv4() -> Regex {
    Regex::new(r"\b\d{1,3}(?:\.\d{1,3}){3}\b").expect("patrón ipv4 inválido")
}

fn patron_mac() -> Regex {
    Regex::new(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b").expect("patrón mac inválido")
}

/// Sustituye toda dirección IPv4 o MAC de `texto` según `tabla`. Si
/// encuentra alguna que la tabla no cubre, no sustituye nada: devuelve
/// la lista completa de direcciones sin mapear, para que el operador
/// las añada antes de volver a intentarlo.
pub fn reescribir(texto: &str, tabla: &HashMap<String, String>) -> Result<String, Vec<String>> {
    let re_ip = patron_ipv4();
    let re_mac = patron_mac();

    let mut sin_mapear = Vec::new();
    for m in re_ip.find_iter(texto) {
        if !tabla.contains_key(m.as_str()) {
            sin_mapear.push(m.as_str().to_string());
        }
    }
    for m in re_mac.find_iter(texto) {
        if !tabla.contains_key(m.as_str()) {
            sin_mapear.push(m.as_str().to_string());
        }
    }
    if !sin_mapear.is_empty() {
        sin_mapear.sort();
        sin_mapear.dedup();
        return Err(sin_mapear);
    }

    let intermedio = re_ip.replace_all(texto, |c: &regex::Captures| {
        tabla
            .get(&c[0])
            .cloned()
            .expect("ya verificado que toda dirección está mapeada")
    });
    let final_ = re_mac.replace_all(&intermedio, |c: &regex::Captures| {
        tabla
            .get(&c[0])
            .cloned()
            .expect("ya verificado que toda dirección está mapeada")
    });
    Ok(final_.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sustituye_todas_las_apariciones_de_una_ip_mapeada() {
        let texto = "addr=\"203.0.113.9\" otro=\"203.0.113.9\"";
        let mut tabla = HashMap::new();
        tabla.insert("203.0.113.9".to_string(), "198.51.100.20".to_string());
        let resultado = reescribir(texto, &tabla).unwrap();
        assert_eq!(resultado, "addr=\"198.51.100.20\" otro=\"198.51.100.20\"");
    }

    #[test]
    fn sustituye_una_mac_mapeada() {
        let texto = "vendor addr=\"02:aa:bb:cc:dd:01\"";
        let mut tabla = HashMap::new();
        tabla.insert(
            "02:aa:bb:cc:dd:01".to_string(),
            "0a:11:22:33:44:01".to_string(),
        );
        let resultado = reescribir(texto, &tabla).unwrap();
        assert_eq!(resultado, "vendor addr=\"0a:11:22:33:44:01\"");
    }

    #[test]
    fn falla_y_lista_las_direcciones_sin_mapear_sin_tocar_nada() {
        let texto = "203.0.113.9 y 203.0.113.10";
        let mut tabla = HashMap::new();
        tabla.insert("203.0.113.9".to_string(), "198.51.100.20".to_string());
        let err = reescribir(texto, &tabla).unwrap_err();
        assert_eq!(err, vec!["203.0.113.10".to_string()]);
    }

    #[test]
    fn el_texto_sin_direcciones_pasa_intacto() {
        let texto = "<hostnames><hostname name=\"host.example\"/></hostnames>";
        let tabla = HashMap::new();
        assert_eq!(reescribir(texto, &tabla).unwrap(), texto);
    }
}
```

En `src-tauri/src/lib.rs`, añade `pub mod gen_fixtures;` entre `pub mod exec;` y `pub mod paths;` (orden alfabético del fichero).

Run: `cargo test --manifest-path src-tauri/Cargo.toml --lib gen_fixtures`
Expected: PASS — los 4 tests en verde.

- [ ] **Step 4: El binario CLI**

Crea `tools/gen-fixtures/main.rs`:

```rust
//! Reescribe direcciones IPv4 y MAC de un fichero de entrada según una
//! tabla de sustitución explícita, y las escribe por stdout. Falla si
//! encuentra alguna dirección que la tabla no cubre: es preferible que
//! el operador la añada a mano a que se cuele sin que nadie la vea en
//! un fixture commiteado.
use std::collections::HashMap;
use std::env;
use std::fs;
use std::process::ExitCode;

use auscan_lib::gen_fixtures::reescribir;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let [_, entrada, tabla] = args.as_slice() else {
        eprintln!("uso: gen-fixtures <entrada> <tabla.json>");
        return ExitCode::FAILURE;
    };

    let texto = match fs::read_to_string(entrada) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("no se pudo leer {entrada}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let tabla_json = match fs::read_to_string(tabla) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("no se pudo leer {tabla}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let sustituciones: HashMap<String, String> = match serde_json::from_str(&tabla_json) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("tabla de sustitución inválida: {e}");
            return ExitCode::FAILURE;
        }
    };

    match reescribir(&texto, &sustituciones) {
        Ok(salida) => {
            print!("{salida}");
            ExitCode::SUCCESS
        }
        Err(sin_mapear) => {
            eprintln!("direcciones sin mapear en la tabla de sustitución:");
            for a in sin_mapear {
                eprintln!("  {a}");
            }
            ExitCode::FAILURE
        }
    }
}
```

Run: `cargo build --manifest-path src-tauri/Cargo.toml --bin gen-fixtures`
Expected: compila sin errores.

- [ ] **Step 5: `clippy`, `fmt`, suite completa, commit**

Run: `cargo fmt --manifest-path src-tauri/Cargo.toml` luego `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings` luego `cargo test --manifest-path src-tauri/Cargo.toml`

```bash
git add src-tauri/src/gen_fixtures.rs src-tauri/src/lib.rs src-tauri/Cargo.toml src-tauri/Cargo.lock tools/gen-fixtures/main.rs
git commit -m "$(cat <<'EOF'
feat: gen-fixtures — reescritura de direcciones para fixtures futuros

Herramienta mínima: sustituye IPv4 y MAC de un fichero según una
tabla explícita, y falla si encuentra alguna dirección que la tabla
no cubre, en vez de dejarla pasar sin más. Sus propios tests son
sintético contra sintético (RFC 5737 a RFC 5737), porque el check de
fixtures recorre todo el repositorio y no hay manera de commitear ni
siquiera un "antes" con IPs reales. No se usa todavía sobre datos
reales: el laboratorio de la spec §8.1 no existe aún.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Documentación — cerrar el hueco de la Fase 3 en THREAT-MODEL.md y actualizar el estado en README

**Files:**
- Modify: `docs/THREAT-MODEL.md` (sección T4)
- Modify: `README.md` (sección "Estado")

**Interfaces:** Ninguna — solo texto.

- [ ] **Step 1: Actualizar T4 en THREAT-MODEL.md**

En `docs/THREAT-MODEL.md`, reemplaza el bloque completo desde `` `exec.rs` encadena tres comprobaciones `` hasta el final de la sección T4 (justo antes de `### T5`) por:

```markdown
`exec.rs` encadena tres comprobaciones puras —`validate_targets`,
`validate_flags` y `validate_binary`, combinadas en `verja()`— que correrán
antes de cualquier `spawn` real en cuanto la Fase 5 conecte la ejecución.
Desde la Fase 4, `adapters::registry()` ya incluye el adaptador de nmap con
su lista real de banderas permitidas, pero ningún camino de producción llama
todavía a `verja()`: esta fase construye y parsea, no ejecuta. La verja en sí
existe y está testeada de punta a punta, ahora también contra el descriptor
real de nmap, no solo contra el adaptador de prueba.

**Cerrado en la Fase 4:** el emparejamiento de `validate_flags` era por
prefijo y tenía un hueco identificado en la revisión de la Fase 3 —no era una
lista verdaderamente cerrada (p. ej. `-pwn` casaría con `-p`), y una dirección
sin validar podía colarse pegada a una bandera permitida—. Ahora el
emparejamiento es por igualdad exacta; una bandera marcada `takes_value`
consume el siguiente token del argv como valor opaco en vez de intentar
casarlo como otra bandera.

**Límite conocido:** `needs_privilege` se compara hoy contra la propia
invocación (`Invocation.needs_privilege`, que pone el adaptador), no contra
el privilegio real del proceso. `verja()` no puede detectar todavía una
bandera privilegiada colada en una ejecución sin privilegios de verdad —
exigir que quien la llame pase el privilegio efectivo (`running_privileged()`
o equivalente) queda como requisito de la Fase 5.

**Dónde:** `src-tauri/src/exec.rs` · `src-tauri/src/adapters/nmap.rs` ·
`src-tauri/tests/exec_gate.rs`
```

- [ ] **Step 2: Actualizar el estado en README.md**

En `README.md`, en la sección `## Estado`, reemplaza el párrafo completo por:

```markdown
En construcción. Ahora mismo existe la fundación: modelo de datos, ciclo de vida
del engagement, purga verificable y el guard de alcance completo con sus tests,
más el primer adaptador real: nmap ya sabe describirse, planificar sus
invocaciones y parsear su XML de salida. **Todavía no lanza ninguna herramienta
de auditoría** — eso llega en la Fase 5, cuando el núcleo conecte `verja()` con
un `spawn` real. El preflight sí ejecuta ya comandos propios, locales y de solo
lectura (la versión de cada herramienta instalada, `fdesetup status` para
FileVault) para informar al operador antes de empezar; ninguno es una
herramienta de red ni forma parte de una auditoría.
```

- [ ] **Step 3: Verificación y commit**

Run: `node scripts/checks/fixtures.mjs` (o el script `npm run check` equivalente si envuelve este y los demás checks)
Expected: sale en verde — ningún texto añadido en este task introduce direcciones fuera de RFC 5737/3849.

```bash
git add docs/THREAT-MODEL.md README.md
git commit -m "$(cat <<'EOF'
docs: cerrar en THREAT-MODEL.md el hueco de validate_flags de la Fase 3

Documenta que el emparejamiento por prefijo quedó cerrado con
igualdad exacta más Flag.takes_value, y que el registro de producción
ya incluye nmap aunque nada lo ejecute todavía. Actualiza el estado
del README para reflejar el primer adaptador real.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```
