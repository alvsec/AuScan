# Fase 6 — Elevación de privilegios (macOS) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Dejar que el operador pida explícitamente "elevar" una fase, arrancando un trabajador privilegiado de vida larga (uno por fase) que ejecuta exactamente lo que se le manda, sin romper el streaming en vivo ni la cancelación real que la Fase 5 ya construyó.

**Architecture:** Un binario nuevo y pequeño (`privileged-worker`, análogo a `gen-fixtures`) es el proceso que `osascript ... with administrator privileges` lanza. Su bucle vive en `worker.rs` (testeable sin privilegios de verdad — no le importa ser root o no). El proceso principal lo pilota por ficheros de control (protocolo en `privilege.rs`): le manda órdenes, lee su salida haciendo tail, y lo para con un centinela — nunca lo mata directamente, porque no puede (`EPERM`). `orchestrator.rs` no cambia de forma: cuando una invocación necesita privilegio, `ejecutar_invocacion` llama a `privilege::ejecutar_privilegiado(...)` en vez de `exec::ejecutar(...)`, y el resto del bucle, la verja, la persistencia, siguen exactamente igual.

**Tech Stack:** Rust (tokio, serde/serde_json), `osascript` vía `tokio::process::Command`, React 19 + TS strict, i18next.

**Spec:** `docs/superpowers/specs/2026-08-22-auscan-design.md` §8.5, §8.7-§8.10 (diseño de esta fase), §9.7 (confirmación con argv real), §9.2 (streaming existente que se reutiliza).

## Global Constraints

- `cargo clippy --all-targets -- -D warnings` y `cargo fmt --check` deben salir limpios al final de cada tarea. `npm run check` (fixtures/nohttp/i18n) debe seguir en verde.
- Ninguna dirección fuera de RFC 5737/3849 ni MAC no localmente administrada en ningún fichero del repositorio, incluidos literales de test.
- Commits en español, imperativo, con `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>` — verbatim, no otro nombre de modelo.
- **`elevar: bool` es una petición, nunca una prueba de privilegio.** Puede aceptarse como parámetro en `run_start`/`run_preview` sin reabrir el hueco que la Fase 5 cerró dos veces (una en el adaptador, `verja()` Task 1; otra en el propio `run_start`, antes de existir): `PlanContext.privileged` y el `effective_privileged` que recibe `verja()` NUNCA se fijan directamente desde `elevar`. Se fijan solo desde `Listo.es_root` — el autoinforme que el propio trabajador mide sobre sí mismo (`preflight::running_privileged()` llamado DENTRO del proceso elevado) y escribe antes de aceptar ninguna orden. Si `elevar` es `true` pero la elevación falla, se rechaza o no llega a tiempo, la fase entera falla con un error claro — **sin fallback silencioso a modo sin privilegios** (spec §8.9): eso cambiaría lo que se escanea sin que el operador lo decidiera.
- `-oX -` a stdout, nunca a fichero, sigue sin tocarse: el trabajador redirige la salida del PROCESO a un fichero de un directorio de control TEMPORAL, nunca a `raw/`. `orchestrator.rs` sigue siendo el único que escribe en `raw/`, exactamente como en la Fase 5.
- El guard y la verja se evalúan en el proceso PRINCIPAL antes de que cualquier orden llegue al trabajador. El trabajador no lleva lógica de alcance ni de política — ejecuta lo que se le manda, nunca lo juzga.
- Todo lo específico de macOS (`osascript`, el quoter de AppleScript, `iniciar_trabajador`) va detrás de `#[cfg(target_os = "macos")]`. El resto (protocolo de ficheros, el bucle del trabajador, `ejecutar_privilegiado`) es multiplataforma y se testea en cualquier SO — Windows sigue compilando (§8.1) aunque no reciba trabajo de elevación.
- Un trabajador por FASE — nunca por invocación (inviable, un password por host) ni por sesión de la app (mantendría un proceso root vivo más de lo necesario). Vive tanto como la fase, ni un segundo más.
- El directorio de control es temporal y se borra siempre al terminar la fase — éxito, error o cancelación — nunca vive dentro de `raw/`.
- Ningún `MutexGuard` de `AppState.open` sobrevive a un `.await` (invariante de la Fase 5, no cambia aquí: nada de esta fase toca `state.open` desde un contexto async sin soltar antes el lock).

---

### Task 1: Protocolo de control y quoter de AppleScript/shell

**Files:**
- Create: `src-tauri/src/privilege.rs`
- Modify: `src-tauri/src/lib.rs:1-10` (añadir `pub mod privilege;`)
- Modify: `src-tauri/src/error.rs` (nuevas variantes)
- Test: incluidos en el propio `privilege.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Produces: `pub struct Orden { pub binario: PathBuf, pub argv: Vec<String>, pub ruta_stdout: PathBuf, pub ruta_stderr: PathBuf }`, `pub struct Estado { pub exit_code: Option<i32> }`, `pub struct Listo { pub es_root: bool }`, `pub fn escribir_orden/leer_orden/escribir_estado/leer_estado/escribir_listo/leer_listo/marcar_cancelar/hay_cancelar/marcar_detener/hay_detener/ruta_stdout/ruta_stderr`, y (macOS only) `pub(crate) fn citar_para_shell(s: &str) -> String` / `pub(crate) fn citar_para_applescript(s: &str) -> String`.
- Consumes: `crate::error::{AppError, Result}`.

- [ ] **Step 1: Añadir las variantes de error que esta fase necesita**

Añade a `src-tauri/src/error.rs`, junto a las variantes existentes (mismo estilo: nombre en inglés, mensaje en español):

```rust
    #[error("protocolo de elevación corrupto: {0}")]
    ProtocoloElevacion(String),

    #[error("elevación fallida: {0}")]
    ElevationFailed(String),
```

- [ ] **Step 2: Escribir el test de ida y vuelta del protocolo**

Crea `src-tauri/src/privilege.rs` con el módulo de test primero:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn una_orden_sobrevive_a_escribirse_y_leerse() {
        let dir = tempfile::tempdir().unwrap();
        let orden = Orden {
            binario: PathBuf::from("/usr/bin/true"),
            argv: vec!["-x".to_string(), "198.51.100.5".to_string()],
            ruta_stdout: dir.path().join("0001.stdout"),
            ruta_stderr: dir.path().join("0001.stderr"),
        };
        escribir_orden(dir.path(), 1, &orden).unwrap();
        let leida = leer_orden(dir.path(), 1).unwrap();
        assert_eq!(leida, Some(orden));
    }

    #[test]
    fn leer_una_orden_que_no_existe_da_none_no_error() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(leer_orden(dir.path(), 99).unwrap(), None);
    }

    #[test]
    fn un_estado_sobrevive_a_escribirse_y_leerse() {
        let dir = tempfile::tempdir().unwrap();
        let estado = Estado { exit_code: Some(0) };
        escribir_estado(dir.path(), 1, &estado).unwrap();
        assert_eq!(leer_estado(dir.path(), 1).unwrap(), Some(estado));
    }

    #[test]
    fn un_listo_sobrevive_a_escribirse_y_leerse() {
        let dir = tempfile::tempdir().unwrap();
        escribir_listo(dir.path(), &Listo { es_root: true }).unwrap();
        assert_eq!(leer_listo(dir.path()).unwrap(), Some(Listo { es_root: true }));
    }

    #[test]
    fn los_centinelas_empiezan_ausentes_y_se_pueden_marcar() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!hay_cancelar(dir.path()));
        assert!(!hay_detener(dir.path()));
        marcar_cancelar(dir.path()).unwrap();
        marcar_detener(dir.path()).unwrap();
        assert!(hay_cancelar(dir.path()));
        assert!(hay_detener(dir.path()));
    }
}
```

Confirma que `tempfile` ya está en las dependencias de dev (`grep tempfile src-tauri/Cargo.toml`); si no está, añádela: `tempfile = "3"` bajo `[dev-dependencies]`.

- [ ] **Step 2b: Ejecutar y comprobar que falla**

Run: `cargo test --manifest-path src-tauri/Cargo.toml privilege::tests`
Expected: FAIL — el módulo `privilege` no existe todavía como parte de la librería.

- [ ] **Step 3: Implementar el protocolo**

Encima del módulo de test, en el mismo fichero:

```rust
//! Protocolo de control con el trabajador elevado (Fase 6, spec §8.10).
//! Todo el intercambio con el proceso que corre `with administrator
//! privileges` pasa por ficheros normales en un directorio temporal
//! por fase -- nunca un FIFO, para no toparse con permisos entre un
//! dueño root y uno normal, y porque es literalmente el mecanismo que
//! el spike de la spec (§8.7) validó: redirigir a fichero y leerlo por
//! cuenta propia mientras el proceso elevado sigue vivo.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};

/// Lo que el proceso principal le pide al trabajador que ejecute. Solo
/// datos -- ningún campo de este tipo decide nada por sí mismo, todo lo
/// que hay aquí ya pasó por el guard y la verja antes de construirse.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Orden {
    pub binario: PathBuf,
    pub argv: Vec<String>,
    pub ruta_stdout: PathBuf,
    pub ruta_stderr: PathBuf,
}

/// Lo que el trabajador informa al terminar una orden.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Estado {
    pub exit_code: Option<i32>,
}

/// Lo que el trabajador escribe nada más arrancar, antes de aceptar
/// ninguna orden: si de verdad es root, medido DESDE DENTRO de sí
/// mismo. `osascript` puede devolver éxito sin que el script interior
/// se haya elevado de verdad si algo del entorno falla de forma rara --
/// lo único que cuenta para decidir `PlanContext.privileged` es lo que
/// el propio proceso mide sobre sí mismo, nunca lo que el lanzador
/// dijo. Ver la Global Constraint sobre `elevar` al principio del plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Listo {
    pub es_root: bool,
}

fn ruta_orden(dir_control: &Path, seq: i64) -> PathBuf {
    dir_control.join(format!("{seq:04}.orden.json"))
}

fn ruta_estado(dir_control: &Path, seq: i64) -> PathBuf {
    dir_control.join(format!("{seq:04}.estado.json"))
}

pub fn ruta_stdout(dir_control: &Path, seq: i64) -> PathBuf {
    dir_control.join(format!("{seq:04}.stdout"))
}

pub fn ruta_stderr(dir_control: &Path, seq: i64) -> PathBuf {
    dir_control.join(format!("{seq:04}.stderr"))
}

fn ruta_listo(dir_control: &Path) -> PathBuf {
    dir_control.join("listo.json")
}

fn ruta_cancelar(dir_control: &Path) -> PathBuf {
    dir_control.join("cancelar")
}

fn ruta_detener(dir_control: &Path) -> PathBuf {
    dir_control.join("detener")
}

pub fn escribir_orden(dir_control: &Path, seq: i64, orden: &Orden) -> Result<()> {
    let json = serde_json::to_string(orden).expect("Orden siempre serializa");
    std::fs::write(ruta_orden(dir_control, seq), json).map_err(AppError::Io)
}

pub fn leer_orden(dir_control: &Path, seq: i64) -> Result<Option<Orden>> {
    let ruta = ruta_orden(dir_control, seq);
    if !ruta.exists() {
        return Ok(None);
    }
    let texto = std::fs::read_to_string(&ruta).map_err(AppError::Io)?;
    serde_json::from_str(&texto)
        .map(Some)
        .map_err(|e| AppError::ProtocoloElevacion(e.to_string()))
}

pub fn escribir_estado(dir_control: &Path, seq: i64, estado: &Estado) -> Result<()> {
    let json = serde_json::to_string(estado).expect("Estado siempre serializa");
    std::fs::write(ruta_estado(dir_control, seq), json).map_err(AppError::Io)
}

pub fn leer_estado(dir_control: &Path, seq: i64) -> Result<Option<Estado>> {
    let ruta = ruta_estado(dir_control, seq);
    if !ruta.exists() {
        return Ok(None);
    }
    let texto = std::fs::read_to_string(&ruta).map_err(AppError::Io)?;
    serde_json::from_str(&texto)
        .map(Some)
        .map_err(|e| AppError::ProtocoloElevacion(e.to_string()))
}

pub fn escribir_listo(dir_control: &Path, listo: &Listo) -> Result<()> {
    let json = serde_json::to_string(listo).expect("Listo siempre serializa");
    std::fs::write(ruta_listo(dir_control), json).map_err(AppError::Io)
}

pub fn leer_listo(dir_control: &Path) -> Result<Option<Listo>> {
    let ruta = ruta_listo(dir_control);
    if !ruta.exists() {
        return Ok(None);
    }
    let texto = std::fs::read_to_string(&ruta).map_err(AppError::Io)?;
    serde_json::from_str(&texto)
        .map(Some)
        .map_err(|e| AppError::ProtocoloElevacion(e.to_string()))
}

pub fn marcar_cancelar(dir_control: &Path) -> Result<()> {
    std::fs::write(ruta_cancelar(dir_control), b"").map_err(AppError::Io)
}

pub fn hay_cancelar(dir_control: &Path) -> bool {
    ruta_cancelar(dir_control).exists()
}

pub fn marcar_detener(dir_control: &Path) -> Result<()> {
    std::fs::write(ruta_detener(dir_control), b"").map_err(AppError::Io)
}

pub fn hay_detener(dir_control: &Path) -> bool {
    ruta_detener(dir_control).exists()
}
```

- [ ] **Step 4: Registrar el módulo y comprobar que los tests pasan**

Añade `pub mod privilege;` a `src-tauri/src/lib.rs` junto a los demás `pub mod`.

Run: `cargo test --manifest-path src-tauri/Cargo.toml privilege::tests`
Expected: 5 tests en verde.

- [ ] **Step 5: El quoter — primero el test contra un shell de verdad**

Añade al mismo módulo de test (dentro de `mod tests`), gateado a macOS porque `sh`/`osascript` son lo que se está probando:

```rust
    #[cfg(target_os = "macos")]
    #[test]
    fn citar_para_shell_sobrevive_a_una_ejecucion_real() {
        for entrada in [
            "sencillo",
            "con espacio",
            "con'comilla",
            "con\"comillas dobles",
            "con$variable",
            "con`backtick`",
            "con;punto y coma",
            "con\\barra invertida",
        ] {
            let citado = citar_para_shell(entrada);
            let salida = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("printf '%s' {citado}"))
                .output()
                .unwrap();
            assert_eq!(
                String::from_utf8_lossy(&salida.stdout),
                entrada,
                "citar_para_shell no sobrevivió a: {entrada:?}"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn citar_para_applescript_sobrevive_a_una_ejecucion_real() {
        for entrada in [
            "sencillo",
            "con espacio",
            "con\"comillas\"",
            "con\\barra invertida",
            "con'comilla simple",
        ] {
            let citado = citar_para_applescript(entrada);
            let salida = std::process::Command::new("osascript")
                .arg("-e")
                .arg(format!("return {citado}"))
                .output()
                .unwrap();
            assert_eq!(
                String::from_utf8_lossy(&salida.stdout).trim_end(),
                entrada,
                "citar_para_applescript no sobrevivió a: {entrada:?}"
            );
        }
    }
```

- [ ] **Step 6: Ejecutar y comprobar que falla**

Run: `cargo test --manifest-path src-tauri/Cargo.toml privilege::tests::citar`
Expected: FAIL — `citar_para_shell`/`citar_para_applescript` no existen.

- [ ] **Step 7: Implementar el quoter**

Añade al final de `privilege.rs` (fuera del módulo de test):

```rust
/// Cita una cadena para pasarla como un único argumento literal a `sh`
/// — comillas simples, con el truco POSIX estándar para una comilla
/// simple embebida: se cierra la comilla, se escapa una comilla simple
/// literal, se vuelve a abrir.
#[cfg(target_os = "macos")]
pub(crate) fn citar_para_shell(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Cita una cadena como literal de AppleScript para interpolarla dentro
/// de un `do shell script "..."`. AppleScript escapa con `\` dentro de
/// una cadena entre comillas dobles: hay que escapar las barras
/// invertidas ANTES que las comillas, o una comilla ya escapada
/// quedaría doblemente escapada.
#[cfg(target_os = "macos")]
pub(crate) fn citar_para_applescript(s: &str) -> String {
    let escapado = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escapado}\"")
}
```

- [ ] **Step 8: Ejecutar y comprobar que pasan**

Run: `cargo test --manifest-path src-tauri/Cargo.toml privilege::tests`
Expected: 7 tests en verde (5 del protocolo + 2 del quoter, si estás en macOS; en Windows/Linux los dos del quoter se saltan por el `cfg`, no fallan).

- [ ] **Step 9: `clippy`, `fmt`, commit**

Run: `cargo clippy --all-targets --manifest-path src-tauri/Cargo.toml -- -D warnings && cargo fmt --check --manifest-path src-tauri/Cargo.toml`

```bash
git add src-tauri/src/privilege.rs src-tauri/src/lib.rs src-tauri/src/error.rs src-tauri/Cargo.toml
git commit -m "$(cat <<'EOF'
feat: protocolo de control y quoter de AppleScript/shell

Ficheros normales, no un FIFO -- es el mecanismo que el spike de la
spec (§8.7) validó. El quoter se prueba contra un sh y un osascript de
verdad, no contra las propias suposiciones de escapado.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: El bucle del trabajador

**Files:**
- Modify: `src-tauri/src/exec.rs` (visibilidad de `matar` y `AcumuladorLineas`)
- Create: `src-tauri/src/worker.rs`
- Modify: `src-tauri/src/lib.rs` (`pub mod worker;`)
- Test: `src-tauri/tests/worker.rs`

**Interfaces:**
- Consumes: `privilege::{Orden, Estado, Listo, leer_orden, escribir_estado, escribir_listo, hay_cancelar, hay_detener}` (Task 1), `exec::matar` (este task lo hace reusable), `preflight::running_privileged`.
- Produces: `pub async fn ejecutar_bucle(dir_control: &Path) -> Result<()>`.

- [ ] **Step 1: Hacer reutilizables `matar()` y `AcumuladorLineas`**

En `src-tauri/src/exec.rs`, cambia las firmas (sin tocar el cuerpo):

```rust
pub(crate) struct AcumuladorLineas {
```
(era `struct AcumuladorLineas`)

```rust
impl AcumuladorLineas {
    pub(crate) fn nuevo() -> Self {
```
y
```rust
    pub(crate) fn alimentar(&mut self, bytes: &[u8]) -> Vec<String> {
```
(eran `fn nuevo`/`fn alimentar` sin `pub(crate)`)

```rust
#[cfg(unix)]
pub(crate) async fn matar(hijo: &mut tokio::process::Child, pid: Option<u32>) {
```
y
```rust
#[cfg(not(unix))]
pub(crate) async fn matar(hijo: &mut tokio::process::Child, _pid: Option<u32>) {
```
(eran `async fn matar` sin `pub(crate)`, en las dos variantes `cfg`)

Justo encima de `struct AcumuladorLineas`, añade una línea al comentario que ya existe explicando por qué ahora es `pub(crate)`:

```rust
/// `pub(crate)`: la Fase 6 reutiliza este divisor de líneas para hacer
/// tail de la salida de un proceso elevado, que llega por fichero en
/// vez de por una tubería en memoria -- mismo divisor, otra fuente.
```

Solo visibilidad — ningún cambio de comportamiento. Confirma que los tests existentes de `exec.rs` siguen intactos:

Run: `cargo test --manifest-path src-tauri/Cargo.toml --lib exec::`
Expected: mismos tests, todos en verde, sin cambios.

- [ ] **Step 2: Escribir el test del bucle del trabajador**

El bucle no sabe que corre como root — nada de lo que hace depende de serlo, así que el test lo corre como un proceso normal más, sin `sudo` ni `osascript` de por medio.

Crea `src-tauri/tests/worker.rs`:

```rust
use std::path::Path;
use std::time::Duration;

use auscan_lib::privilege::{self, Orden};
use auscan_lib::worker::ejecutar_bucle;

fn dir_de_prueba() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[tokio::test]
async fn escribe_listo_con_su_propio_estado_de_privilegio_antes_de_esperar_ordenes() {
    let dir = dir_de_prueba();
    let manejo = tokio::spawn(ejecutar_bucle(dir.path().to_path_buf()));

    let listo = esperar_listo(dir.path()).await;
    // El test corre sin privilegios: el trabajador tiene que medir eso
    // de verdad, no asumir nada.
    assert!(!listo.es_root);

    privilege::marcar_detener(dir.path()).unwrap();
    manejo.await.unwrap().unwrap();
}

#[tokio::test]
async fn ejecuta_una_orden_y_escribe_su_salida_y_su_estado() {
    let dir = dir_de_prueba();
    let manejo = tokio::spawn(ejecutar_bucle(dir.path().to_path_buf()));
    esperar_listo(dir.path()).await;

    let orden = Orden {
        binario: PathBuf::from("/bin/echo"),
        argv: vec!["hola-trabajador".to_string()],
        ruta_stdout: privilege::ruta_stdout(dir.path(), 1),
        ruta_stderr: privilege::ruta_stderr(dir.path(), 1),
    };
    privilege::escribir_orden(dir.path(), 1, &orden).unwrap();

    let estado = esperar_estado(dir.path(), 1).await;
    assert_eq!(estado.exit_code, Some(0));
    let stdout = std::fs::read_to_string(&orden.ruta_stdout).unwrap();
    assert_eq!(stdout.trim_end(), "hola-trabajador");

    privilege::marcar_detener(dir.path()).unwrap();
    manejo.await.unwrap().unwrap();
}

#[tokio::test]
async fn el_centinela_de_cancelar_mata_al_hijo_en_curso() {
    let dir = dir_de_prueba();
    let manejo = tokio::spawn(ejecutar_bucle(dir.path().to_path_buf()));
    esperar_listo(dir.path()).await;

    let orden = Orden {
        binario: PathBuf::from("/bin/sleep"),
        argv: vec!["30".to_string()],
        ruta_stdout: privilege::ruta_stdout(dir.path(), 1),
        ruta_stderr: privilege::ruta_stderr(dir.path(), 1),
    };
    privilege::escribir_orden(dir.path(), 1, &orden).unwrap();

    // Le da tiempo a arrancar antes de cancelar, para que sea un
    // proceso en curso de verdad lo que se mata, no una carrera contra
    // el propio spawn.
    tokio::time::sleep(Duration::from_millis(300)).await;
    privilege::marcar_cancelar(dir.path()).unwrap();

    let inicio = tokio::time::Instant::now();
    let estado = esperar_estado(dir.path(), 1).await;
    // `sleep 30` no termina solo en menos de 30s: si el estado llega
    // mucho antes, es que el centinela lo mató de verdad.
    assert!(inicio.elapsed() < Duration::from_secs(5));
    assert_ne!(estado.exit_code, Some(0));

    privilege::marcar_detener(dir.path()).unwrap();
    manejo.await.unwrap().unwrap();
}

#[tokio::test]
async fn el_centinela_de_detener_para_el_bucle_entero() {
    let dir = dir_de_prueba();
    let manejo = tokio::spawn(ejecutar_bucle(dir.path().to_path_buf()));
    esperar_listo(dir.path()).await;

    privilege::marcar_detener(dir.path()).unwrap();
    let resultado = tokio::time::timeout(Duration::from_secs(5), manejo).await;
    assert!(resultado.is_ok(), "el bucle no salió tras el centinela de detener");
}

use std::path::PathBuf;

async fn esperar_listo(dir: &Path) -> privilege::Listo {
    for _ in 0..50 {
        if let Some(l) = privilege::leer_listo(dir).unwrap() {
            return l;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("el trabajador no escribió listo.json a tiempo");
}

async fn esperar_estado(dir: &Path, seq: i64) -> privilege::Estado {
    for _ in 0..100 {
        if let Some(e) = privilege::leer_estado(dir, seq).unwrap() {
            return e;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("el trabajador no escribió el estado a tiempo");
}
```

- [ ] **Step 3: Ejecutar y comprobar que falla**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test worker`
Expected: FAIL en compilación — `auscan_lib::worker` no existe.

- [ ] **Step 4: Implementar el bucle**

Crea `src-tauri/src/worker.rs`:

```rust
//! El bucle del trabajador elevado (spec §8.8-§8.9). Este módulo no
//! sabe que corre como root -- ni falta que le hace. Su única
//! responsabilidad es mecánica: leer una orden, lanzar exactamente ese
//! proceso, redirigir su salida a los ficheros indicados, matarlo si
//! aparece el centinela de cancelar, informar, y repetir hasta que
//! aparezca el de detener. Cero lógica de alcance o de política -- eso
//! ya se decidió en el proceso principal antes de que la orden llegara
//! aquí.
//!
//! Por eso es plenamente testeable SIN privilegios de verdad: nada de
//! lo que hace este bucle depende de ser root, así que los tests lo
//! corren como un proceso normal más (`src-tauri/tests/worker.rs`).

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{AppError, Result};
use crate::exec::matar;
use crate::privilege::{self, Estado, Listo, Orden};

const INTERVALO_SONDEO: Duration = Duration::from_millis(200);

/// Corre el bucle entero: escribe `listo` con su propio estado de
/// privilegio, luego procesa órdenes en orden hasta que aparece el
/// centinela de detener.
pub async fn ejecutar_bucle(dir_control: PathBuf) -> Result<()> {
    privilege::escribir_listo(
        &dir_control,
        &Listo {
            es_root: crate::preflight::running_privileged(),
        },
    )?;

    let mut seq: i64 = 1;
    loop {
        if privilege::hay_detener(&dir_control) {
            return Ok(());
        }
        match privilege::leer_orden(&dir_control, seq)? {
            Some(orden) => {
                procesar_orden(&dir_control, seq, &orden).await?;
                seq += 1;
            }
            None => {
                tokio::time::sleep(INTERVALO_SONDEO).await;
            }
        }
    }
}

async fn procesar_orden(dir_control: &Path, seq: i64, orden: &Orden) -> Result<()> {
    let stdout_f = std::fs::File::create(&orden.ruta_stdout).map_err(AppError::Io)?;
    let stderr_f = std::fs::File::create(&orden.ruta_stderr).map_err(AppError::Io)?;

    let mut comando = tokio::process::Command::new(&orden.binario);
    comando
        .args(&orden.argv)
        .stdout(std::process::Stdio::from(stdout_f))
        .stderr(std::process::Stdio::from(stderr_f))
        .stdin(std::process::Stdio::null());
    #[cfg(unix)]
    comando.process_group(0);

    let mut hijo = comando.spawn().map_err(AppError::Io)?;
    let pid = hijo.id();

    let exit_code = loop {
        if let Some(estado) = hijo.try_wait().map_err(AppError::Io)? {
            break estado.code();
        }
        if privilege::hay_cancelar(dir_control) {
            matar(&mut hijo, pid).await;
            break None;
        }
        tokio::time::sleep(INTERVALO_SONDEO).await;
    };

    privilege::escribir_estado(dir_control, seq, &Estado { exit_code })
}
```

Nota sobre la redirección directa a fichero: al pedirle a `tokio::process::Command` que escriba `stdout`/`stderr` sobre un `File` real (no `Stdio::piped()`), es el propio sistema operativo el que escribe los bytes en disco — captura byte a byte gratis, sin que este módulo tenga que acumular ni volver a montar líneas. Eso es justo lo que `exec::ejecutar()` sí necesita hacer (captura Y streaming a la vez, en el mismo proceso), y por lo que este bucle NO llama a `exec::ejecutar()`: aquí solo hace falta la mitad del trabajo. La otra mitad —convertir esos bytes en líneas para la UI— vive en el lado que SÍ puede permitirse tail-ear un fichero que crece: `orchestrator.rs`, en el Task 4.

Añade `pub mod worker;` a `src-tauri/src/lib.rs`.

- [ ] **Step 5: Ejecutar y comprobar que pasa**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test worker`
Expected: 4 tests en verde.

- [ ] **Step 6: `clippy`, `fmt`, commit**

```bash
cargo clippy --all-targets --manifest-path src-tauri/Cargo.toml -- -D warnings
cargo fmt --check --manifest-path src-tauri/Cargo.toml
git add src-tauri/src/exec.rs src-tauri/src/worker.rs src-tauri/src/lib.rs src-tauri/tests/worker.rs
git commit -m "$(cat <<'EOF'
feat: el bucle del trabajador elevado

Redirige la salida del proceso hijo directamente a fichero -- el
sistema operativo hace la captura byte a byte, este módulo no
necesita re-montar líneas. Sin lógica de alcance: solo ejecuta lo que
se le manda. Probado sin privilegios de verdad, porque nada de lo que
hace depende de serlo.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: El binario del trabajador

**Files:**
- Create: `tools/privileged-worker/main.rs`
- Modify: `src-tauri/Cargo.toml` (nuevo `[[bin]]`)

**Interfaces:**
- Consumes: `auscan_lib::worker::ejecutar_bucle` (Task 2).
- Produces: el binario `privileged-worker`, invocado como `privileged-worker <directorio-de-control>`.

- [ ] **Step 1: Añadir el binario a `Cargo.toml`**

Junto al `[[bin]]` de `gen-fixtures` en `src-tauri/Cargo.toml`:

```toml
[[bin]]
name = "privileged-worker"
path = "../tools/privileged-worker/main.rs"
```

- [ ] **Step 2: Escribir el binario**

Crea `tools/privileged-worker/main.rs`:

```rust
//! Punto de entrada del trabajador elevado. Envoltorio fino a
//! propósito: toda la lógica real vive en `auscan_lib::worker`, donde
//! se puede testear sin privilegios de verdad (ver
//! `src-tauri/tests/worker.rs`). Este binario es justo el proceso que
//! `osascript ... with administrator privileges` lanza -- nada más.
use std::path::PathBuf;
use std::process::ExitCode;

use auscan_lib::worker::ejecutar_bucle;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let [_, dir_control] = args.as_slice() else {
        eprintln!("uso: privileged-worker <directorio-de-control>");
        return ExitCode::FAILURE;
    };

    match ejecutar_bucle(PathBuf::from(dir_control)).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("el trabajador terminó con error: {e}");
            ExitCode::FAILURE
        }
    }
}
```

Confirma que `tokio` con la feature `rt-multi-thread`/`macros` ya está disponible para binarios del paquete (lo está, `Cargo.toml` lo declara para la librería y los binarios del mismo paquete comparten dependencias).

- [ ] **Step 3: Compilar y probar manualmente sin privilegios**

Run: `cargo build --manifest-path src-tauri/Cargo.toml --bin privileged-worker`
Expected: compila sin avisos.

Run (verificación manual, no automatizada — confirma que el binario funciona como proceso suelto antes de que `privilege.rs` lo pilote):
```bash
DIR=$(mktemp -d)
src-tauri/target/debug/privileged-worker "$DIR" &
sleep 1
cat "$DIR/listo.json"
touch "$DIR/detener"
wait
```
Expected: `listo.json` contiene `{"es_root":false}` (no corre elevado), y el proceso termina limpio tras `touch detener`.

- [ ] **Step 4: `clippy`, `fmt`, commit**

```bash
cargo clippy --all-targets --manifest-path src-tauri/Cargo.toml -- -D warnings
cargo fmt --check --manifest-path src-tauri/Cargo.toml
git add tools/privileged-worker/main.rs src-tauri/Cargo.toml
git commit -m "$(cat <<'EOF'
feat: binario privileged-worker

Envoltorio fino sobre auscan_lib::worker::ejecutar_bucle, igual que
gen-fixtures envuelve su propia lógica de librería.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: `privilege.rs` — ciclo de vida y `ejecutar_privilegiado`

**Files:**
- Modify: `src-tauri/src/privilege.rs` (añade el ciclo de vida sobre lo del Task 1)
- Test: `src-tauri/tests/privilege_lifecycle.rs`

**Interfaces:**
- Consumes: todo lo del Task 1 (protocolo, quoter), `exec::{AcumuladorLineas, Linea, LineaOrigen, ResultadoEjecucion}` (ahora reutilizables), `tokio_util::sync::CancellationToken`.
- Produces: `pub struct TrabajadorActivo` (opaco), `pub async fn iniciar_trabajador(dir_control: &Path) -> Result<TrabajadorActivo>` (macOS only), `pub async fn detener_trabajador(trabajador: TrabajadorActivo) -> Result<()>`, `pub async fn ejecutar_privilegiado(trabajador: &TrabajadorActivo, seq: i64, binary_path: &Path, argv: &[String], timeout: Duration, cancelar: CancellationToken, on_linea: impl FnMut(Linea)) -> Result<ResultadoEjecucion>`.

**Nota de diseño, para que quien implemente no se sorprenda:** `ejecutar_privilegiado` tiene la MISMA forma de retorno que `exec::ejecutar()` a propósito — es lo que permite que `orchestrator.rs` (Task 5) solo cambie una línea (qué función llama) sin tocar nada de lo que hace con el resultado.

- [ ] **Step 1: Escribir el test del ciclo de vida completo, sin privilegios reales**

`iniciar_trabajador` de verdad usa `osascript`, que abre un diálogo real y no se puede automatizar en un test. Lo que SÍ se puede probar automáticamente es la parte que importa de verdad: que `TrabajadorActivo`/`ejecutar_privilegiado` funcionan correctamente contra un trabajador YA arrancado (arrancado a mano en el test, saltándose `osascript`, tal como ya se hace en `tests/worker.rs`), incluida la comprobación de `Listo.es_root`.

Crea `src-tauri/tests/privilege_lifecycle.rs`:

```rust
use std::path::PathBuf;
use std::time::Duration;

use auscan_lib::exec::{Linea, LineaOrigen};
use auscan_lib::privilege::{self, TrabajadorActivo};
use auscan_lib::worker::ejecutar_bucle;
use tokio_util::sync::CancellationToken;

async fn trabajador_de_prueba(dir: &std::path::Path) -> (tokio::task::JoinHandle<()>, TrabajadorActivo) {
    let manejo = tokio::spawn({
        let dir = dir.to_path_buf();
        async move {
            ejecutar_bucle(dir).await.unwrap();
        }
    });
    for _ in 0..50 {
        if privilege::leer_listo(dir).unwrap().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    (manejo, TrabajadorActivo::para_pruebas(dir.to_path_buf()))
}

#[tokio::test]
async fn ejecutar_privilegiado_devuelve_la_salida_completa_y_el_codigo() {
    let dir = tempfile::tempdir().unwrap();
    let (manejo, trabajador) = trabajador_de_prueba(dir.path()).await;

    let mut lineas = Vec::new();
    let resultado = privilege::ejecutar_privilegiado(
        &trabajador,
        1,
        &PathBuf::from("/bin/echo"),
        &["linea-uno".to_string()],
        Duration::from_secs(5),
        CancellationToken::new(),
        |l: Linea| lineas.push(l),
    )
    .await
    .unwrap();

    assert_eq!(resultado.exit_code, Some(0));
    assert!(!resultado.cancelado);
    assert_eq!(String::from_utf8_lossy(&resultado.raw).trim_end(), "linea-uno");
    assert!(lineas
        .iter()
        .any(|l| l.origen == LineaOrigen::Stdout && l.texto == "linea-uno"));

    privilege::detener_trabajador(trabajador).await.unwrap();
    manejo.await.unwrap();
}

#[tokio::test]
async fn cancelar_durante_ejecutar_privilegiado_marca_el_centinela_y_espera_el_estado() {
    let dir = tempfile::tempdir().unwrap();
    let (manejo, trabajador) = trabajador_de_prueba(dir.path()).await;

    let token = CancellationToken::new();
    let token_para_cancelar = token.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        token_para_cancelar.cancel();
    });

    let inicio = tokio::time::Instant::now();
    let resultado = privilege::ejecutar_privilegiado(
        &trabajador,
        1,
        &PathBuf::from("/bin/sleep"),
        &["30".to_string()],
        Duration::from_secs(30),
        token,
        |_| {},
    )
    .await
    .unwrap();

    assert!(resultado.cancelado);
    assert!(inicio.elapsed() < Duration::from_secs(10));

    privilege::detener_trabajador(trabajador).await.unwrap();
    manejo.await.unwrap();
}
```

- [ ] **Step 2: Ejecutar y comprobar que falla**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test privilege_lifecycle`
Expected: FAIL en compilación — `TrabajadorActivo`, `para_pruebas`, `ejecutar_privilegiado`, `detener_trabajador` no existen todavía.

- [ ] **Step 3: Implementar el ciclo de vida y `ejecutar_privilegiado`**

Añade al final de `src-tauri/src/privilege.rs`:

```rust
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::exec::{matar, AcumuladorLineas, Linea, LineaOrigen, ResultadoEjecucion};

const INTERVALO_SONDEO_LECTURA: Duration = Duration::from_millis(200);

/// Un trabajador elevado vivo, con su propio directorio de control.
/// `detener_trabajador` es lo único que lo cierra correctamente --
/// dejar caer este valor sin llamarla deja el proceso root esperando
/// órdenes para siempre (por diseño no se implementa `Drop`: cerrar un
/// proceso privilegiado en el destructor de un valor normal, sin poder
/// propagar el error de esa operación, es peor que exigir un cierre
/// explícito).
pub struct TrabajadorActivo {
    dir_control: PathBuf,
    #[cfg(target_os = "macos")]
    osascript: Option<tokio::process::Child>,
}

impl TrabajadorActivo {
    /// Solo para tests: construye un `TrabajadorActivo` que apunta a un
    /// trabajador ya arrancado a mano (saltándose `osascript`, como en
    /// `tests/worker.rs`), para probar `ejecutar_privilegiado` sin
    /// necesitar privilegios de verdad ni un diálogo real.
    #[doc(hidden)]
    pub fn para_pruebas(dir_control: PathBuf) -> Self {
        Self {
            dir_control,
            #[cfg(target_os = "macos")]
            osascript: None,
        }
    }
}

/// Arranca el trabajador elevado para una fase. Resuelve la ruta del
/// binario hermano del propio paquete (nunca una ruta que dependa de
/// dónde esté instalada la app en el sistema del cliente), lo lanza vía
/// `osascript ... with administrator privileges`, y espera a que el
/// propio proceso confirme por escrito que de verdad es root.
///
/// Si el operador rechaza el diálogo, si `osascript` falla, o si el
/// trabajador arranca pero NO es root (entorno raro, no debería pasar
/// nunca) -- error, sin excepción. No hay un modo "casi elevado": ver
/// la Global Constraint sobre `elevar` al principio del plan.
#[cfg(target_os = "macos")]
pub async fn iniciar_trabajador(dir_control: &Path) -> Result<TrabajadorActivo> {
    const PLAZO_ARRANQUE: Duration = Duration::from_secs(120);

    std::fs::create_dir_all(dir_control).map_err(AppError::Io)?;

    let binario_trabajador = std::env::current_exe()
        .map_err(AppError::Io)?
        .parent()
        .ok_or_else(|| AppError::ElevationFailed("no se pudo localizar el binario propio".to_string()))?
        .join("privileged-worker");
    if !binario_trabajador.exists() {
        return Err(AppError::ElevationFailed(format!(
            "no se encontró el binario del trabajador en {}",
            binario_trabajador.display()
        )));
    }

    // Ni la ruta del binario ni la del directorio de control vienen de
    // texto libre del operador -- salen de `current_exe()` y de este
    // mismo proceso -- pero se citan lo mismo, por si acaso: es el
    // mismo principio que aplica la verja a los argv de un adaptador.
    let comando_interno = format!(
        "{} {}",
        citar_para_shell(&binario_trabajador.display().to_string()),
        citar_para_shell(&dir_control.display().to_string())
    );
    let script = format!(
        "do shell script {} with administrator privileges",
        citar_para_applescript(&comando_interno)
    );

    let osascript = tokio::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(AppError::Io)?;

    let plazo = tokio::time::Instant::now() + PLAZO_ARRANQUE;
    loop {
        if let Some(listo) = leer_listo(dir_control)? {
            if !listo.es_root {
                return Err(AppError::ElevationFailed(
                    "el trabajador arrancó pero no es root".to_string(),
                ));
            }
            return Ok(TrabajadorActivo {
                dir_control: dir_control.to_path_buf(),
                osascript: Some(osascript),
            });
        }
        if tokio::time::Instant::now() >= plazo {
            return Err(AppError::ElevationFailed(
                "el operador no autorizó la elevación a tiempo".to_string(),
            ));
        }
        tokio::time::sleep(INTERVALO_SONDEO_LECTURA).await;
    }
}

/// Para el trabajador y limpia su directorio de control. Marca el
/// centinela de detener -- el propio proceso root se apaga solo, la
/// app no puede matarlo directamente -- y espera a que `osascript`
/// termine antes de borrar nada, para no borrar ficheros que el
/// trabajador todavía pudiera tocar.
pub async fn detener_trabajador(mut trabajador: TrabajadorActivo) -> Result<()> {
    marcar_detener(&trabajador.dir_control)?;
    #[cfg(target_os = "macos")]
    if let Some(mut hijo) = trabajador.osascript.take() {
        let _ = hijo.wait().await;
    }
    let _ = std::fs::remove_dir_all(&trabajador.dir_control);
    Ok(())
}

/// Le pide al trabajador que ejecute `binary_path argv`, y hace tail de
/// su salida exactamente como `exec::ejecutar()` hace tail de una
/// tubería -- misma forma de retorno, mismo `AcumuladorLineas`, para
/// que quien llama (`orchestrator.rs`) no note la diferencia más allá
/// de qué función invocó.
#[allow(clippy::too_many_arguments)]
pub async fn ejecutar_privilegiado(
    trabajador: &TrabajadorActivo,
    seq: i64,
    binary_path: &Path,
    argv: &[String],
    timeout: Duration,
    cancelar: CancellationToken,
    mut on_linea: impl FnMut(Linea),
) -> Result<ResultadoEjecucion> {
    let dir_control = &trabajador.dir_control;
    let orden = Orden {
        binario: binary_path.to_path_buf(),
        argv: argv.to_vec(),
        ruta_stdout: ruta_stdout(dir_control, seq),
        ruta_stderr: ruta_stderr(dir_control, seq),
    };
    escribir_orden(dir_control, seq, &orden)?;

    let mut pos_stdout: u64 = 0;
    let mut pos_stderr: u64 = 0;
    let mut acc_stdout = AcumuladorLineas::nuevo();
    let mut acc_stderr = AcumuladorLineas::nuevo();
    let mut raw = Vec::new();
    let mut stderr_completo = Vec::new();
    let plazo = tokio::time::Instant::now() + timeout;

    loop {
        leer_nuevo(&orden.ruta_stdout, &mut pos_stdout, &mut acc_stdout, &mut raw, LineaOrigen::Stdout, &mut on_linea)?;
        leer_nuevo(&orden.ruta_stderr, &mut pos_stderr, &mut acc_stderr, &mut stderr_completo, LineaOrigen::Stderr, &mut on_linea)?;

        if let Some(estado) = leer_estado(dir_control, seq)? {
            // Última pasada, por si quedó algo entre el último sondeo y
            // que el trabajador escribiera el estado.
            leer_nuevo(&orden.ruta_stdout, &mut pos_stdout, &mut acc_stdout, &mut raw, LineaOrigen::Stdout, &mut on_linea)?;
            leer_nuevo(&orden.ruta_stderr, &mut pos_stderr, &mut acc_stderr, &mut stderr_completo, LineaOrigen::Stderr, &mut on_linea)?;
            return Ok(ResultadoEjecucion {
                raw,
                stderr: stderr_completo,
                exit_code: estado.exit_code,
                cancelado: false,
            });
        }

        if cancelar.is_cancelled() || tokio::time::Instant::now() >= plazo {
            marcar_cancelar(dir_control)?;
            // El trabajador es quien mata a su hijo -- esta función
            // solo espera a que confirme que ya lo hizo, con el mismo
            // sondeo del estado que el camino normal.
            loop {
                if leer_estado(dir_control, seq)?.is_some() {
                    break;
                }
                tokio::time::sleep(INTERVALO_SONDEO_LECTURA).await;
            }
            return Ok(ResultadoEjecucion {
                raw,
                stderr: stderr_completo,
                exit_code: None,
                cancelado: true,
            });
        }

        tokio::time::sleep(INTERVALO_SONDEO_LECTURA).await;
    }
}

#[allow(clippy::too_many_arguments)]
fn leer_nuevo(
    ruta: &Path,
    posicion: &mut u64,
    acumulador: &mut AcumuladorLineas,
    destino_bytes: &mut Vec<u8>,
    origen: LineaOrigen,
    on_linea: &mut impl FnMut(Linea),
) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom};

    let Ok(mut f) = std::fs::File::open(ruta) else {
        return Ok(()); // el trabajador todavía no ha creado el fichero
    };
    f.seek(SeekFrom::Start(*posicion)).map_err(AppError::Io)?;
    let mut buf = Vec::new();
    let leidos = f.read_to_end(&mut buf).map_err(AppError::Io)?;
    if leidos == 0 {
        return Ok(());
    }
    *posicion += leidos as u64;
    destino_bytes.extend_from_slice(&buf);
    for linea in acumulador.alimentar(&buf) {
        on_linea(Linea { origen, texto: linea });
    }
    Ok(())
}
```

- [ ] **Step 4: Ejecutar y comprobar que pasan**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test privilege_lifecycle`
Expected: 2 tests en verde.

- [ ] **Step 5: `clippy`, `fmt`, commit**

```bash
cargo clippy --all-targets --manifest-path src-tauri/Cargo.toml -- -D warnings
cargo fmt --check --manifest-path src-tauri/Cargo.toml
git add src-tauri/src/privilege.rs src-tauri/tests/privilege_lifecycle.rs
git commit -m "$(cat <<'EOF'
feat: ciclo de vida del trabajador y ejecutar_privilegiado

ejecutar_privilegiado devuelve exactamente la misma forma que
exec::ejecutar() -- ResultadoEjecucion -- para que orchestrator.rs
pueda elegir entre las dos sin cambiar nada de lo que hace después.
Probado contra un trabajador arrancado a mano, sin osascript ni
privilegios reales: iniciar_trabajador (la única parte que sí depende
de un diálogo real) se prueba manualmente, no en CI.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: `orchestrator.rs` — enrutar y arrancar/parar el trabajador

**Files:**
- Modify: `src-tauri/src/orchestrator.rs`
- Test: `src-tauri/tests/orchestrator.rs` (nuevos casos)

**Interfaces:**
- Consumes: `privilege::{iniciar_trabajador, detener_trabajador, ejecutar_privilegiado, TrabajadorActivo}` (Task 4).
- Produces: `ejecutar_fase` gana un parámetro `elevar: bool`; `privilegio_disponible` deja de ser un parámetro externo y pasa a calcularse dentro de la función.

**Nota de diseño:** `PlanContext.privileged` (que decide qué banderas construye el adaptador) tiene que reflejar si la elevación tuvo éxito ANTES de llamar a `plan()` — así que el intento de elevar pasa a ser el primer paso de `ejecutar_fase`, antes incluso de cargar el alcance.

- [ ] **Step 1: Escribir el test de que una fase sin elevar no cambia de comportamiento**

Añade a `src-tauri/tests/orchestrator.rs` (usa `estado_de_prueba`/`AdaptadorDePrueba` ya existentes en ese fichero):

```rust
#[tokio::test]
async fn una_fase_sin_elevar_no_intenta_arrancar_ningun_trabajador() {
    let (_dir, state, _id) = estado_de_prueba();
    let registro: Vec<Box<dyn ToolAdapter>> = vec![Box::new(AdaptadorDePrueba)];
    let mut eventos = Vec::new();

    ejecutar_fase(
        &state,
        &registro,
        Phase::Discovery,
        "prueba",
        &["198.51.100.5".to_string()],
        false, // elevar
        &PhaseOptions::default(),
        CancellationToken::new(),
        move |s| eventos.push(format!("{s:?}")),
    )
    .await
    .unwrap();
    // Si esto compila y no cuelga (ejecutar_fase no intenta arrancar
    // osascript en background), el camino sin elevar sigue siendo el
    // de siempre.
}
```

- [ ] **Step 2: Ejecutar y comprobar que falla**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test orchestrator una_fase_sin_elevar`
Expected: FAIL en compilación — `ejecutar_fase` todavía toma `privilegio_disponible: bool`, no `elevar: bool`, en esa posición.

- [ ] **Step 3: Cambiar la firma y el arranque/parada del trabajador**

En `src-tauri/src/orchestrator.rs`, añade `use crate::preflight;` al bloque de `use crate::...` existente al principio del fichero (hoy no está — `preflight::running_privileged()` se necesita en este task).

Cambia la firma de `ejecutar_fase`:

```rust
#[allow(clippy::too_many_arguments)]
pub async fn ejecutar_fase(
    state: &AppState,
    registro: &[Box<dyn ToolAdapter>],
    fase: Phase,
    tool_id: &str,
    objetivos_crudos: &[String],
    elevar: bool,
    opciones: &PhaseOptions,
    cancelar: CancellationToken,
    mut on_suceso: impl FnMut(SucesoRun) + Send + 'static,
) -> Result<()> {
    // Elevar, si se pidió, es lo PRIMERO -- antes de cargar el alcance
    // siquiera. `PlanContext.privileged` decide qué banderas construye
    // el adaptador, así que tiene que reflejar si la elevación tuvo
    // éxito ANTES de llamar a `plan()`, no después. Si `elevar` es
    // true y falla, la fase entera falla aquí mismo -- sin fallback
    // silencioso a modo sin privilegios (spec §8.9): eso cambiaría lo
    // que se escanea sin que el operador lo decidiera, y ya vio el
    // argv previsto para `elevar=true` en la confirmación (§9.7).
    #[cfg(target_os = "macos")]
    let trabajador: Option<crate::privilege::TrabajadorActivo> = if elevar {
        let dir_control = std::env::temp_dir().join(format!("auscan-privilegio-{}", uuid_simple()));
        Some(crate::privilege::iniciar_trabajador(&dir_control).await?)
    } else {
        None
    };
    #[cfg(not(target_os = "macos"))]
    let trabajador: Option<()> = if elevar {
        return Err(AppError::ElevationFailed(
            "la elevación solo está disponible en macOS".to_string(),
        ));
    } else {
        None
    };
    let privilegio_disponible = trabajador.is_some() || preflight::running_privileged();

    let resultado = ejecutar_fase_interna(
        state,
        registro,
        fase,
        tool_id,
        objetivos_crudos,
        privilegio_disponible,
        &trabajador,
        opciones,
        cancelar,
        &mut on_suceso,
    )
    .await;

    #[cfg(target_os = "macos")]
    if let Some(t) = trabajador {
        crate::privilege::detener_trabajador(t).await?;
    }

    resultado
}

fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{nanos:x}-{}", std::process::id())
}
```

Renombra la función `ejecutar_fase` ACTUAL (todo su cuerpo tal cual está hoy, sin el arranque/parada del trabajador) a `ejecutar_fase_interna`, y añádele el parámetro `trabajador: &Option<crate::privilege::TrabajadorActivo>` (en no-macOS, `&Option<()>`) justo antes de `opciones`. Su firma queda:

```rust
#[allow(clippy::too_many_arguments)]
async fn ejecutar_fase_interna(
    state: &AppState,
    registro: &[Box<dyn ToolAdapter>],
    fase: Phase,
    tool_id: &str,
    objetivos_crudos: &[String],
    privilegio_disponible: bool,
    #[cfg(target_os = "macos")] trabajador: &Option<crate::privilege::TrabajadorActivo>,
    #[cfg(not(target_os = "macos"))] trabajador: &Option<()>,
    opciones: &PhaseOptions,
    cancelar: CancellationToken,
    on_suceso: &mut (impl FnMut(SucesoRun) + Send + 'static),
) -> Result<()> {
    // ... cuerpo idéntico al `ejecutar_fase` de la Fase 5 ...
}
```

Dentro de `ejecutar_fase_interna`, el bucle YA acumula el `(hosts, servicios, observaciones)` que devuelve cada invocación (Fase 5, ronda de recuentos reales) — no toques esa acumulación, solo añade `trabajador` como argumento en la misma llamada, en la posición que le corresponde según la firma del Step 4:

```rust
        let (h, s, o) = ejecutar_invocacion(
            state,
            registro,
            tool_id,
            &id_engagement,
            invocacion,
            privilegio_disponible,
            trabajador,
            cancelar.clone(),
            &mut on_suceso,
        )
        .await?;
        // Lo que ya hubiera aquí para sumar h/s/o a los totales de la
        // fase sigue exactamente igual -- usa los nombres de variable
        // que el código real ya tenga, no los que aparezcan en este
        // plan si difirieran.
```

- [ ] **Step 4: Enrutar `ejecutar_invocacion` al trabajador cuando hay uno**

En `ejecutar_invocacion`, añade el parámetro `trabajador` justo después de `privilegio_disponible` (mismo tipo condicional que en `ejecutar_fase_interna`):

```rust
#[allow(clippy::too_many_arguments)]
async fn ejecutar_invocacion(
    state: &AppState,
    registro: &[Box<dyn ToolAdapter>],
    tool_id: &str,
    id_engagement: &str,
    invocacion: Invocation,
    privilegio_disponible: bool,
    #[cfg(target_os = "macos")] trabajador: &Option<crate::privilege::TrabajadorActivo>,
    #[cfg(not(target_os = "macos"))] trabajador: &Option<()>,
    cancelar: CancellationToken,
    on_suceso: &mut (impl FnMut(SucesoRun) + Send + 'static),
) -> Result<(usize, usize, usize)> {
```

(la firma sigue devolviendo `Result<(usize, usize, usize)>` — el recuento de hosts/servicios/observaciones de la Fase 5, sin cambios; aquí solo se añade el parámetro `trabajador`.)

Y, dentro del cuerpo, cambia la línea que llama a `exec::ejecutar`:

```rust
    let resultado = match trabajador {
        #[cfg(target_os = "macos")]
        Some(t) => {
            crate::privilege::ejecutar_privilegiado(t, seq, &binario, &invocacion.argv, timeout, cancelar, &mut on_linea).await?
        }
        _ => exec::ejecutar(&binario, &invocacion.argv, timeout, cancelar, &mut on_linea).await?,
    };
```

(`seq` ya existe en el ámbito de `ejecutar_invocacion` — es el mismo que se usa para `crear_tool_run`.)

- [ ] **Step 5: Ejecutar y comprobar que pasan**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test orchestrator`
Expected: todos los tests existentes de `orchestrator.rs` siguen en verde (llamándolos ahora con `elevar: false` donde antes pasaban `privilegio_disponible`), más el nuevo `una_fase_sin_elevar_no_intenta_arrancar_ningun_trabajador`.

Si algún test existente pasaba `true` como `privilegio_disponible` para simular una fase ya-privilegiada (revisa los tests de Task 1 de la Fase 5, `verja_usa_el_privilegio_efectivo...`), NO lo cambies a `elevar: true` — eso ahora intentaría arrancar `osascript` de verdad. Ajusta esos tests para seguir probando lo que probaban (que `privilegio_disponible=true` alimenta correctamente `verja`) llamando a la lógica correspondiente directamente en vez de a través de `ejecutar_fase`, o deja constancia en el informe de la tarea de cuál era el caso y cómo se resolvió.

- [ ] **Step 6: `clippy`, `fmt`, commit**

```bash
cargo clippy --all-targets --manifest-path src-tauri/Cargo.toml -- -D warnings
cargo fmt --check --manifest-path src-tauri/Cargo.toml
git add src-tauri/src/orchestrator.rs src-tauri/tests/orchestrator.rs
git commit -m "$(cat <<'EOF'
feat: orchestrator.rs arranca y para el trabajador según elevar

privilegio_disponible deja de ser un booleano que alguien más decide y
pasa a calcularse aquí: solo es true si de verdad hay un trabajador
vivo y root, o si el propio proceso ya lo es. Elevar es lo primero que
pasa en ejecutar_fase, antes de planificar, porque PlanContext.privileged
tiene que reflejarlo antes de que el adaptador construya banderas.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Comandos Tauri — `elevar` en `run_start` y `run_preview`

**Files:**
- Modify: `src-tauri/src/lib.rs`

**Interfaces:**
- Consumes: `orchestrator::ejecutar_fase`/`orchestrator::planificar` (ahora toman `elevar`/`privileged` con la semántica del Task 5).
- Produces: `run_start(phase, tool_id, targets, elevar: bool)`, `run_preview(phase, tool_id, targets, elevar: bool) -> Vec<String>`.

**Recordatorio de la Global Constraint:** `elevar` es una petición. `run_preview` la usa tal cual para enseñar el argv que se vería SI la elevación (todavía no intentada en esa llamada) tuviera éxito — no ejecuta nada, así que no hay ningún hecho que verificar todavía. `run_start` sí ejecuta de verdad: ahí, `elevar` solo dispara el intento; `orchestrator::ejecutar_fase` (Task 5) es quien decide `privilegio_disponible` de verdad, nunca este comando.

- [ ] **Step 1: `run_preview` gana `elevar`**

En `src-tauri/src/lib.rs`, la firma de `run_preview` pasa a:

```rust
#[tauri::command(async)]
fn run_preview(
    state: State<AppState>,
    phase: String,
    tool_id: String,
    targets: Vec<String>,
    elevar: bool,
) -> Result<Vec<String>> {
    let fase = fase_desde_str(&phase)?;
    let opciones = PhaseOptions::default();
    let registro = adapters::registry();
    let (invocaciones, _id_engagement) =
        orchestrator::planificar(&state, &registro, fase, &tool_id, &targets, elevar, &opciones)?;
    Ok(invocaciones
        .iter()
        .map(|inv| format!("{tool_id} {}", inv.argv.join(" ")))
        .collect())
}
```

(Antes calculaba `privileged` con `preflight::running_privileged()`; ahora usa directamente `elevar`, porque una vista previa es una hipótesis sobre lo que pasaría SI la elevación pedida tuviera éxito, y `planificar` nunca ejecuta nada — no hay ningún hecho de privilegio real que verificar en una llamada de solo lectura.)

- [ ] **Step 2: `run_start` gana `elevar`**

Cambia la firma de `run_start`:

```rust
#[tauri::command]
async fn run_start(
    app: AppHandle,
    state: State<'_, AppState>,
    phase: String,
    tool_id: String,
    targets: Vec<String>,
    elevar: bool,
) -> Result<()> {
```

Dentro, elimina la línea `let privileged = preflight::running_privileged();` (ya no se calcula aquí — `ejecutar_fase` lo calcula internamente, Task 5) y cambia la llamada a `ejecutar_fase` para pasar `elevar` en la posición donde antes iba `privileged`:

```rust
            orchestrator::ejecutar_fase(
                state_interna.inner(),
                &registro,
                fase,
                &tool_id,
                &targets,
                elevar,
                &opciones,
                cancelar,
                move |suceso| { /* ... sin cambios ... */ },
            )
            .await
```

- [ ] **Step 3: Comprobar que compila y los tests de `lib.rs` siguen en verde**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --lib`
Expected: todos en verde. Si algún test de `lib.rs` llamaba a `run_start`/`run_preview` con la firma antigua, ajústalo para pasar `elevar: false` (mismo comportamiento que antes, ahora explícito).

- [ ] **Step 4: `clippy`, `fmt`, commit**

```bash
cargo clippy --all-targets --manifest-path src-tauri/Cargo.toml -- -D warnings
cargo fmt --check --manifest-path src-tauri/Cargo.toml
git add src-tauri/src/lib.rs
git commit -m "$(cat <<'EOF'
feat: run_start y run_preview aceptan elevar

elevar es una petición, no una prueba de privilegio: run_preview la
usa para enseñar el argv hipotético (no ejecuta nada, no hay nada que
verificar); run_start solo la reenvía a ejecutar_fase, que es quien
decide de verdad si hubo privilegio, nunca este comando.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Frontend — casilla "elevar esta fase"

**Files:**
- Modify: `src/data/runs.ts`
- Modify: `src/pages/Run.tsx`
- Modify: `src/pages/Run.test.tsx`
- Modify: `src/i18n/locales/es.json`, `src/i18n/locales/en.json`

**Interfaces:**
- Consumes: `api.preview`/`api.start` (ahora toman `elevar`).

- [ ] **Step 1: Claves de i18n**

Añade a `"run"` en `src/i18n/locales/es.json`:

```json
    "elevar": "Elevar esta fase (pide autorización de administrador)"
```

Y en `en.json`:

```json
    "elevar": "Elevate this phase (asks for administrator authorization)"
```

- [ ] **Step 2: `src/data/runs.ts` gana `elevar`**

```typescript
export const api = {
  preview: (phase: string, toolId: string, targets: string[], elevar: boolean): Promise<string[]> =>
    invoke("run_preview", { phase, toolId, targets, elevar }),
  start: (phase: string, toolId: string, targets: string[], elevar: boolean): Promise<void> =>
    invoke("run_start", { phase, toolId, targets, elevar }),
  cancel: (): Promise<void> => invoke("run_cancel"),
};
```

- [ ] **Step 3: Escribir el test de la casilla antes de tocar `Run.tsx`**

Añade a `src/pages/Run.test.tsx` (sigue el patrón ya establecido en ese fichero: tienda real, `invoke` mockeado con despacho por comando):

```typescript
  it("pide la vista previa con elevar=true si la casilla está marcada", async () => {
    render(<Run />);
    await userEvent.type(screen.getByLabelText(/objetivos/i), "198.51.100.5");
    await userEvent.click(screen.getByLabelText(/elevar esta fase/i));
    await userEvent.click(screen.getByRole("button", { name: /lanzar/i }));

    await waitFor(() => {
      expect(invoke).toHaveBeenCalledWith("run_preview", {
        phase: "discovery",
        toolId: "nmap",
        targets: ["198.51.100.5"],
        elevar: true,
      });
    });
  });

  it("no eleva por defecto", async () => {
    render(<Run />);
    await userEvent.type(screen.getByLabelText(/objetivos/i), "198.51.100.5");
    await userEvent.click(screen.getByRole("button", { name: /lanzar/i }));

    await waitFor(() => {
      expect(invoke).toHaveBeenCalledWith(
        "run_preview",
        expect.objectContaining({ elevar: false }),
      );
    });
  });
```

Comprueba primero cómo el resto de `Run.test.tsx` mockea `run_preview` (probablemente con `invoke.mockImplementation((cmd) => cmd === "run_preview" ? Promise.resolve([...]) : Promise.resolve(undefined))`, siguiendo el patrón de `Preflight.test.tsx`) y ajusta estos dos tests a ese mismo mock si hace falta, en vez de duplicar uno nuevo.

- [ ] **Step 4: Ejecutar y comprobar que falla**

Run: `npx vitest run src/pages/Run.test.tsx`
Expected: FAIL — `Run.tsx` no tiene ninguna casilla de elevar todavía, y llama a `api.preview`/`api.start` sin el cuarto argumento.

- [ ] **Step 5: Añadir la casilla y cablearla**

En `src/pages/Run.tsx`, añade el estado y el control:

```tsx
  const [elevar, setElevar] = useState(false);
```

Junto al resto de controles del formulario (antes del botón de lanzar), deshabilitado con las mismas tres condiciones que ya deshabilitan fase/objetivos:

```tsx
      <label htmlFor="elevar">
        <input
          id="elevar"
          type="checkbox"
          checked={elevar}
          onChange={(e) => setElevar(e.target.checked)}
          disabled={estado === "corriendo" || confirmando || cargandoPrevisualizacion}
        />
        {t("run.elevar")}
      </label>
```

Cambia las dos llamadas que ya existen para incluir `elevar`:

```tsx
      const previsualizacion = await api.preview(fase, "nmap", objetivos, elevar);
```

```tsx
    await iniciar(fase, "nmap", objetivos, elevar);
```

`iniciar` (en `useRunStore.ts`) y `api.start` necesitan el mismo cuarto parámetro — propágalo igual que ya se propaga `phase`/`toolId`/`targets` hoy, sin cambiar nada más de su forma.

- [ ] **Step 6: Ejecutar y comprobar que pasan**

Run: `npx vitest run src/pages/Run.test.tsx`
Expected: todos los tests en verde, incluidos los dos nuevos.

- [ ] **Step 7: `typecheck`, `lint`, `npm run check`, commit**

```bash
npm run check
```

```bash
git add src/data/runs.ts src/pages/Run.tsx src/pages/Run.test.tsx src/store/useRunStore.ts src/i18n/locales/es.json src/i18n/locales/en.json
git commit -m "$(cat <<'EOF'
feat: casilla "elevar esta fase" en la pantalla de ejecución

Se propaga sin cambios hasta run_start/run_preview -- es una petición,
nunca una prueba de privilegio (ver la Global Constraint del plan);
lo único que decide si el privilegio es real es lo que el propio
trabajador informa de sí mismo, en el backend.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Notas para la revisión final

- El único punto de esta fase que un test automatizado no puede cubrir de verdad es `iniciar_trabajador` en macOS: requiere un diálogo real de autorización. Vale la pena que la revisión final incluya una prueba manual real (arrancar la app, marcar "elevar", autorizar de verdad) antes de dar la fase por cerrada — análoga a cómo el spike de la Fase 0 se verificó en la red propia del consultor en vez de solo razonarse.
- El directorio de control temporal (`std::env::temp_dir().join("auscan-privilegio-...")`) se borra en `detener_trabajador`. Si `ejecutar_fase` entrase en pánico entre `iniciar_trabajador` y el `detener_trabajador` del `resultado`, quedaría huérfano — el mismo tipo de fallo que ya se cerró para `ejecucion_activa` con `GuardaEjecucion` en la Fase 5. Si la revisión final lo considera alcanzable, es candidato a un guard RAII análogo; de momento el directorio vive fuera de cualquier dato del engagement, así que un huérfano no es una fuga de datos de cliente, solo basura de `/tmp`.
