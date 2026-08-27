# Fase 5 — Ejecución, streaming y cancelación: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Conectar `verja()` con un `spawn` real por primera vez: lanzar una fase de nmap desde la UI, verla en vivo (log + progreso), poder cancelarla, y que los hosts/servicios/observaciones queden persistidos y encadenados a la fase siguiente.

**Architecture:** Tres módulos Rust nuevos/ampliados — `exec.rs` gana la mecánica de proceso (spawn asíncrono, captura de líneas, cancelación por grupo de procesos), `runs.rs` (nuevo) posee toda la persistencia SQL, `orchestrator.rs` (nuevo) encadena plan→verja→spawn→parse→persistir para una fase. Dos comandos Tauri asíncronos (`run_start`, `run_cancel`) exponen esto a una pantalla nueva de React que muestra el argv para confirmar, el log en vivo, y un recuento final.

**Tech Stack:** `tokio` (proceso async, streaming, timeout), `tokio-util` (`CancellationToken`), `sha2` (hash del raw), Tauri events (`run:log`, `run:progress`, `run:done`).

**Spec:** `docs/superpowers/specs/2026-08-22-auscan-design.md` (§9 completa — 9.1 a 9.9 —, §7.3 la verja, §8 privilegios, §14 plan de fases)

## Global Constraints

- `cargo clippy --all-targets -- -D warnings` y `cargo fmt --check` deben salir limpios al final de cada tarea. `npm run check` (fixtures/nohttp/i18n) debe seguir en verde.
- Ninguna dirección fuera de RFC 5737/3849 ni MAC no localmente administrada en ningún fichero del repositorio, incluidos literales de test.
- Commits en español, imperativo, con `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>` — verbatim, no otro nombre de modelo.
- `verja()` recibe el privilegio efectivo como parámetro explícito (`effective_privileged: bool`); nunca vuelve a leer `Invocation.needs_privilege` para decidir si hay privilegio de verdad.
- El binario a ejecutar se resuelve **una sola vez** por invocación y esa misma `PathBuf` se usa tanto para lanzar como para el `expected_path` de `verja()` — nunca se canoniza, nunca se re-resuelve dos veces con posibilidad de discrepancia.
- Justo antes de cada `spawn`, se revalida la versión del binario contra `descriptor.min_version` otra vez.
- Ningún `MutexGuard` de `AppState.open` se mantiene vivo a través de un `.await`. Cada acceso a la conexión SQL es un bloque síncrono que suelta el lock antes de la siguiente espera asíncrona.
- `-oX -` a stdout, nunca a fichero — ya lo hace el adaptador de nmap desde la Fase 4, esta fase no lo toca.
- Los objetivos de cada fase los escribe el operador y se validan con `Scope::validate_target` en cada lanzamiento, no solo el primero (spec §9.9).
- Sin pantalla de resultados navegable en esta fase (spec §9.8) — solo ejecución en vivo y un recuento final.
- `ObservationKind` no se amplía.
- `progress_from`/`parse_progress` (spec §9.3) no se conectan en esta fase: nmap con `-oX -` no emite ninguna línea de progreso legible por separado (comprobado en vivo — con o sin `-v`, todo lo que produce es la única salida XML, y `stderr` queda vacío), así que el único adaptador que existe siempre devuelve `None`. Conectar ese camino ahora sería construir un paso que ningún test real podría ejercitar. Queda para cuando exista un adaptador (httpx, nuclei) cuyo `parse_progress` sí devuelva algo.

---

## Task 1: `verja()` deja de fiarse de `Invocation.needs_privilege`

Cierra el hueco ledgereado en las revisiones de las Fases 3 y 4: el privilegio efectivo pasa a ser un parámetro explícito que pone quien orquesta, nunca lo que el propio adaptador declaró de sí mismo.

**Files:**
- Modify: `src-tauri/src/exec.rs`
- Modify: `src-tauri/tests/exec_gate.rs`

**Interfaces:**
- Produces: `pub fn verja(invocation: &Invocation, binary_path: &Path, descriptor: &ToolDescriptor, expected_path: &Path, effective_privileged: bool) -> Result<()>` — todas las tareas posteriores que llamen a `verja()` (Task 5) usan esta firma de 5 argumentos.

- [ ] **Step 1: Cambiar la firma de `verja()` y su doc-comment**

En `src-tauri/src/exec.rs`, reemplaza la función `verja` completa (doc-comment incluido):

```rust
/// Las tres comprobaciones juntas, en el orden en que el orquestador las
/// llama antes de cada `spawn`, para todos los adaptadores, sin excepción.
///
/// `effective_privileged` es el privilegio REAL del proceso en este
/// instante (`preflight::running_privileged()` o equivalente) — nunca
/// `invocation.needs_privilege`, que lo declara el propio adaptador. Un
/// adaptador con un fallo (o malicioso) podría marcar `needs_privilege`
/// y aun así intentar ejecutarse sin privilegios de verdad si esta
/// función se fiase de esa autocertificación; por eso el privilegio
/// efectivo entra como parámetro aparte, puesto por quien tiene
/// autoridad para saberlo.
pub fn verja(
    invocation: &Invocation,
    binary_path: &Path,
    descriptor: &ToolDescriptor,
    expected_path: &Path,
    effective_privileged: bool,
) -> Result<()> {
    validate_targets(&invocation.argv, &invocation.targets)?;
    validate_flags(&invocation.argv, descriptor, effective_privileged)?;
    validate_binary(binary_path, expected_path)?;
    Ok(())
}
```

También reemplaza el párrafo "Límite conocido" del doc-comment de `validate_flags` (la función justo antes de `validate_binary`):

```rust
/// **Cerrado en la Fase 5:** `invocation_privileged` lo pone quien
/// llama. Antes de esta fase, la única llamadora (`verja()`) lo sacaba
/// de `Invocation.needs_privilege` — el propio adaptador
/// autocertificándose. Ahora `verja()` recibe el privilegio efectivo
/// del proceso como parámetro explícito y es eso lo que llega aquí.
```

- [ ] **Step 2: Arreglar los 5 sitios que llaman a `verja()` en `exec_gate.rs`**

En `src-tauri/tests/exec_gate.rs`, en `verja_encadena_las_tres_comprobaciones_en_orden`, añade `, false` como quinto argumento a las dos llamadas:

```rust
    assert!(verja(&inv_ok, bin, &d, bin, false).is_ok());
    ...
    assert!(verja(&inv_mal, bin, &d, bin, false).is_err());
```

En `verja_acepta_un_objetivo_autorizado_con_espacios_alrededor`, igual:

```rust
    assert!(
        verja(&inv, bin, &d, bin, false).is_ok(),
        "un objetivo autorizado con espacios no debe rechazarse por la verja combinada"
    );
```

Reemplaza `verja_rechaza_syn_scan_sin_privilegio_con_el_descriptor_real_de_nmap` entera (la que usa `Nmap.descriptor()`) por esta, que prueba la propiedad nueva — que el privilegio EFECTIVO manda, no lo que declara el adaptador:

```rust
#[test]
fn verja_usa_el_privilegio_efectivo_no_lo_que_declara_el_adaptador() {
    use auscan_lib::adapters::nmap::Nmap;

    let scope = scope_198();
    let target = scope.validate("198.51.100.5").unwrap();
    let d = Nmap.descriptor();
    let bin = Path::new("/opt/homebrew/bin/nmap");

    let mut inv = auscan_lib::adapters::Invocation {
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
        needs_privilege: true, // el adaptador DICE que es privilegiada
        raw_from: auscan_lib::adapters::RawSource::Stdout,
        progress_from: auscan_lib::adapters::ProgressSource::None,
        stdin: None,
        timeout: std::time::Duration::from_secs(60),
    };

    // Aunque needs_privilege diga true, si el privilegio EFECTIVO es
    // false, -sS sigue sin poder ejecutarse: la verja no se fía de la
    // autocertificación del adaptador.
    assert!(matches!(
        verja(&inv, bin, &d, bin, false),
        Err(AppError::PrivilegeRequired(_))
    ));

    // Con el privilegio efectivo en true, sí se acepta.
    assert!(verja(&inv, bin, &d, bin, true).is_ok());

    // Y al revés: needs_privilege en false no cambia nada por sí solo
    // si el argv sigue llevando -sS con privilegio efectivo real.
    inv.needs_privilege = false;
    assert!(verja(&inv, bin, &d, bin, true).is_ok());
}
```

- [ ] **Step 3: `clippy`, `fmt`, tests, commit**

Run: `cargo fmt --manifest-path src-tauri/Cargo.toml` luego `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings` luego `cargo test --manifest-path src-tauri/Cargo.toml --test exec_gate`
Expected: todo limpio, los tests de `exec_gate.rs` en verde.

```bash
git add src-tauri/src/exec.rs src-tauri/tests/exec_gate.rs
git commit -m "$(cat <<'EOF'
fix: verja() exige el privilegio efectivo, no lo que declara el adaptador

Añade effective_privileged como parámetro explícito de verja(), en
vez de leer Invocation.needs_privilege internamente. Cierra el hueco
ledgereado en las revisiones finales de las Fases 3 y 4: un adaptador
con un fallo -- o malicioso -- ya no puede autocertificarse
privilegiado y colar una bandera como -sS sin que el proceso tenga
privilegio de verdad.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: `exec.rs` — lanzar un proceso y capturar sus líneas

Primera pieza de la mecánica de ejecución real: lanzar un binario, acumular su stdout/stderr byte a byte (para el hash y el fichero `raw/`), y a la vez invocar un callback por cada línea completa de cualquiera de los dos flujos, para el streaming. Sin cancelación ni timeout todavía — eso es la Task 3.

**Files:**
- Modify: `src-tauri/Cargo.toml` (dependencia `tokio`)
- Modify: `src-tauri/src/exec.rs`
- Create: `src-tauri/tests/exec_spawn.rs`

**Interfaces:**
- Produces: `pub enum LineaOrigen { Stdout, Stderr }`, `pub struct Linea { pub origen: LineaOrigen, pub texto: String }`, `pub struct ResultadoEjecucion { pub raw: Vec<u8>, pub stderr: Vec<u8>, pub exit_code: Option<i32>, pub cancelado: bool }`, `pub async fn ejecutar(binary_path: &Path, argv: &[String], mut on_linea: impl FnMut(Linea)) -> Result<ResultadoEjecucion>`. Task 3 amplía esta firma con `timeout`/`cancelar`; Task 5 la consume tal cual quede al final de la Task 3.

- [ ] **Step 1: Añadir `tokio`**

En `src-tauri/Cargo.toml`, bajo `[dependencies]`:

```toml
tokio = { version = "1", features = ["process", "io-util", "time", "sync"] }
```

- [ ] **Step 2: Implementar la captura de líneas byte-fiel**

**Por qué no basta con `BufReader::lines()`:** esa API separa por `\n` y descarta el separador, así que reconstruir `raw` uniendo líneas con `\n` de nuevo NO reproduce necesariamente los bytes exactos que el proceso escribió (un `raw_sha256` calculado sobre esa reconstrucción podría no coincidir con el hash real de lo que el proceso produjo). En vez de eso, se lee en trozos crudos con `AsyncReadExt::read`, cada trozo se añade a `raw` tal cual, y por separado se alimenta a un acumulador que solo busca `\n` para trocear en líneas de cara al callback — los bytes acumulados nunca pasan por esa tokenización.

En `src-tauri/src/exec.rs`, añade al principio del fichero (tras los `use` existentes):

```rust
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;

/// De qué flujo salió una línea capturada durante una ejecución.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineaOrigen {
    Stdout,
    Stderr,
}

/// Una línea completa de stdout o stderr, para streaming en vivo.
#[derive(Debug, Clone, PartialEq)]
pub struct Linea {
    pub origen: LineaOrigen,
    pub texto: String,
}

/// Lo que queda de una ejecución al terminar.
#[derive(Debug, Clone)]
pub struct ResultadoEjecucion {
    pub raw: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
    pub cancelado: bool,
}

/// Acumula bytes crudos y separa líneas completas por `\n`, tolerando
/// también un `\r\n` final (Windows) al trocear — pero sin que esa
/// tolerancia toque nunca los bytes que se acumulan para `raw`/`stderr`.
struct AcumuladorLineas {
    buffer: Vec<u8>,
}

impl AcumuladorLineas {
    fn nuevo() -> Self {
        Self { buffer: Vec::new() }
    }

    fn alimentar(&mut self, bytes: &[u8]) -> Vec<String> {
        self.buffer.extend_from_slice(bytes);
        let mut lineas = Vec::new();
        while let Some(pos) = self.buffer.iter().position(|&b| b == b'\n') {
            let linea: Vec<u8> = self.buffer.drain(..=pos).collect();
            let mut fin = linea.len() - 1;
            if fin > 0 && linea[fin - 1] == b'\r' {
                fin -= 1;
            }
            lineas.push(String::from_utf8_lossy(&linea[..fin]).into_owned());
        }
        lineas
    }
}
```

Añade la función `ejecutar` al final del fichero:

```rust
/// Lanza `binary_path` con `argv`, acumula todo su stdout y stderr
/// byte a byte, e invoca `on_linea` por cada línea completa de
/// cualquiera de los dos flujos, en el orden en que llegan.
pub async fn ejecutar(
    binary_path: &Path,
    argv: &[String],
    mut on_linea: impl FnMut(Linea),
) -> Result<ResultadoEjecucion> {
    let mut hijo = Command::new(binary_path)
        .args(argv)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::null())
        .spawn()
        .map_err(AppError::Io)?;

    let mut stdout = hijo.stdout.take().expect("stdout se pidió piped()");
    let mut stderr = hijo.stderr.take().expect("stderr se pidió piped()");

    let mut raw = Vec::new();
    let mut stderr_completo = Vec::new();
    let mut lineas_stdout = AcumuladorLineas::nuevo();
    let mut lineas_stderr = AcumuladorLineas::nuevo();
    let mut buf_stdout = [0u8; 4096];
    let mut buf_stderr = [0u8; 4096];
    let mut stdout_cerrado = false;
    let mut stderr_cerrado = false;

    while !(stdout_cerrado && stderr_cerrado) {
        tokio::select! {
            leido = stdout.read(&mut buf_stdout), if !stdout_cerrado => {
                let n = leido.map_err(AppError::Io)?;
                if n == 0 {
                    stdout_cerrado = true;
                } else {
                    raw.extend_from_slice(&buf_stdout[..n]);
                    for linea in lineas_stdout.alimentar(&buf_stdout[..n]) {
                        on_linea(Linea { origen: LineaOrigen::Stdout, texto: linea });
                    }
                }
            }
            leido = stderr.read(&mut buf_stderr), if !stderr_cerrado => {
                let n = leido.map_err(AppError::Io)?;
                if n == 0 {
                    stderr_cerrado = true;
                } else {
                    stderr_completo.extend_from_slice(&buf_stderr[..n]);
                    for linea in lineas_stderr.alimentar(&buf_stderr[..n]) {
                        on_linea(Linea { origen: LineaOrigen::Stderr, texto: linea });
                    }
                }
            }
        }
    }

    let estado = hijo.wait().await.map_err(AppError::Io)?;
    Ok(ResultadoEjecucion {
        raw,
        stderr: stderr_completo,
        exit_code: estado.code(),
        cancelado: false,
    })
}
```

- [ ] **Step 3: Tests con procesos reales triviales**

Crea `src-tauri/tests/exec_spawn.rs` (sigue el mismo patrón que ya usa `preflight.rs` para spawnear `sh`/`cmd` reales en vez de fabricar salidas):

```rust
use std::path::Path;

use auscan_lib::exec::{ejecutar, Linea, LineaOrigen};

#[cfg(unix)]
fn shell() -> (&'static str, &'static str) {
    ("sh", "-c")
}
#[cfg(windows)]
fn shell() -> (&'static str, &'static str) {
    ("cmd", "/C")
}

async fn correr(script_unix: &str, script_windows: &str) -> (auscan_lib::exec::ResultadoEjecucion, Vec<Linea>) {
    let (bin, flag) = shell();
    #[cfg(unix)]
    let script = script_unix;
    #[cfg(windows)]
    let script = script_windows;
    let mut lineas = Vec::new();
    let resultado = ejecutar(Path::new(bin), &[flag.to_string(), script.to_string()], |l| {
        lineas.push(l)
    })
    .await
    .unwrap();
    (resultado, lineas)
}

#[cfg(unix)]
#[tokio::test]
async fn ejecutar_captura_stdout_completo_byte_a_byte() {
    let (resultado, _lineas) = correr("printf 'linea1\\nlinea2\\n'", "").await;
    assert_eq!(resultado.raw, b"linea1\nlinea2\n");
    assert_eq!(resultado.exit_code, Some(0));
}

#[tokio::test]
async fn ejecutar_invoca_on_linea_por_cada_linea_de_stdout() {
    let (_resultado, lineas) = correr(
        "echo uno; echo dos",
        "echo uno&& echo dos",
    )
    .await;
    assert_eq!(lineas.len(), 2);
    assert_eq!(lineas[0], Linea { origen: LineaOrigen::Stdout, texto: "uno".to_string() });
    assert_eq!(lineas[1], Linea { origen: LineaOrigen::Stdout, texto: "dos".to_string() });
}

#[tokio::test]
async fn ejecutar_separa_stderr_de_stdout() {
    let (resultado, lineas) = correr(
        "echo por-stdout; echo por-stderr 1>&2",
        "echo por-stdout&& echo por-stderr 1>&2",
    )
    .await;
    assert!(resultado.raw.starts_with(b"por-stdout"));
    assert!(resultado.stderr.starts_with(b"por-stderr"));
    assert!(lineas
        .iter()
        .any(|l| l.origen == LineaOrigen::Stdout && l.texto == "por-stdout"));
    assert!(lineas
        .iter()
        .any(|l| l.origen == LineaOrigen::Stderr && l.texto == "por-stderr"));
}

#[tokio::test]
async fn ejecutar_devuelve_el_codigo_de_salida_real() {
    let (resultado, _) = correr("exit 7", "exit 7").await;
    assert_eq!(resultado.exit_code, Some(7));
}
```

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test exec_spawn`
Expected: 4 tests en verde (3 en Windows, ya que el primero es `#[cfg(unix)]` — la comprobación byte-exacta se deja solo en Unix porque `cmd`'s `echo` termina en CRLF, no LF, y comparar bytes exactos ahí exigiría una constante distinta por plataforma sin aportar nada que las otras tres pruebas no cubran ya).

- [ ] **Step 4: `clippy`, `fmt`, commit**

Run: `cargo fmt --manifest-path src-tauri/Cargo.toml` luego `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings` luego `cargo test --manifest-path src-tauri/Cargo.toml`

```bash
git add src-tauri/Cargo.toml src-tauri/Cargo.lock src-tauri/src/exec.rs src-tauri/tests/exec_spawn.rs
git commit -m "$(cat <<'EOF'
feat: exec.rs -- lanzar un proceso y capturar sus líneas en vivo

ejecutar() lanza un binario con tokio, acumula stdout/stderr byte a
byte (para el hash y raw/) y por separado invoca un callback por cada
línea completa de cualquiera de los dos flujos, sin que la
tokenización de líneas toque los bytes acumulados. Sin cancelación ni
timeout todavía -- eso llega en la próxima tarea.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: `exec.rs` — cancelación y timeout

**Files:**
- Modify: `src-tauri/Cargo.toml` (dependencia `tokio-util`)
- Modify: `src-tauri/src/exec.rs`
- Modify: `src-tauri/tests/exec_spawn.rs`

**Interfaces:**
- Produces: `pub async fn ejecutar(binary_path: &Path, argv: &[String], timeout: Duration, cancelar: tokio_util::sync::CancellationToken, mut on_linea: impl FnMut(Linea)) -> Result<ResultadoEjecucion>` — firma final que la Task 5 consume.

- [ ] **Step 1: Añadir `tokio-util`**

En `src-tauri/Cargo.toml`, bajo `[dependencies]`:

```toml
tokio-util = "0.7"
```

- [ ] **Step 2: Por qué `CancellationToken` y no `Notify`**

Una fase puede tener varias invocaciones seguidas (`Services` lanza una por host). Si se cancelase con `tokio::sync::Notify`, un `notify_one()` disparado mientras corre la invocación 2 de 3 lo consumiría esa invocación — y la 3 arrancaría fresca, sin ver nada, porque el aviso ya se gastó. `CancellationToken` no tiene ese problema: una vez cancelado, se queda cancelado, y `.cancelled().await` en cualquier invocación posterior resuelve al instante. Es el motivo por el que esta tarea usa `tokio-util` en vez de un canal a mano.

- [ ] **Step 3: Ampliar `ejecutar()` con cancelación y timeout**

En `src-tauri/src/exec.rs`, añade a los `use`:

```rust
use tokio_util::sync::CancellationToken;
```

Reemplaza la firma y el cuerpo de `ejecutar` (mantén `AcumuladorLineas` tal cual):

```rust
/// Lanza `binary_path` con `argv` en su propio grupo de procesos
/// (Unix), acumula stdout/stderr byte a byte e invoca `on_linea` por
/// cada línea completa. Si `cancelar` se activa o `timeout` se agota,
/// mata el grupo entero -- `SIGTERM` y, tras un plazo de gracia,
/// `SIGKILL` -- y devuelve `cancelado: true`. En plataformas sin grupo
/// de procesos POSIX, mata solo el hijo directo sin paso amable.
pub async fn ejecutar(
    binary_path: &Path,
    argv: &[String],
    timeout: Duration,
    cancelar: CancellationToken,
    mut on_linea: impl FnMut(Linea),
) -> Result<ResultadoEjecucion> {
    let mut comando = Command::new(binary_path);
    comando
        .args(argv)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        comando.process_group(0);
    }

    let mut hijo = comando.spawn().map_err(AppError::Io)?;
    let pid = hijo.id();

    let mut stdout = hijo.stdout.take().expect("stdout se pidió piped()");
    let mut stderr = hijo.stderr.take().expect("stderr se pidió piped()");

    let mut raw = Vec::new();
    let mut stderr_completo = Vec::new();
    let mut lineas_stdout = AcumuladorLineas::nuevo();
    let mut lineas_stderr = AcumuladorLineas::nuevo();
    let mut buf_stdout = [0u8; 4096];
    let mut buf_stderr = [0u8; 4096];
    let mut stdout_cerrado = false;
    let mut stderr_cerrado = false;
    let plazo = tokio::time::Instant::now() + timeout;

    loop {
        if stdout_cerrado && stderr_cerrado {
            break;
        }
        tokio::select! {
            leido = stdout.read(&mut buf_stdout), if !stdout_cerrado => {
                let n = leido.map_err(AppError::Io)?;
                if n == 0 {
                    stdout_cerrado = true;
                } else {
                    raw.extend_from_slice(&buf_stdout[..n]);
                    for linea in lineas_stdout.alimentar(&buf_stdout[..n]) {
                        on_linea(Linea { origen: LineaOrigen::Stdout, texto: linea });
                    }
                }
            }
            leido = stderr.read(&mut buf_stderr), if !stderr_cerrado => {
                let n = leido.map_err(AppError::Io)?;
                if n == 0 {
                    stderr_cerrado = true;
                } else {
                    stderr_completo.extend_from_slice(&buf_stderr[..n]);
                    for linea in lineas_stderr.alimentar(&buf_stderr[..n]) {
                        on_linea(Linea { origen: LineaOrigen::Stderr, texto: linea });
                    }
                }
            }
            () = cancelar.cancelled() => {
                matar(&mut hijo, pid).await;
                return Ok(ResultadoEjecucion { raw, stderr: stderr_completo, exit_code: None, cancelado: true });
            }
            () = tokio::time::sleep_until(plazo) => {
                matar(&mut hijo, pid).await;
                return Ok(ResultadoEjecucion { raw, stderr: stderr_completo, exit_code: None, cancelado: true });
            }
        }
    }

    let estado = hijo.wait().await.map_err(AppError::Io)?;
    Ok(ResultadoEjecucion {
        raw,
        stderr: stderr_completo,
        exit_code: estado.code(),
        cancelado: false,
    })
}

#[cfg(unix)]
async fn matar(hijo: &mut tokio::process::Child, pid: Option<u32>) {
    let Some(pid) = pid else { return };
    // SAFETY: enviar una señal a un grupo de procesos que esta misma
    // función creó al lanzar el hijo (`process_group(0)`) no tiene más
    // precondición que un pid válido, y `pid` viene de `Child::id()`
    // sobre un hijo que sigue vivo en este punto.
    unsafe {
        libc::killpg(pid as i32, libc::SIGTERM);
    }
    if tokio::time::timeout(Duration::from_secs(3), hijo.wait())
        .await
        .is_err()
    {
        unsafe {
            libc::killpg(pid as i32, libc::SIGKILL);
        }
        let _ = hijo.wait().await;
    }
}

#[cfg(not(unix))]
async fn matar(hijo: &mut tokio::process::Child, _pid: Option<u32>) {
    let _ = hijo.kill().await;
}
```

- [ ] **Step 4: Tests de cancelación y timeout**

En `src-tauri/tests/exec_spawn.rs`, añade a los `use`:

```rust
use std::time::Duration;

use tokio_util::sync::CancellationToken;
```

Actualiza `correr()` para que reciba también `timeout` y `cancelar`:

```rust
async fn correr_con(
    script_unix: &str,
    script_windows: &str,
    timeout: Duration,
    cancelar: CancellationToken,
) -> (auscan_lib::exec::ResultadoEjecucion, Vec<Linea>) {
    let (bin, flag) = shell();
    #[cfg(unix)]
    let script = script_unix;
    #[cfg(windows)]
    let script = script_windows;
    let mut lineas = Vec::new();
    let resultado = ejecutar(
        Path::new(bin),
        &[flag.to_string(), script.to_string()],
        timeout,
        cancelar,
        |l| lineas.push(l),
    )
    .await
    .unwrap();
    (resultado, lineas)
}

async fn correr(script_unix: &str, script_windows: &str) -> (auscan_lib::exec::ResultadoEjecucion, Vec<Linea>) {
    correr_con(script_unix, script_windows, Duration::from_secs(30), CancellationToken::new()).await
}
```

(las cuatro pruebas de la Task 2 siguen compilando sin cambios, porque `correr()` mantiene su firma; solo cambia su interior)

Añade:

```rust
#[cfg(unix)]
fn dormir_mucho() -> &'static str {
    "sleep 30"
}
#[cfg(windows)]
fn dormir_mucho() -> &'static str {
    "timeout /T 30"
}

#[tokio::test]
async fn ejecutar_se_cancela_cuando_se_solicita() {
    let cancelar = CancellationToken::new();
    let señal = cancelar.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        señal.cancel();
    });
    let script = dormir_mucho();
    let (resultado, _) = correr_con(script, script, Duration::from_secs(60), cancelar).await;
    assert!(resultado.cancelado);
    assert_eq!(resultado.exit_code, None);
}

#[tokio::test]
async fn ejecutar_se_cancela_al_agotar_el_timeout() {
    let script = dormir_mucho();
    let (resultado, _) = correr_con(script, script, Duration::from_millis(200), CancellationToken::new()).await;
    assert!(resultado.cancelado);
}

#[tokio::test]
async fn cancelar_ya_disparado_antes_de_lanzar_tambien_para_el_proceso() {
    // Prueba justo la razón de usar CancellationToken en vez de Notify:
    // un token ya cancelado ANTES de empezar debe seguir contando como
    // cancelado, no perderse.
    let cancelar = CancellationToken::new();
    cancelar.cancel();
    let script = dormir_mucho();
    let (resultado, _) = correr_con(script, script, Duration::from_secs(60), cancelar).await;
    assert!(resultado.cancelado);
}
```

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test exec_spawn`
Expected: 7 tests en verde (Unix) / 6 en Windows.

- [ ] **Step 5: `clippy`, `fmt`, commit**

Run: `cargo fmt --manifest-path src-tauri/Cargo.toml` luego `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings` luego `cargo test --manifest-path src-tauri/Cargo.toml`

```bash
git add src-tauri/Cargo.toml src-tauri/Cargo.lock src-tauri/src/exec.rs src-tauri/tests/exec_spawn.rs
git commit -m "$(cat <<'EOF'
feat: exec.rs -- cancelación por CancellationToken y timeout

El hijo se lanza en su propio grupo de procesos en Unix; cancelar
envía SIGTERM al grupo y SIGKILL tras un plazo de gracia. Se usa
CancellationToken en vez de un Notify porque una fase puede lanzar
varias invocaciones seguidas (Services, una por host) y una señal de
cancelación tiene que seguir siéndolo para la siguiente invocación,
no solo para la que estaba corriendo cuando se pidió.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: `runs.rs` — persistencia de ejecuciones, hosts, servicios y observaciones

Toda la escritura SQL de esta fase, aislada de la mecánica de proceso. Funciones sobre una `Connection`, sin lanzar nada — testeables igual que `scope.rs`.

**Files:**
- Modify: `src-tauri/Cargo.toml` (dependencia `sha2`)
- Modify: `src-tauri/src/error.rs` (`AppError::InconsistentParse`)
- Create: `src-tauri/src/runs.rs`
- Modify: `src-tauri/src/lib.rs` (`pub mod runs;`)
- Create: `src-tauri/tests/runs.rs`

**Interfaces:**
- Consumes: `HostFact`, `ServiceFact`, `ObservationFact`, `ObservationKind`, `KnownState` (de `adapters/mod.rs`, sin cambios).
- Produces: `pub fn siguiente_seq(conn: &Connection) -> Result<i64>`, `pub fn crear_tool_run(conn: &Connection, seq: i64, tool: &str, tool_version: &str, tool_path: &str, phase: &str, argv_json: &str, privileged: bool, targets_json: &str, started_at: &str) -> Result<i64>`, `pub fn cerrar_tool_run(conn: &Connection, id: i64, finished_at: &str, exit_code: Option<i32>, status: &str, raw_path: Option<&str>, raw_sha256: Option<&str>, stderr_path: Option<&str>) -> Result<()>`, `pub fn upsert_hosts(conn: &Connection, tool_run_id: i64, hosts: &[HostFact]) -> Result<HashMap<IpAddr, i64>>`, `pub fn upsert_services(conn: &Connection, tool_run_id: i64, host_ids: &HashMap<IpAddr, i64>, services: &[ServiceFact]) -> Result<()>`, `pub fn insertar_observaciones(conn: &Connection, tool_run_id: i64, host_ids: &HashMap<IpAddr, i64>, observations: &[ObservationFact], observed_at: &str) -> Result<()>`, `pub fn load_known_state(conn: &Connection) -> Result<KnownState>`, `pub fn sha256_hex(bytes: &[u8]) -> String`. Task 5 llama a todas estas.

- [ ] **Step 1: Dependencias y el error nuevo**

En `src-tauri/Cargo.toml`, bajo `[dependencies]`:

```toml
sha2 = "0.10"
```

En `src-tauri/src/error.rs`, añade (junto a `ParseFailed`):

```rust
    #[error("los datos parseados son inconsistentes: {0}")]
    InconsistentParse(String),
```

- [ ] **Step 2: Crear `runs.rs`**

Crea `src-tauri/src/runs.rs`:

```rust
//! Persistencia de ejecuciones, hosts, servicios y observaciones. Sin
//! mecánica de proceso aquí: solo SQL sobre una conexión ya abierta.

use std::collections::HashMap;
use std::net::IpAddr;

use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::adapters::{HostFact, KnownState, ObservationFact, ObservationKind, ServiceFact};
use crate::error::{AppError, Result};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn kind_str(k: ObservationKind) -> &'static str {
    match k {
        ObservationKind::HostDiscovered => "host_discovered",
        ObservationKind::HostOsGuess => "host_os_guess",
        ObservationKind::ServiceOpen => "service_open",
        ObservationKind::ServiceVersionDisclosed => "service_version_disclosed",
        ObservationKind::WebTechnology => "web_technology",
        ObservationKind::WebTitle => "web_title",
        ObservationKind::WebHeaderAbsent => "web_header_absent",
        ObservationKind::TlsProtocolEnabled => "tls_protocol_enabled",
        ObservationKind::TlsCipherOffered => "tls_cipher_offered",
        ObservationKind::TlsCertificateExpiry => "tls_certificate_expiry",
        ObservationKind::SmbSigningState => "smb_signing_state",
        ObservationKind::SshAlgorithmOffered => "ssh_algorithm_offered",
        ObservationKind::TemplateMatch => "template_match",
    }
}

pub fn siguiente_seq(conn: &Connection) -> Result<i64> {
    let seq: i64 = conn.query_row("SELECT COALESCE(MAX(seq), 0) + 1 FROM tool_run", [], |r| {
        r.get(0)
    })?;
    Ok(seq)
}

#[allow(clippy::too_many_arguments)]
pub fn crear_tool_run(
    conn: &Connection,
    seq: i64,
    tool: &str,
    tool_version: &str,
    tool_path: &str,
    phase: &str,
    argv_json: &str,
    privileged: bool,
    targets_json: &str,
    started_at: &str,
) -> Result<i64> {
    conn.execute(
        "INSERT INTO tool_run (seq, tool, tool_version, tool_path, phase, argv_json, privileged, targets_json, started_at, status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'running')",
        rusqlite::params![
            seq,
            tool,
            tool_version,
            tool_path,
            phase,
            argv_json,
            privileged,
            targets_json,
            started_at,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

#[allow(clippy::too_many_arguments)]
pub fn cerrar_tool_run(
    conn: &Connection,
    id: i64,
    finished_at: &str,
    exit_code: Option<i32>,
    status: &str,
    raw_path: Option<&str>,
    raw_sha256: Option<&str>,
    stderr_path: Option<&str>,
) -> Result<()> {
    conn.execute(
        "UPDATE tool_run
         SET finished_at = ?1, exit_code = ?2, status = ?3, raw_path = ?4, raw_sha256 = ?5, stderr_path = ?6
         WHERE id = ?7",
        rusqlite::params![finished_at, exit_code, status, raw_path, raw_sha256, stderr_path, id],
    )?;
    Ok(())
}

/// Upsert de un host. Los campos mutables se conservan si la nueva
/// lectura no trae nada (`COALESCE`): una fase posterior que no vuelve
/// a reportar el hostname o el MAC de un host no debe borrar lo que una
/// fase anterior ya averiguó. `state` sigue la misma regla porque un
/// "up"/"down" de una fase vacía no debería pisar un estado ya
/// confirmado. `last_seen_run` sí se pisa siempre: cualquier ejecución
/// que toque este host cuenta como haberlo visto de nuevo.
pub fn upsert_host(conn: &Connection, tool_run_id: i64, host: &HostFact) -> Result<i64> {
    let id: i64 = conn.query_row(
        "INSERT INTO host (ip, hostname, mac, vendor, os_guess, os_accuracy, state, first_seen_run, last_seen_run)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
         ON CONFLICT(ip) DO UPDATE SET
           hostname = COALESCE(excluded.hostname, hostname),
           mac = COALESCE(excluded.mac, mac),
           vendor = COALESCE(excluded.vendor, vendor),
           os_guess = COALESCE(excluded.os_guess, os_guess),
           os_accuracy = COALESCE(excluded.os_accuracy, os_accuracy),
           state = COALESCE(excluded.state, state),
           last_seen_run = excluded.last_seen_run
         RETURNING id",
        rusqlite::params![
            host.ip.to_string(),
            host.hostname,
            host.mac,
            host.vendor,
            host.os_guess,
            host.os_accuracy,
            host.state,
            tool_run_id,
        ],
        |r| r.get(0),
    )?;
    Ok(id)
}

pub fn upsert_hosts(
    conn: &Connection,
    tool_run_id: i64,
    hosts: &[HostFact],
) -> Result<HashMap<IpAddr, i64>> {
    hosts
        .iter()
        .map(|h| Ok((h.ip, upsert_host(conn, tool_run_id, h)?)))
        .collect()
}

/// Upsert de un servicio. A diferencia de `upsert_host`, `state` se
/// pisa SIEMPRE sin `COALESCE`: el estado de un puerto puede cambiar de
/// verdad entre ejecuciones (una regla de firewall, por ejemplo), y la
/// lectura más reciente es la que debe quedar.
pub fn upsert_service(
    conn: &Connection,
    tool_run_id: i64,
    host_id: i64,
    service: &ServiceFact,
) -> Result<i64> {
    let id: i64 = conn.query_row(
        "INSERT INTO service (host_id, port, proto, state, service, product, version, extrainfo, tunnel, cpe, banner, first_seen_run, last_seen_run)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12)
         ON CONFLICT(host_id, port, proto) DO UPDATE SET
           state = excluded.state,
           service = COALESCE(excluded.service, service),
           product = COALESCE(excluded.product, product),
           version = COALESCE(excluded.version, version),
           extrainfo = COALESCE(excluded.extrainfo, extrainfo),
           tunnel = COALESCE(excluded.tunnel, tunnel),
           cpe = COALESCE(excluded.cpe, cpe),
           banner = COALESCE(excluded.banner, banner),
           last_seen_run = excluded.last_seen_run
         RETURNING id",
        rusqlite::params![
            host_id,
            service.port,
            service.proto,
            service.state,
            service.service,
            service.product,
            service.version,
            service.extrainfo,
            service.tunnel,
            service.cpe,
            service.banner,
            tool_run_id,
        ],
        |r| r.get(0),
    )?;
    Ok(id)
}

pub fn upsert_services(
    conn: &Connection,
    tool_run_id: i64,
    host_ids: &HashMap<IpAddr, i64>,
    services: &[ServiceFact],
) -> Result<()> {
    for s in services {
        let host_id = *host_ids
            .get(&s.host_ip)
            .ok_or_else(|| AppError::InconsistentParse(s.host_ip.to_string()))?;
        upsert_service(conn, tool_run_id, host_id, s)?;
    }
    Ok(())
}

/// `service_id` se deja siempre NULL: `subject` ya identifica
/// "ip:puerto/proto" por completo, y resolver el id exigiría conocer
/// el protocolo, que `ObservationFact` no lleva -- adivinar "tcp" aquí
/// filtraría conocimiento de un adaptador concreto dentro de una capa
/// que sirve a cualquiera.
pub fn insertar_observaciones(
    conn: &Connection,
    tool_run_id: i64,
    host_ids: &HashMap<IpAddr, i64>,
    observations: &[ObservationFact],
    observed_at: &str,
) -> Result<()> {
    for o in observations {
        let host_id = match o.host_ip {
            Some(ip) => Some(
                *host_ids
                    .get(&ip)
                    .ok_or_else(|| AppError::InconsistentParse(ip.to_string()))?,
            ),
            None => None,
        };
        conn.execute(
            "INSERT INTO observation (tool_run_id, host_id, service_id, kind, subject, statement, evidence, evidence_ref, meta_json, observed_at)
             VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(tool_run_id, kind, subject, statement) DO NOTHING",
            rusqlite::params![
                tool_run_id,
                host_id,
                kind_str(o.kind),
                o.subject,
                o.statement,
                o.evidence,
                o.evidence_ref,
                o.meta_json,
                observed_at,
            ],
        )?;
    }
    Ok(())
}

/// Reconstruye lo que ya se sabe de fases anteriores, para alimentar el
/// `plan()` de la siguiente.
pub fn load_known_state(conn: &Connection) -> Result<KnownState> {
    let mut hosts_stmt =
        conn.prepare("SELECT ip, hostname, mac, vendor, os_guess, os_accuracy, state FROM host")?;
    let hosts = hosts_stmt
        .query_map([], |r| {
            let ip: String = r.get(0)?;
            Ok(HostFact {
                ip: ip
                    .parse()
                    .expect("host.ip lo escribe solo upsert_host, siempre una IP válida"),
                hostname: r.get(1)?,
                mac: r.get(2)?,
                vendor: r.get(3)?,
                os_guess: r.get(4)?,
                os_accuracy: r.get(5)?,
                state: r.get(6)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let mut services_stmt = conn.prepare(
        "SELECT host.ip, service.port, service.proto, service.state, service.service,
                service.product, service.version, service.extrainfo, service.tunnel,
                service.cpe, service.banner
         FROM service JOIN host ON host.id = service.host_id",
    )?;
    let services = services_stmt
        .query_map([], |r| {
            let ip: String = r.get(0)?;
            Ok(ServiceFact {
                host_ip: ip
                    .parse()
                    .expect("host.ip lo escribe solo upsert_host, siempre una IP válida"),
                port: r.get(1)?,
                proto: r.get(2)?,
                state: r.get(3)?,
                service: r.get(4)?,
                product: r.get(5)?,
                version: r.get(6)?,
                extrainfo: r.get(7)?,
                tunnel: r.get(8)?,
                cpe: r.get(9)?,
                banner: r.get(10)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(KnownState { hosts, services })
}
```

En `src-tauri/src/lib.rs`, añade `pub mod runs;` entre `pub mod preflight;` y `pub mod scope;` (orden alfabético).

- [ ] **Step 3: Tests de `runs.rs`**

Crea `src-tauri/tests/runs.rs`:

```rust
use std::collections::HashMap;
use std::net::IpAddr;

use auscan_lib::adapters::{HostFact, ObservationFact, ObservationKind, ServiceFact};
use auscan_lib::runs;

fn engagement_abierto() -> (tempfile::TempDir, rusqlite::Connection) {
    let dir = tempfile::tempdir().unwrap();
    let e = auscan_lib::engagement::create(dir.path(), "CLAVEL").unwrap();
    let conn = auscan_lib::engagement::open(dir.path(), &e.id).unwrap();
    (dir, conn)
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

fn servicio_de_prueba(ip: &str, port: u16) -> ServiceFact {
    ServiceFact {
        host_ip: ip.parse::<IpAddr>().unwrap(),
        port,
        proto: "tcp".to_string(),
        state: "open".to_string(),
        service: Some("http".to_string()),
        product: None,
        version: None,
        extrainfo: None,
        tunnel: None,
        cpe: None,
        banner: None,
    }
}

fn crear_run(conn: &rusqlite::Connection, seq: i64, phase: &str, started_at: &str) -> i64 {
    runs::crear_tool_run(
        conn,
        seq,
        "nmap",
        "7.99.0",
        "/opt/homebrew/bin/nmap",
        phase,
        "[]",
        false,
        "[]",
        started_at,
    )
    .unwrap()
}

#[test]
fn siguiente_seq_empieza_en_uno_y_crece() {
    let (_d, conn) = engagement_abierto();
    assert_eq!(runs::siguiente_seq(&conn).unwrap(), 1);
    crear_run(&conn, 1, "discovery", "2026-08-27T10:00:00Z");
    assert_eq!(runs::siguiente_seq(&conn).unwrap(), 2);
}

#[test]
fn upsert_host_inserta_la_primera_vez_y_conserva_datos_al_actualizar() {
    let (_d, conn) = engagement_abierto();
    let run1 = crear_run(&conn, 1, "discovery", "2026-08-27T10:00:00Z");
    let mut h = host_de_prueba("198.51.100.5");
    h.hostname = Some("host5.example".to_string());
    let id1 = runs::upsert_host(&conn, run1, &h).unwrap();

    let run2 = crear_run(&conn, 2, "portsweep", "2026-08-27T10:05:00Z");
    let mut h2 = host_de_prueba("198.51.100.5");
    h2.hostname = None; // esta fase no vuelve a reportar el hostname
    let id2 = runs::upsert_host(&conn, run2, &h2).unwrap();

    assert_eq!(id1, id2, "mismo host, mismo id");
    let known = runs::load_known_state(&conn).unwrap();
    assert_eq!(known.hosts.len(), 1);
    assert_eq!(
        known.hosts[0].hostname.as_deref(),
        Some("host5.example"),
        "un None de una fase posterior no debe borrar lo que ya se sabía"
    );
}

#[test]
fn upsert_service_pisa_el_estado_aunque_cambie() {
    let (_d, conn) = engagement_abierto();
    let run1 = crear_run(&conn, 1, "portsweep", "2026-08-27T10:00:00Z");
    let host_id = runs::upsert_host(&conn, run1, &host_de_prueba("198.51.100.5")).unwrap();
    let mut s = servicio_de_prueba("198.51.100.5", 80);
    s.state = "open".to_string();
    runs::upsert_service(&conn, run1, host_id, &s).unwrap();

    let run2 = crear_run(&conn, 2, "portsweep", "2026-08-27T11:00:00Z");
    let mut s2 = servicio_de_prueba("198.51.100.5", 80);
    s2.state = "closed".to_string();
    runs::upsert_service(&conn, run2, host_id, &s2).unwrap();

    let known = runs::load_known_state(&conn).unwrap();
    assert_eq!(known.services.len(), 1);
    assert_eq!(known.services[0].state, "closed");
}

#[test]
fn insertar_observaciones_no_duplica_la_misma_observacion() {
    let (_d, conn) = engagement_abierto();
    let run = crear_run(&conn, 1, "discovery", "2026-08-27T10:00:00Z");
    let host_id = runs::upsert_host(&conn, run, &host_de_prueba("198.51.100.5")).unwrap();
    let mut ids = HashMap::new();
    ids.insert("198.51.100.5".parse::<IpAddr>().unwrap(), host_id);
    let obs = vec![ObservationFact {
        host_ip: Some("198.51.100.5".parse().unwrap()),
        port: None,
        kind: ObservationKind::HostDiscovered,
        subject: "198.51.100.5".to_string(),
        statement: "Host activo".to_string(),
        evidence: None,
        evidence_ref: None,
        meta_json: None,
    }];
    runs::insertar_observaciones(&conn, run, &ids, &obs, "2026-08-27T10:00:01Z").unwrap();
    runs::insertar_observaciones(&conn, run, &ids, &obs, "2026-08-27T10:00:01Z").unwrap();

    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM observation", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1);
}

#[test]
fn insertar_observaciones_falla_si_el_host_no_esta_en_el_mapa() {
    let (_d, conn) = engagement_abierto();
    let run = crear_run(&conn, 1, "discovery", "2026-08-27T10:00:00Z");
    let ids = HashMap::new(); // vacío a propósito
    let obs = vec![ObservationFact {
        host_ip: Some("198.51.100.5".parse().unwrap()),
        port: None,
        kind: ObservationKind::HostDiscovered,
        subject: "198.51.100.5".to_string(),
        statement: "Host activo".to_string(),
        evidence: None,
        evidence_ref: None,
        meta_json: None,
    }];
    assert!(matches!(
        runs::insertar_observaciones(&conn, run, &ids, &obs, "2026-08-27T10:00:01Z"),
        Err(auscan_lib::error::AppError::InconsistentParse(_))
    ));
}

#[test]
fn cerrar_tool_run_actualiza_los_campos_finales() {
    let (_d, conn) = engagement_abierto();
    let id = crear_run(&conn, 1, "discovery", "2026-08-27T10:00:00Z");
    runs::cerrar_tool_run(
        &conn,
        id,
        "2026-08-27T10:00:05Z",
        Some(0),
        "ok",
        Some("raw/0001-nmap-discovery.xml"),
        Some(&runs::sha256_hex(b"contenido")),
        None,
    )
    .unwrap();
    let (status, exit_code): (String, Option<i32>) = conn
        .query_row("SELECT status, exit_code FROM tool_run WHERE id = ?1", [id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(status, "ok");
    assert_eq!(exit_code, Some(0));
}

#[test]
fn sha256_hex_es_determinista_y_de_64_caracteres_hex() {
    let a = runs::sha256_hex(b"lo mismo");
    let b = runs::sha256_hex(b"lo mismo");
    assert_eq!(a, b);
    assert_eq!(a.len(), 64);
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
}
```

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test runs`
Expected: 7 tests en verde.

- [ ] **Step 4: `clippy`, `fmt`, commit**

Run: `cargo fmt --manifest-path src-tauri/Cargo.toml` luego `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings` luego `cargo test --manifest-path src-tauri/Cargo.toml`

```bash
git add src-tauri/Cargo.toml src-tauri/Cargo.lock src-tauri/src/error.rs src-tauri/src/runs.rs src-tauri/src/lib.rs src-tauri/tests/runs.rs
git commit -m "$(cat <<'EOF'
feat: runs.rs -- persistencia de ejecuciones, hosts, servicios y observaciones

Upsert de host/service con COALESCE para no perder lo que una fase
anterior ya sabía cuando una posterior no vuelve a reportarlo -- salvo
el estado de un servicio, que sí se pisa siempre porque puede cambiar
de verdad entre ejecuciones. load_known_state() reconstruye el
KnownState que alimenta el plan() de la siguiente fase. Sin mecánica
de proceso aquí: solo SQL sobre una conexión ya abierta.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: `orchestrator.rs` — encadenar plan → verja → spawn → parse → persistir

La tarea más delicada del plan. Junta todo lo anterior para ejecutar una fase completa. El punto que exige más cuidado: **ningún `MutexGuard` de `AppState.open` puede seguir vivo a través de un `.await`** — cada acceso a la conexión SQL es un bloque que suelta el lock antes de esperar al proceso.

**Files:**
- Create: `src-tauri/src/orchestrator.rs`
- Modify: `src-tauri/src/error.rs` (`AppError::ToolVersionInsuficiente`)
- Modify: `src-tauri/src/lib.rs` (`pub mod orchestrator;`)
- Create: `src-tauri/tests/orchestrator.rs`

**Interfaces:**
- Consumes: `verja` de 5 argumentos (Task 1), `exec::ejecutar` con `CancellationToken` (Task 3), todo `runs::*` (Task 4), `AppState`/`OpenEngagement` (ya existentes), `paths::raw_dir`, `db::now_iso`, `scope::{Scope, SystemResolver}`, `adapters::{PlanContext, ParseContext, ToolAdapter, Phase, PhaseOptions}`.
- Produces: `pub enum SucesoRun { Log { origen: exec::LineaOrigen, texto: String }, RunTerminado { seq: i64, status: String }, FaseTerminada }`, `pub async fn ejecutar_fase(state: &AppState, registro: &[Box<dyn ToolAdapter>], fase: Phase, tool_id: &str, objetivos_crudos: &[String], privilegio_disponible: bool, opciones: &PhaseOptions, cancelar: CancellationToken, on_suceso: impl FnMut(SucesoRun) + Send + 'static) -> Result<()>`. Task 6 llama a esta función desde un comando Tauri.

- [ ] **Step 1: El error de versión insuficiente**

En `src-tauri/src/error.rs`, añade:

```rust
    #[error("{tool} está en {actual}, pero esta fase exige al menos {minimo}")]
    ToolVersionInsuficiente {
        tool: String,
        actual: String,
        minimo: String,
    },
```

- [ ] **Step 2: Crear `orchestrator.rs`**

Crea `src-tauri/src/orchestrator.rs`:

```rust
//! Encadena plan → verja → spawn → parse → persistir para una fase
//! completa. El único módulo que sabe hacer las cinco cosas a la vez;
//! cada una por separado vive en su propio fichero (`adapters`,
//! `exec`, `runs`) precisamente para que este quede como el único
//! sitio que las junta.

use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::adapters::{Invocation, ParseContext, Phase, PhaseOptions, PlanContext, ToolAdapter};
use crate::db;
use crate::error::{AppError, Result};
use crate::exec::{self, LineaOrigen};
use crate::paths;
use crate::runs;
use crate::scope::{self, SystemResolver};
use crate::state::AppState;

/// Lo que le pasa a quien esté viendo la ejecución en vivo.
pub enum SucesoRun {
    Log { origen: LineaOrigen, texto: String },
    RunTerminado { seq: i64, status: String },
    FaseTerminada,
}

fn fase_str(f: Phase) -> &'static str {
    match f {
        Phase::Discovery => "discovery",
        Phase::PortSweep => "portsweep",
        Phase::Services => "services",
        Phase::Web => "web",
        Phase::Templates => "templates",
        Phase::Tls => "tls",
        Phase::Smb => "smb",
        Phase::Ssh => "ssh",
        Phase::Mdns => "mdns",
    }
}

/// Ejecuta una fase completa: arma el `PlanContext`, pide las
/// invocaciones al adaptador, y lanza cada una en orden.
#[allow(clippy::too_many_arguments)]
pub async fn ejecutar_fase(
    state: &AppState,
    registro: &[Box<dyn ToolAdapter>],
    fase: Phase,
    tool_id: &str,
    objetivos_crudos: &[String],
    privilegio_disponible: bool,
    opciones: &PhaseOptions,
    cancelar: CancellationToken,
    mut on_suceso: impl FnMut(SucesoRun) + Send + 'static,
) -> Result<()> {
    let (invocaciones, id_engagement) = {
        // Bloque síncrono: el guard se suelta al final de este bloque,
        // antes de cualquier `.await`.
        let guard = state.open.lock().unwrap_or_else(|e| e.into_inner());
        let abierto = guard.as_ref().ok_or(AppError::NoEngagementOpen)?;
        let conn = &abierto.conn;

        let scope = scope::load(conn)?;
        let resolver = SystemResolver;
        let mut targets = Vec::new();
        for t in objetivos_crudos {
            targets.extend(scope.validate_target(t, &resolver)?);
        }

        let known = runs::load_known_state(conn)?;
        let adaptador = registro
            .iter()
            .find(|a| a.descriptor().id == tool_id)
            .ok_or_else(|| AppError::ToolNotFound(tool_id.to_string()))?;
        let ctx = PlanContext {
            phase: fase,
            scope: &scope,
            targets: &targets,
            known: &known,
            privileged: privilegio_disponible,
            options: opciones,
        };
        (adaptador.plan(&ctx)?, abierto.id.clone())
    };

    for invocacion in invocaciones {
        ejecutar_invocacion(
            state,
            registro,
            tool_id,
            &id_engagement,
            invocacion,
            privilegio_disponible,
            cancelar.clone(),
            &mut on_suceso,
        )
        .await?;
    }
    on_suceso(SucesoRun::FaseTerminada);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn ejecutar_invocacion(
    state: &AppState,
    registro: &[Box<dyn ToolAdapter>],
    tool_id: &str,
    id_engagement: &str,
    invocacion: Invocation,
    privilegio_disponible: bool,
    cancelar: CancellationToken,
    on_suceso: &mut (impl FnMut(SucesoRun) + Send + 'static),
) -> Result<()> {
    let adaptador = registro
        .iter()
        .find(|a| a.descriptor().id == tool_id)
        .ok_or_else(|| AppError::ToolNotFound(tool_id.to_string()))?;
    let descriptor = adaptador.descriptor();

    // Se resuelve UNA sola vez: esta misma ruta se usa para lanzar y
    // para el `expected_path` de la verja. El hueco de symlinks de
    // Homebrew desaparece por construcción, no por canonicalizar.
    let binario = which::which(descriptor.binaries[0])
        .map_err(|_| AppError::ToolNotFound(tool_id.to_string()))?;

    // Revalidación de versión justo antes de ejecutar: si cambió desde
    // el preflight (un `brew upgrade` de por medio), no se lanza.
    let salida_version = std::process::Command::new(&binario)
        .args(adaptador.version_argv())
        .output()
        .map_err(AppError::Io)?;
    let version = adaptador
        .parse_version(&String::from_utf8_lossy(&salida_version.stdout))
        .map_err(|_| AppError::ToolVersionInsuficiente {
            tool: tool_id.to_string(),
            actual: "desconocida".to_string(),
            minimo: descriptor.min_version.to_string(),
        })?;
    if version < descriptor.min_version {
        return Err(AppError::ToolVersionInsuficiente {
            tool: tool_id.to_string(),
            actual: version.to_string(),
            minimo: descriptor.min_version.to_string(),
        });
    }

    exec::verja(&invocacion, &binario, &descriptor, &binario, privilegio_disponible)?;

    let (tool_run_id, seq) = {
        let guard = state.open.lock().unwrap_or_else(|e| e.into_inner());
        let abierto = guard.as_ref().ok_or(AppError::NoEngagementOpen)?;
        let conn = &abierto.conn;
        let seq = runs::siguiente_seq(conn)?;
        let targets_json = serde_json::to_string(
            &invocacion
                .targets
                .iter()
                .map(|t| t.to_string())
                .collect::<Vec<_>>(),
        )
        .expect("Vec<String> siempre serializa");
        let argv_json =
            serde_json::to_string(&invocacion.argv).expect("Vec<String> siempre serializa");
        let id = runs::crear_tool_run(
            conn,
            seq,
            descriptor.id,
            &version.to_string(),
            &binario.display().to_string(),
            fase_str(invocacion.phase),
            &argv_json,
            invocacion.needs_privilege,
            &targets_json,
            &db::now_iso(),
        )?;
        (id, seq)
    };

    let raw_dir = paths::raw_dir(&state.root, id_engagement)?;
    std::fs::create_dir_all(&raw_dir).map_err(AppError::Io)?;
    let nombre_raw = format!(
        "{seq:04}-{}-{}.xml",
        descriptor.id,
        fase_str(invocacion.phase)
    );
    let raw_rel = format!("raw/{nombre_raw}");

    let mut on_linea = |l: exec::Linea| {
        on_suceso(SucesoRun::Log {
            origen: l.origen,
            texto: l.texto,
        });
    };
    let timeout: Duration = invocacion.timeout;
    let resultado = exec::ejecutar(&binario, &invocacion.argv, timeout, cancelar, &mut on_linea).await?;

    std::fs::write(raw_dir.join(&nombre_raw), &resultado.raw).map_err(AppError::Io)?;
    let raw_sha256 = runs::sha256_hex(&resultado.raw);

    let status = if resultado.cancelado {
        "cancelled"
    } else if resultado.exit_code == Some(0) {
        "ok"
    } else {
        "failed"
    };

    {
        let guard = state.open.lock().unwrap_or_else(|e| e.into_inner());
        let abierto = guard.as_ref().ok_or(AppError::NoEngagementOpen)?;
        let conn = &abierto.conn;
        runs::cerrar_tool_run(
            conn,
            tool_run_id,
            &db::now_iso(),
            resultado.exit_code,
            status,
            Some(&raw_rel),
            Some(&raw_sha256),
            None,
        )?;

        if !resultado.cancelado && status == "ok" {
            let ctx = ParseContext {
                tool_run_id,
                raw_path: &raw_rel,
                observed_at: &db::now_iso(),
            };
            match adaptador.parse(&resultado.raw, &ctx) {
                Ok(normalizado) => {
                    let host_ids = runs::upsert_hosts(conn, tool_run_id, &normalizado.hosts)?;
                    runs::upsert_services(conn, tool_run_id, &host_ids, &normalizado.services)?;
                    runs::insertar_observaciones(
                        conn,
                        tool_run_id,
                        &host_ids,
                        &normalizado.observations,
                        &db::now_iso(),
                    )?;
                }
                Err(e) => {
                    on_suceso(SucesoRun::Log {
                        origen: LineaOrigen::Stderr,
                        texto: format!("no se pudo interpretar la salida: {e}"),
                    });
                }
            }
        }
    }

    on_suceso(SucesoRun::RunTerminado {
        seq,
        status: status.to_string(),
    });
    Ok(())
}
```

En `src-tauri/src/lib.rs`, añade `pub mod orchestrator;` entre `pub mod paths;` (después de `runs`, orden alfabético: adapters, db, engagement, error, exec, gen_fixtures, orchestrator, paths, preflight, runs, scope, state).

- [ ] **Step 3: Test de extremo a extremo con `FakeAdapter` y un binario real trivial**

`FakeAdapter` (en `tests/common/mod.rs`) usa `"fake-tool"` como binario, que no existe en el `PATH` de una máquina de test — para probar el orquestador de punta a punta sin depender de que nmap esté instalado, se necesita un adaptador de prueba que apunte a un binario que SÍ existe siempre: `sh` (Unix) / `cmd` (Windows), y cuyo `parse()` sea trivial.

Crea `src-tauri/tests/orchestrator.rs`:

```rust
mod common;

use std::sync::Arc;
use std::time::Duration;

use auscan_lib::adapters::{
    Flag, HostFact, InstallHint, Invocation, Normalized, ObservationFact, ObservationKind,
    ParseContext, Phase, PhaseOptions, PlanContext, ProgressSource, RawSource, ToolAdapter,
    ToolDescriptor,
};
use auscan_lib::error::Result;
use auscan_lib::orchestrator::{ejecutar_fase, SucesoRun};
use auscan_lib::scope::ScopeKind;
use auscan_lib::state::AppState;
use semver::Version;
use tokio_util::sync::CancellationToken;

#[cfg(unix)]
const BINARIO: &str = "sh";
#[cfg(windows)]
const BINARIO: &str = "cmd";

/// Adaptador de prueba para el orquestador: apunta a un binario que
/// siempre existe (`sh`/`cmd`) y produce un host fijo sin leer nada de
/// su salida real -- lo que importa aquí es la orquestación, no el
/// parseo.
struct AdaptadorDePrueba;

impl ToolAdapter for AdaptadorDePrueba {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            id: "prueba",
            binaries: &[BINARIO],
            min_version: Version::new(0, 0, 1),
            phases: &[Phase::Discovery],
            install_hint: InstallHint {
                brew: &["install", "prueba"],
                winget: &["install", "-e", "Prueba"],
            },
            allowed_flags: &[],
        }
    }

    fn version_argv(&self) -> Vec<String> {
        #[cfg(unix)]
        return vec!["-c".to_string(), "echo prueba 1.0.0".to_string()];
        #[cfg(windows)]
        return vec!["/C".to_string(), "echo prueba 1.0.0".to_string()];
    }

    fn parse_version(&self, stdout: &str) -> Result<Version> {
        let numero = stdout.split_whitespace().last().unwrap_or("0.0.0");
        Version::parse(numero.trim()).map_err(|_| auscan_lib::error::AppError::ParseFailed(stdout.to_string()))
    }

    fn plan(&self, ctx: &PlanContext) -> Result<Vec<Invocation>> {
        if ctx.targets.is_empty() {
            return Ok(vec![]);
        }
        #[cfg(unix)]
        let argv = vec!["-c".to_string(), "echo hola".to_string()];
        #[cfg(windows)]
        let argv = vec!["/C".to_string(), "echo hola".to_string()];
        Ok(vec![Invocation {
            phase: Phase::Discovery,
            argv,
            targets: ctx.targets.to_vec(),
            needs_privilege: false,
            raw_from: RawSource::Stdout,
            progress_from: ProgressSource::None,
            stdin: None,
            timeout: Duration::from_secs(10),
        }])
    }

    fn parse(&self, _raw: &[u8], _ctx: &ParseContext) -> Result<Normalized> {
        let host = HostFact {
            ip: "198.51.100.5".parse().unwrap(),
            hostname: None,
            mac: None,
            vendor: None,
            os_guess: None,
            os_accuracy: None,
            state: Some("up".to_string()),
        };
        Ok(Normalized {
            hosts: vec![host.clone()],
            services: vec![],
            observations: vec![ObservationFact {
                host_ip: Some(host.ip),
                port: None,
                kind: ObservationKind::HostDiscovered,
                subject: host.ip.to_string(),
                statement: "Host activo".to_string(),
                evidence: None,
                evidence_ref: None,
                meta_json: None,
            }],
        })
    }
}

fn estado_de_prueba() -> (tempfile::TempDir, AppState, String) {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::new(dir.path().to_path_buf());
    let referencia = auscan_lib::engagement::create(dir.path(), "CLAVEL").unwrap();
    let conn = auscan_lib::engagement::open(dir.path(), &referencia.id).unwrap();
    auscan_lib::scope::add_entry(&conn, ScopeKind::Allow, "198.51.100.0/24", None).unwrap();
    *state.open.lock().unwrap() = Some(auscan_lib::state::OpenEngagement {
        id: referencia.id.clone(),
        conn,
    });
    (dir, state, referencia.id)
}

#[tokio::test]
async fn ejecutar_fase_persiste_lo_que_parse_devuelve() {
    let (_dir, state, _id) = estado_de_prueba();
    let registro: Vec<Box<dyn ToolAdapter>> = vec![Box::new(AdaptadorDePrueba)];
    let sucesos = Arc::new(std::sync::Mutex::new(Vec::new()));
    let s2 = sucesos.clone();

    ejecutar_fase(
        &state,
        &registro,
        Phase::Discovery,
        "prueba",
        &["198.51.100.5".to_string()],
        false,
        &PhaseOptions::default(),
        CancellationToken::new(),
        move |suceso| s2.lock().unwrap().push(suceso),
    )
    .await
    .unwrap();

    let sucesos = sucesos.lock().unwrap();
    assert!(sucesos
        .iter()
        .any(|s| matches!(s, SucesoRun::RunTerminado { status, .. } if status == "ok")));
    assert!(sucesos.iter().any(|s| matches!(s, SucesoRun::FaseTerminada)));

    let guard = state.open.lock().unwrap();
    let conn = &guard.as_ref().unwrap().conn;
    let n_hosts: i64 = conn.query_row("SELECT COUNT(*) FROM host", [], |r| r.get(0)).unwrap();
    assert_eq!(n_hosts, 1);
    let n_runs: i64 = conn
        .query_row("SELECT COUNT(*) FROM tool_run WHERE status = 'ok'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n_runs, 1);
}

#[tokio::test]
async fn ejecutar_fase_rechaza_un_objetivo_fuera_de_alcance() {
    let (_dir, state, _id) = estado_de_prueba();
    let registro: Vec<Box<dyn ToolAdapter>> = vec![Box::new(AdaptadorDePrueba)];

    let resultado = ejecutar_fase(
        &state,
        &registro,
        Phase::Discovery,
        "prueba",
        &["203.0.113.9".to_string()], // fuera del /24 autorizado
        false,
        &PhaseOptions::default(),
        CancellationToken::new(),
        |_| {},
    )
    .await;

    assert!(resultado.is_err());
    let guard = state.open.lock().unwrap();
    let conn = &guard.as_ref().unwrap().conn;
    let n_runs: i64 = conn.query_row("SELECT COUNT(*) FROM tool_run", [], |r| r.get(0)).unwrap();
    assert_eq!(n_runs, 0, "un objetivo fuera de alcance no debe crear ningún tool_run");
}

#[tokio::test]
async fn ejecutar_fase_cancelada_deja_el_tool_run_marcado_y_no_persiste_hallazgos() {
    let (_dir, state, _id) = estado_de_prueba();
    let registro: Vec<Box<dyn ToolAdapter>> = vec![Box::new(AdaptadorDePrueba)];
    let cancelar = CancellationToken::new();
    cancelar.cancel(); // ya cancelado antes de empezar

    ejecutar_fase(
        &state,
        &registro,
        Phase::Discovery,
        "prueba",
        &["198.51.100.5".to_string()],
        false,
        &PhaseOptions::default(),
        cancelar,
        |_| {},
    )
    .await
    .unwrap();

    let guard = state.open.lock().unwrap();
    let conn = &guard.as_ref().unwrap().conn;
    let (status, n_hosts): (String, i64) = conn
        .query_row(
            "SELECT status, (SELECT COUNT(*) FROM host) FROM tool_run LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "cancelled");
    assert_eq!(n_hosts, 0, "una ejecución cancelada no parsea ni persiste hallazgos");
}
```

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test orchestrator`
Expected: 3 tests en verde. Si algo no compila por un desajuste de tipos entre lo que este test asume y lo que `AppState`/`OpenEngagement` exponen de verdad, revisa `src-tauri/src/state.rs` — sus campos son públicos y el test los usa directamente.

- [ ] **Step 4: `clippy`, `fmt`, commit**

Run: `cargo fmt --manifest-path src-tauri/Cargo.toml` luego `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings` luego `cargo test --manifest-path src-tauri/Cargo.toml`

```bash
git add src-tauri/src/orchestrator.rs src-tauri/src/error.rs src-tauri/src/lib.rs src-tauri/tests/orchestrator.rs
git commit -m "$(cat <<'EOF'
feat: orchestrator.rs -- encadena plan, verja, spawn, parse y persistencia

Arma el PlanContext con el alcance vigente y los objetivos que escribe
el operador (revalidados en cada llamada, no solo la primera),
resuelve el binario una sola vez para lanzar y para la verja,
revalida su versión justo antes de ejecutar, y persiste lo que
parse() produzca. Cada acceso a la conexión SQL es un bloque que
suelta el lock antes de esperar al proceso -- ningún MutexGuard vive
a través de un await.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Comandos Tauri — `run_start` y `run_cancel`

**Files:**
- Modify: `src-tauri/src/state.rs` (`ejecucion_activa`)
- Modify: `src-tauri/src/lib.rs` (comandos + registro)

**Interfaces:**
- Consumes: `orchestrator::ejecutar_fase`/`SucesoRun` (Task 5).
- Produces: comando Tauri `run_start(phase: String, tool_id: String, targets: Vec<String>) -> Result<()>` (asíncrono, dispara y vuelve enseguida; el progreso llega por eventos), comando `run_cancel() -> Result<()>`. Eventos emitidos: `run:log` (`{ origen: "stdout"|"stderr", texto: String }`), `run:done` (`{ seq: i64, status: String }`), `run:fase-terminada` (sin payload).

**Por qué `run_start` no recibe `privileged` del frontend:** ese booleano acabaría entrando directo como `effective_privileged` en `verja()` (Task 1) a través de `orchestrator::ejecutar_fase`. Aceptarlo tal cual desde el comando sería reabrir, con el frontend en vez del adaptador, exactamente el hueco que la Task 1 cerró: cualquiera que pudiera invocar el comando —o un bug en la propia UI— podría declararse privilegiado sin que el proceso lo esté de verdad. El comando calcula el privilegio real él mismo, con `preflight::running_privileged()`, y ese es el único valor que le llega a `ejecutar_fase`.

- [ ] **Step 1: Ampliar `AppState`**

En `src-tauri/src/state.rs`, añade el campo y su tipo:

```rust
use tokio_util::sync::CancellationToken;

pub struct AppState {
    pub root: PathBuf,
    pub open: Mutex<Option<OpenEngagement>>,
    pub ejecucion_activa: Mutex<Option<CancellationToken>>,
}
```

Actualiza `AppState::new`:

```rust
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            open: Mutex::new(None),
            ejecucion_activa: Mutex::new(None),
        }
    }
```

- [ ] **Step 2: Los comandos**

En `src-tauri/src/lib.rs`, añade a los `use`:

```rust
use tauri::Emitter;
use tokio_util::sync::CancellationToken;

use adapters::{Phase, PhaseOptions};
use orchestrator::SucesoRun;
```

Añade los dos comandos (antes de `#[cfg_attr(mobile, ...)] pub fn run()`):

```rust
fn fase_desde_str(s: &str) -> Result<Phase> {
    match s {
        "discovery" => Ok(Phase::Discovery),
        "portsweep" => Ok(Phase::PortSweep),
        "services" => Ok(Phase::Services),
        _ => Err(error::AppError::ToolNotFound(format!("fase desconocida: {s}"))),
    }
}

#[tauri::command]
async fn run_start(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    phase: String,
    tool_id: String,
    targets: Vec<String>,
) -> Result<()> {
    let fase = fase_desde_str(&phase)?;
    let cancelar = CancellationToken::new();
    *state.ejecucion_activa.lock().unwrap_or_else(|e| e.into_inner()) = Some(cancelar.clone());

    // El privilegio real lo calcula el comando, nunca el frontend: si
    // `privileged` llegase como argumento de `invoke`, cualquier llamador
    // -- o un bug de la propia UI -- podría declararse privilegiado sin
    // que el proceso lo esté de verdad, reabriendo con el frontend el
    // hueco que la Task 1 cerró para los adaptadores.
    let privileged = preflight::running_privileged();
    let opciones = PhaseOptions::default();

    // `state: State<'_, AppState>` no sobrevive dentro de la tarea
    // `spawn`eada: su lifetime está atado a esta llamada de comando, que
    // vuelve antes de que la tarea termine. `app: AppHandle` sí es
    // `Clone + Send + 'static` -- se mueve entero dentro del bloque y
    // `app.state::<AppState>()` se vuelve a pedir AHÍ DENTRO, nunca antes.
    tauri::async_runtime::spawn(async move {
        let registro = adapters::registry();
        let state_interna = app.state::<AppState>();
        let app_para_eventos = app.clone();
        let resultado = orchestrator::ejecutar_fase(
            state_interna.inner(),
            &registro,
            fase,
            &tool_id,
            &targets,
            privileged,
            &opciones,
            cancelar,
            move |suceso| {
                let _ = match suceso {
                    SucesoRun::Log { origen, texto } => app_para_eventos.emit(
                        "run:log",
                        serde_json::json!({
                            "origen": match origen {
                                exec::LineaOrigen::Stdout => "stdout",
                                exec::LineaOrigen::Stderr => "stderr",
                            },
                            "texto": texto,
                        }),
                    ),
                    SucesoRun::RunTerminado { seq, status } => app_para_eventos.emit(
                        "run:done",
                        serde_json::json!({ "seq": seq, "status": status }),
                    ),
                    SucesoRun::FaseTerminada => app_para_eventos.emit("run:fase-terminada", ()),
                };
            },
        )
        .await;
        if let Err(e) = resultado {
            let _ = app.emit("run:log", serde_json::json!({ "origen": "stderr", "texto": e.to_string() }));
        }
    });

    Ok(())
}

#[tauri::command]
fn run_cancel(state: State<AppState>) -> Result<()> {
    let guard = state.ejecucion_activa.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(token) = guard.as_ref() {
        token.cancel();
    }
    Ok(())
}
```

Añade `run_start` y `run_cancel` a `tauri::generate_handler![...]`, y `pub mod orchestrator;`/`pub mod runs;`/`pub mod exec;` ya deberían estar todos declarados desde tareas anteriores (verifica el bloque de `pub mod` al principio de `lib.rs`).

**Nota sobre por qué `app.state::<AppState>()` se pide DENTRO del bloque `spawn`, no antes:** el `state: State<'_, AppState>` que recibe el comando tiene un lifetime atado a esta llamada, que vuelve (`Ok(())`) antes de que la tarea asíncrona termine — moverlo dentro del `async move` no compila. `app: AppHandle` sí es `Clone + Send + 'static`, así que se mueve entero, y `app.state::<AppState>()` se llama otra vez ya dentro del bloque, sobre ese `app` que ahora vive tanto como la tarea. Es el mismo `AppState` que gestiona Tauri, no una copia — solo cambia cuándo se pide la referencia.

- [ ] **Step 3: Verificación manual con `cargo check`**

Run: `cargo check --manifest-path src-tauri/Cargo.toml`
Expected: compila sin errores. Presta atención a cualquier aviso sobre `Send`/`'static` en la tarea `spawn`eada — si el compilador se queja de que algo capturado no es `Send`, es la señal exacta que Task 5 pedía vigilar: algo está reteniendo una referencia no compatible con hilos a través de un `.await`.

- [ ] **Step 4: `clippy`, `fmt`, tests, commit**

Run: `cargo fmt --manifest-path src-tauri/Cargo.toml` luego `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings` luego `cargo test --manifest-path src-tauri/Cargo.toml`

```bash
git add src-tauri/src/state.rs src-tauri/src/lib.rs
git commit -m "$(cat <<'EOF'
feat: comandos Tauri run_start y run_cancel

run_start dispara la orquestación en una tarea aparte y vuelve
enseguida; el progreso llega por los eventos run:log, run:done y
run:fase-terminada. run_cancel cancela lo que esté corriendo ahora
mismo a través del CancellationToken guardado en AppState.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Frontend — capa de datos y store de ejecución

**Files:**
- Create: `src/domain/model/run.ts`
- Create: `src/data/runs.ts`
- Create: `src/store/useRunStore.ts`
- Create: `src/store/useRunStore.test.ts`

**Interfaces:**
- Produces: `export type LineaLog = { origen: "stdout" | "stderr"; texto: string }`, `export type RunDone = { seq: number; status: string }`, tienda `useRunStore` con `estado: "inactivo" | "corriendo"`, `lineas: LineaLog[]`, `runsTerminados: RunDone[]`, `error: string | null`, `iniciar(phase, toolId, targets): Promise<void>`, `cancelar(): Promise<void>`. Sin parámetro de privilegio a propósito — ver la nota de la Task 6. Task 8 consume esta tienda directamente.

- [ ] **Step 1: Tipos de dominio**

Crea `src/domain/model/run.ts`:

```typescript
export type LineaLog = {
  origen: "stdout" | "stderr";
  texto: string;
};

export type RunDone = {
  seq: number;
  status: string;
};
```

- [ ] **Step 2: Capa de datos**

Mira primero `src/data/preflight.ts` para seguir exactamente su estilo de envoltura sobre `invoke`. Crea `src/data/runs.ts`:

```typescript
import { invoke } from "@tauri-apps/api/core";

// Sin `privileged` aquí a propósito: el comando calcula el privilegio
// real él mismo (`preflight::running_privileged()`). Aceptarlo como
// argumento reabriría, con el frontend, el hueco que la verja cerró
// para los adaptadores -- cualquiera que invocase el comando podría
// declararse privilegiado sin que el proceso lo esté de verdad.
export const api = {
  start: (phase: string, toolId: string, targets: string[]): Promise<void> =>
    invoke("run_start", { phase, toolId, targets }),
  cancel: (): Promise<void> => invoke("run_cancel"),
};
```

- [ ] **Step 3: Store con los listeners de eventos**

Crea `src/store/useRunStore.ts`:

```typescript
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { create } from "zustand";

import { api } from "../data/runs";
import type { LineaLog, RunDone } from "../domain/model/run";

type EstadoRun = "inactivo" | "corriendo";

type RunStore = {
  estado: EstadoRun;
  lineas: LineaLog[];
  runsTerminados: RunDone[];
  error: string | null;
  iniciar: (phase: string, toolId: string, targets: string[]) => Promise<void>;
  cancelar: () => Promise<void>;
  _suscribir: () => Promise<UnlistenFn[]>;
};

const mensaje = (e: unknown): string =>
  typeof e === "string" ? e : e instanceof Error ? e.message : String(e);

// Buffer acotado: la spec exige que el log de la UI no crezca sin
// límite, aunque raw/ guarde siempre la salida completa.
const MAX_LINEAS = 500;

export const useRunStore = create<RunStore>((set, get) => ({
  estado: "inactivo",
  lineas: [],
  runsTerminados: [],
  error: null,

  iniciar: async (phase, toolId, targets) => {
    set({ estado: "corriendo", lineas: [], runsTerminados: [], error: null });
    await get()._suscribir();
    try {
      await api.start(phase, toolId, targets);
    } catch (e) {
      set({ error: mensaje(e), estado: "inactivo" });
    }
  },

  cancelar: async () => {
    try {
      await api.cancel();
    } catch (e) {
      set({ error: mensaje(e) });
    }
  },

  _suscribir: async () => {
    const unlistenLog = await listen<LineaLog>("run:log", (evento) => {
      set((s) => ({
        lineas: [...s.lineas, evento.payload].slice(-MAX_LINEAS),
      }));
    });
    const unlistenDone = await listen<RunDone>("run:done", (evento) => {
      set((s) => ({ runsTerminados: [...s.runsTerminados, evento.payload] }));
    });
    const unlistenFase = await listen("run:fase-terminada", () => {
      set({ estado: "inactivo" });
    });
    return [unlistenLog, unlistenDone, unlistenFase];
  },
}));
```

- [ ] **Step 4: Test de la tienda**

Mira primero cómo `src/store/usePreflightStore.ts` (si tiene test) o `useAppStore`'s consumers mockean `@tauri-apps/api/core` y `@tauri-apps/api/event` en este proyecto, y sigue exactamente ese patrón de mock. Crea `src/store/useRunStore.test.ts`:

```typescript
import { beforeEach, describe, expect, it, vi } from "vitest";

const listeners: Record<string, (evento: { payload: unknown }) => void> = {};

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn((nombre: string, cb: (evento: { payload: unknown }) => void) => {
    listeners[nombre] = cb;
    return Promise.resolve(() => {
      delete listeners[nombre];
    });
  }),
}));

import { invoke } from "@tauri-apps/api/core";
import { useRunStore } from "./useRunStore";

describe("useRunStore", () => {
  beforeEach(() => {
    useRunStore.setState({ estado: "inactivo", lineas: [], runsTerminados: [], error: null });
    vi.mocked(invoke).mockReset();
  });

  it("pasa a corriendo y limpia el estado anterior al iniciar", async () => {
    vi.mocked(invoke).mockResolvedValue(undefined);
    await useRunStore.getState().iniciar("discovery", "nmap", ["198.51.100.5"]);
    expect(useRunStore.getState().estado).toBe("corriendo");
    expect(useRunStore.getState().lineas).toEqual([]);
  });

  it("acumula líneas de log según llegan por el evento run:log", async () => {
    vi.mocked(invoke).mockResolvedValue(undefined);
    await useRunStore.getState().iniciar("discovery", "nmap", ["198.51.100.5"]);
    listeners["run:log"]({ payload: { origen: "stdout", texto: "hola" } });
    expect(useRunStore.getState().lineas).toEqual([{ origen: "stdout", texto: "hola" }]);
  });

  it("vuelve a inactivo cuando llega run:fase-terminada", async () => {
    vi.mocked(invoke).mockResolvedValue(undefined);
    await useRunStore.getState().iniciar("discovery", "nmap", ["198.51.100.5"]);
    listeners["run:fase-terminada"]({ payload: undefined });
    expect(useRunStore.getState().estado).toBe("inactivo");
  });

  it("guarda el error y vuelve a inactivo si start falla", async () => {
    vi.mocked(invoke).mockRejectedValue("fuera de alcance");
    await useRunStore.getState().iniciar("discovery", "nmap", ["203.0.113.9"]);
    expect(useRunStore.getState().error).toBe("fuera de alcance");
    expect(useRunStore.getState().estado).toBe("inactivo");
  });
});
```

Run: `npm test -- useRunStore`
Expected: 4 tests en verde. Si el mock de `@tauri-apps/api/event` no coincide con cómo este proyecto ya mockea `listen` en otro sitio (por ejemplo si `Preflight.test.tsx` ya tiene un patrón establecido), ajusta este test a ese patrón existente en vez de inventar uno nuevo — anota la diferencia si la hay.

- [ ] **Step 5: `tsc`, `eslint`, commit**

Run: `npm run check` (o los pasos de lint/typecheck/test que ese script agrupe)

```bash
git add src/domain/model/run.ts src/data/runs.ts src/store/useRunStore.ts src/store/useRunStore.test.ts
git commit -m "$(cat <<'EOF'
feat: capa de datos y store de ejecución en el frontend

useRunStore se suscribe a run:log/run:done/run:fase-terminada al
iniciar una ejecución, con un buffer de log acotado a 500 líneas -- la
salida completa vive siempre en raw/, esto es solo lo que ve el
operador en pantalla mientras corre.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Frontend — pantalla de ejecución en vivo

**Files:**
- Create: `src/pages/Run.tsx`
- Create: `src/pages/Run.test.tsx`
- Modify: `src/App.tsx`
- Modify: `src/i18n/locales/es.json`, `src/i18n/locales/en.json`

**Interfaces:**
- Consumes: `useRunStore` (Task 7).

- [ ] **Step 1: Claves de i18n**

Mira primero la forma exacta de una sección existente (por ejemplo `"preflight"` en `src/i18n/locales/es.json`) para mantener el mismo estilo de nombres de clave. Añade a `src/i18n/locales/es.json` (nivel superior, junto a `"scope"`):

```json
  "run": {
    "titulo": "Ejecución",
    "objetivos": "Objetivos (uno por línea)",
    "fase": "Fase",
    "confirmarTitulo": "Se va a ejecutar",
    "confirmarBoton": "Ejecutar",
    "cancelarBoton": "Cancelar edición",
    "lanzarBoton": "Lanzar",
    "cancelarEjecucionBoton": "Cancelar ejecución",
    "corriendo": "Corriendo…",
    "sinLineas": "Sin salida todavía.",
    "recuento": "{{n}} líneas de log"
  }
```

Y a `src/i18n/locales/en.json`, la traducción equivalente:

```json
  "run": {
    "titulo": "Run",
    "objetivos": "Targets (one per line)",
    "fase": "Phase",
    "confirmarTitulo": "About to run",
    "confirmarBoton": "Run",
    "cancelarBoton": "Cancel editing",
    "lanzarBoton": "Launch",
    "cancelarEjecucionBoton": "Cancel execution",
    "corriendo": "Running…",
    "sinLineas": "No output yet.",
    "recuento": "{{n}} log lines"
  }
```

También añade a `"nav"` en ambos ficheros: `"run": "Ejecución"` (es) / `"run": "Run"` (en).

- [ ] **Step 2: La pantalla**

Crea `src/pages/Run.tsx`:

```tsx
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useRunStore } from "../store/useRunStore";

const FASES = ["discovery", "portsweep", "services"] as const;

export function Run() {
  const { t } = useTranslation();
  const { estado, lineas, runsTerminados, error, iniciar, cancelar } = useRunStore();
  const [fase, setFase] = useState<(typeof FASES)[number]>("discovery");
  const [objetivosTexto, setObjetivosTexto] = useState("");
  const [confirmando, setConfirmando] = useState(false);

  const objetivos = objetivosTexto
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  const pedirConfirmacion = () => setConfirmando(true);

  const lanzar = async () => {
    setConfirmando(false);
    await iniciar(fase, "nmap", objetivos);
  };

  return (
    <section>
      <h1>{t("run.titulo")}</h1>

      <label>
        {t("run.fase")}
        <select value={fase} onChange={(e) => setFase(e.target.value as (typeof FASES)[number])} disabled={estado === "corriendo"}>
          {FASES.map((f) => (
            <option key={f} value={f}>
              {f}
            </option>
          ))}
        </select>
      </label>

      <label>
        {t("run.objetivos")}
        <textarea
          value={objetivosTexto}
          onChange={(e) => setObjetivosTexto(e.target.value)}
          disabled={estado === "corriendo"}
        />
      </label>

      {!confirmando && (
        <button type="button" onClick={pedirConfirmacion} disabled={estado === "corriendo" || objetivos.length === 0}>
          {t("run.lanzarBoton")}
        </button>
      )}

      {confirmando && (
        <div role="dialog" aria-label={t("run.confirmarTitulo")}>
          <p>{t("run.confirmarTitulo")}</p>
          <p>
            nmap {fase} {objetivos.join(" ")}
          </p>
          <button type="button" onClick={lanzar}>
            {t("run.confirmarBoton")}
          </button>
          <button type="button" onClick={() => setConfirmando(false)}>
            {t("run.cancelarBoton")}
          </button>
        </div>
      )}

      {estado === "corriendo" && (
        <>
          <p>{t("run.corriendo")}</p>
          <button type="button" onClick={() => void cancelar()}>
            {t("run.cancelarEjecucionBoton")}
          </button>
        </>
      )}

      {error && <p role="alert">{error}</p>}

      <p>{t("run.recuento", { n: lineas.length })}</p>
      <pre data-testid="log">
        {lineas.length === 0
          ? t("run.sinLineas")
          : lineas.map((l, i) => `[${l.origen}] ${l.texto}`).join("\n")}
      </pre>

      {runsTerminados.length > 0 && (
        <ul>
          {runsTerminados.map((r) => (
            <li key={r.seq}>
              #{r.seq}: {r.status}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
```

- [ ] **Step 3: Test de la pantalla**

Mira primero `src/pages/Preflight.test.tsx` para el patrón de mock de `useRunStore`/store hooks ya establecido en este proyecto. Crea `src/pages/Run.test.tsx`:

```tsx
import { render, screen, fireEvent } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";

import { useRunStore } from "../store/useRunStore";
import { Run } from "./Run";

vi.mock("../store/useRunStore");

const storeBase = {
  estado: "inactivo" as const,
  lineas: [],
  runsTerminados: [],
  error: null,
  iniciar: vi.fn(),
  cancelar: vi.fn(),
};

describe("Run", () => {
  beforeEach(() => {
    vi.mocked(useRunStore).mockReturnValue({ ...storeBase });
  });

  it("no lanza sin escribir objetivos", () => {
    render(<Run />);
    expect(screen.getByRole("button", { name: /lanzar/i })).toBeDisabled();
  });

  it("pide confirmación mostrando el argv antes de lanzar", () => {
    render(<Run />);
    fireEvent.change(screen.getByLabelText(/objetivos/i), {
      target: { value: "198.51.100.5" },
    });
    fireEvent.click(screen.getByRole("button", { name: /lanzar/i }));
    expect(screen.getByRole("dialog")).toHaveTextContent("198.51.100.5");
    expect(storeBase.iniciar).not.toHaveBeenCalled();
  });

  it("llama a iniciar solo tras confirmar", () => {
    render(<Run />);
    fireEvent.change(screen.getByLabelText(/objetivos/i), {
      target: { value: "198.51.100.5" },
    });
    fireEvent.click(screen.getByRole("button", { name: /lanzar/i }));
    fireEvent.click(screen.getByRole("button", { name: /^ejecutar$/i }));
    expect(storeBase.iniciar).toHaveBeenCalledWith("discovery", "nmap", ["198.51.100.5"]);
  });

  it("muestra las líneas de log acumuladas", () => {
    vi.mocked(useRunStore).mockReturnValue({
      ...storeBase,
      estado: "corriendo",
      lineas: [{ origen: "stdout", texto: "hola" }],
    });
    render(<Run />);
    expect(screen.getByTestId("log")).toHaveTextContent("hola");
  });

  it("el botón de cancelar ejecución llama a cancelar", () => {
    vi.mocked(useRunStore).mockReturnValue({ ...storeBase, estado: "corriendo" });
    render(<Run />);
    fireEvent.click(screen.getByRole("button", { name: /cancelar ejecución/i }));
    expect(storeBase.cancelar).toHaveBeenCalled();
  });
});
```

Run: `npm test -- Run.test`
Expected: 5 tests en verde. Si `getByLabelText`/`getByRole` no encuentran el control esperado por cómo React Testing Library asocia `<label>` con `<select>`/`<textarea>` en este proyecto (depende de si ya usan `htmlFor` explícito en otras pantallas), ajusta las queries del test al patrón real de `Scope.tsx`/`Preflight.tsx` en vez de forzarlo.

- [ ] **Step 4: Añadir la pantalla a la navegación**

En `src/App.tsx`, añade el import y la pestaña:

```tsx
import { Run } from "./pages/Run";

type Pantalla = "preflight" | "engagements" | "scope" | "run";
```

Y en el JSX, junto a los otros botones de `<nav>`:

```tsx
        <button type="button" onClick={() => setPantalla("run")}>
          {t("nav.run")}
        </button>
```

Y junto a los otros renderizados condicionales:

```tsx
      {pantalla === "run" && <Run />}
```

- [ ] **Step 5: `tsc`, `eslint`, `npm run check`, commit**

Run: `npm run check`
Expected: todo limpio, incluida la paridad de claves i18n (`check:i18n`) entre `es.json` y `en.json`.

```bash
git add src/pages/Run.tsx src/pages/Run.test.tsx src/App.tsx src/i18n/locales/es.json src/i18n/locales/en.json
git commit -m "$(cat <<'EOF'
feat: pantalla de ejecución en vivo

Elegir fase, escribir objetivos, confirmar viendo el argv exacto que
se va a lanzar, ver el log en vivo mientras corre, y poder cancelar.
Sin tabla de resultados navegable -- eso llega cuando la fase de
exportadores ya necesite leer los mismos datos.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
EOF
)"
```
