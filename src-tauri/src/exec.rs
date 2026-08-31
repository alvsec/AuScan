//! La verja: lo que se comprueba antes de lanzar cualquier proceso.
//!
//! Esta fase implementa las comprobaciones como funciones puras. El
//! `spawn` real —y por tanto el único sitio donde se llaman en
//! producción— llega en la Fase 5. Separar la validación de la
//! ejecución es lo que las hace testeables sin lanzar ningún proceso.

use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

use crate::adapters::{Invocation, ToolDescriptor};
use crate::error::{AppError, Result};
use crate::scope::ScopedTarget;

/// Lo que `matar` espera entre el `SIGTERM` amable y el `SIGKILL` que no
/// admite discusión.
///
/// Es una constante con nombre, y no un `3` suelto dentro de `matar`,
/// porque el trabajador elevado reutiliza esta misma función para matar
/// a SU hijo: quien espera al otro lado (`privilege::ejecutar_privilegiado`)
/// necesita construir su propio plazo A PARTIR de este, no adivinarlo.
pub(crate) const PLAZO_GRACIA_MATAR: Duration = Duration::from_secs(3);

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
///
/// `pub(crate)`: la Fase 6 reutiliza este divisor de líneas para hacer
/// tail de la salida de un proceso elevado, que llega por fichero en
/// vez de por una tubería en memoria -- mismo divisor, otra fuente.
pub(crate) struct AcumuladorLineas {
    buffer: Vec<u8>,
}

impl AcumuladorLineas {
    pub(crate) fn nuevo() -> Self {
        Self { buffer: Vec::new() }
    }

    pub(crate) fn alimentar(&mut self, bytes: &[u8]) -> Vec<String> {
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
        let trimmed = token.trim();
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            if !targets.iter().any(|t| t.ip() == ip) {
                return Err(AppError::UnvalidatedTarget(token.clone()));
            }
            continue;
        }
        if let Some((host, resto)) = trimmed.split_once('/') {
            if host.parse::<IpAddr>().is_ok() && resto.chars().all(|c| c.is_ascii_digit()) {
                return Err(AppError::UnvalidatedTarget(token.clone()));
            }
        }
    }
    Ok(())
}

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
/// **Cerrado en la Fase 5:** `invocation_privileged` lo pone quien
/// llama. Antes de esta fase, la única llamadora (`verja()`) lo sacaba
/// de `Invocation.needs_privilege` — el propio adaptador
/// autocertificándose. Ahora `verja()` recibe el privilegio efectivo
/// del proceso como parámetro explícito y es eso lo que llega aquí.
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
    // Antes del `spawn`, no después. El `select!` de más abajo solo mira
    // el token una vez el proceso ya está corriendo: con una fase de
    // varias invocaciones (Services planifica una por host), cancelar a
    // mitad lanzaba igualmente el escáner de cada host restante para
    // matarlo en el mismo suspiro. La forma del resultado es la misma
    // que produce la rama `cancelar.cancelled()` del `select!` -- sin
    // salida capturada, sin código de salida, `cancelado: true` --
    // porque para quien llama es el mismo hecho: se canceló.
    if cancelar.is_cancelled() {
        return Ok(ResultadoEjecucion {
            raw: Vec::new(),
            stderr: Vec::new(),
            exit_code: None,
            cancelado: true,
        });
    }

    let mut comando = Command::new(binary_path);
    comando
        .args(argv)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::null());
    // `process_group` es un método inherente de `tokio::process::Command`
    // en esta versión de tokio (no requiere `std::os::unix::process::
    // CommandExt` en scope; importarlo aquí sobra y `clippy -D warnings`
    // lo marca como `unused_imports`).
    #[cfg(unix)]
    comando.process_group(0);

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
pub(crate) async fn matar(hijo: &mut tokio::process::Child, pid: Option<u32>) {
    let Some(pid) = pid else { return };
    // SAFETY: enviar una señal a un grupo de procesos que esta misma
    // función creó al lanzar el hijo (`process_group(0)`) no tiene más
    // precondición que un pid válido, y `pid` viene de `Child::id()`
    // sobre un hijo que sigue vivo en este punto.
    unsafe {
        libc::killpg(pid as i32, libc::SIGTERM);
    }
    if tokio::time::timeout(PLAZO_GRACIA_MATAR, hijo.wait())
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
pub(crate) async fn matar(hijo: &mut tokio::process::Child, _pid: Option<u32>) {
    let _ = hijo.kill().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    // `AcumuladorLineas` es privado — no se puede ejercitar desde
    // `tests/exec_spawn.rs`. Y un proceso real casi nunca fuerza que un
    // `read()` corte una línea a la mitad (la salida de los scripts de
    // prueba es minúscula y llega en un solo trozo), así que ese
    // camino queda sin probar si no se llama a `alimentar` a mano. Estas
    // pruebas comprueban justo eso: que el `buffer` interno persiste
    // entre llamadas y reconstruye la línea igual si llega entera de una
    // vez o repartida entre varias llamadas.
    #[test]
    fn una_linea_partida_entre_dos_llamadas_se_reconstruye() {
        let mut acumulador = AcumuladorLineas::nuevo();
        // Ningún '\n' todavía: no debe salir ninguna línea, pero los
        // bytes no se pueden perder.
        assert_eq!(acumulador.alimentar(b"linea-par"), Vec::<String>::new());
        assert_eq!(acumulador.alimentar(b"cial\n"), vec!["linea-parcial"]);
    }

    #[test]
    fn una_sola_llamada_puede_completar_varias_lineas_y_dejar_un_resto_parcial() {
        let mut acumulador = AcumuladorLineas::nuevo();
        let lineas = acumulador.alimentar(b"uno\ndos\ntres-parcial");
        assert_eq!(lineas, vec!["uno", "dos"]);
        // "tres-parcial" se quedó en el buffer, sin '\n' todavía.
        assert_eq!(acumulador.alimentar(b"\n"), vec!["tres-parcial"]);
    }

    #[test]
    fn un_crlf_partido_justo_entre_el_cr_y_el_lf_se_recorta_igual() {
        let mut acumulador = AcumuladorLineas::nuevo();
        // El '\r' llega en un trozo y el '\n' en el siguiente: si el
        // acumulador tokenizase antes de tener ambos bytes, el '\r'
        // quedaría pegado a la línea.
        assert_eq!(acumulador.alimentar(b"hola\r"), Vec::<String>::new());
        assert_eq!(acumulador.alimentar(b"\n"), vec!["hola"]);
    }
}
