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
            Some(orden) => match procesar_orden(&dir_control, seq, &orden).await? {
                FinDeOrden::Siguiente => seq += 1,
                // Apareció el centinela de detener con la orden en
                // vuelo: no se vuelve a esperar nada, la app está
                // cerrando este trabajador.
                FinDeOrden::Detener => return Ok(()),
            },
            None => {
                tokio::time::sleep(INTERVALO_SONDEO).await;
            }
        }
    }
}

/// Cómo terminó una orden, visto desde el bucle.
enum FinDeOrden {
    /// La orden terminó -- bien, mal, o matada por el centinela de
    /// cancelar --: toca esperar la siguiente.
    Siguiente,
    /// Apareció el centinela de DETENER con el hijo todavía corriendo.
    /// El hijo ya está muerto y el bucle entero se acaba: no hay
    /// "siguiente orden" que esperar.
    Detener,
}

async fn procesar_orden(dir_control: &Path, seq: i64, orden: &Orden) -> Result<FinDeOrden> {
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

    let mut fin = FinDeOrden::Siguiente;
    let exit_code = loop {
        if let Some(estado) = hijo.try_wait().map_err(AppError::Io)? {
            break estado.code();
        }
        if privilege::hay_cancelar(dir_control) {
            matar(&mut hijo, pid).await;
            break None;
        }
        // El de detener también, y en el MISMO sondeo. Antes solo se
        // miraba entre orden y orden: si el cuerpo de la fase se iba por
        // un camino que no marca el de cancelar, `detener_trabajador` se
        // quedaba esperando a que terminase un escaneo entero (que
        // pueden ser minutos u horas) antes de que este bucle llegara
        // siquiera a mirar su centinela.
        if privilege::hay_detener(dir_control) {
            matar(&mut hijo, pid).await;
            fin = FinDeOrden::Detener;
            break None;
        }
        tokio::time::sleep(INTERVALO_SONDEO).await;
    };

    // El estado se escribe igual en los tres finales, detener incluido:
    // quien esté esperando esta invocación al otro lado tiene derecho a
    // enterarse de que ya no va a llegar nada más.
    privilege::escribir_estado(dir_control, seq, &Estado { exit_code })?;
    Ok(fin)
}
