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
