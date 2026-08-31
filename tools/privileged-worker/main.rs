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
