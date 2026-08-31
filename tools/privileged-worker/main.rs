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
    let [_, dir_control, pid_padre] = args.as_slice() else {
        eprintln!("uso: privileged-worker <directorio-de-control> <pid-de-la-app>");
        return ExitCode::FAILURE;
    };
    // El pid del proceso que lo lanzó, para vigilar que siga vivo. Se
    // pasa explícitamente porque `getppid()` no sirve: `do shell script
    // ... with administrator privileges` no cuelga este proceso de la
    // app, sino del trampolín de autorización del sistema.
    let Ok(pid_padre) = pid_padre.parse::<u32>() else {
        eprintln!("el pid de la app no es un número: {pid_padre:?}");
        return ExitCode::FAILURE;
    };

    match ejecutar_bucle(PathBuf::from(dir_control), pid_padre).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("el trabajador terminó con error: {e}");
            ExitCode::FAILURE
        }
    }
}
