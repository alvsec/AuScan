use std::path::PathBuf;
use std::sync::Mutex;

use rusqlite::Connection;
use tokio_util::sync::CancellationToken;

use crate::error::{AppError, Result};

pub struct OpenEngagement {
    pub id: String,
    pub conn: Connection,
}

pub struct AppState {
    pub root: PathBuf,
    pub open: Mutex<Option<OpenEngagement>>,
    pub ejecucion_activa: Mutex<Option<CancellationToken>>,
}

impl AppState {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            open: Mutex::new(None),
            ejecucion_activa: Mutex::new(None),
        }
    }

    /// Ejecuta `f` sobre la conexión del engagement abierto.
    ///
    /// Un mutex envenenado se recupera en vez de propagar el pánico: si no,
    /// un único fallo dejaría todos los comandos de alcance inservibles
    /// hasta reiniciar, con un engagement abierto y datos de cliente
    /// cargados. El dato que protege sigue siendo consistente porque nada
    /// dentro del lock lo deja a medias.
    pub fn with_open<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let guard = self.open.lock().unwrap_or_else(|e| e.into_inner());
        let abierto = guard.as_ref().ok_or(AppError::NoEngagementOpen)?;
        f(&abierto.conn)
    }
}
