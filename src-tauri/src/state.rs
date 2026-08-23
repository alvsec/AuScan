use std::path::PathBuf;
use std::sync::Mutex;

use rusqlite::Connection;

use crate::error::{AppError, Result};

pub struct OpenEngagement {
    pub id: String,
    pub conn: Connection,
}

pub struct AppState {
    pub root: PathBuf,
    pub open: Mutex<Option<OpenEngagement>>,
}

impl AppState {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            open: Mutex::new(None),
        }
    }

    /// Ejecuta `f` sobre la conexión del engagement abierto.
    pub fn with_open<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let guard = self.open.lock().expect("mutex envenenado");
        let abierto = guard.as_ref().ok_or(AppError::NoEngagementOpen)?;
        f(&abierto.conn)
    }

    /// Cierra el engagement abierto, si lo hay.
    ///
    /// Imprescindible antes de purgar: en Windows no se puede borrar un
    /// fichero con un descriptor abierto.
    pub fn close(&self) {
        let mut guard = self.open.lock().expect("mutex envenenado");
        *guard = None;
    }
}
