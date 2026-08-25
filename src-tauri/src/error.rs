use serde::{Serialize, Serializer};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("identificador de engagement inválido: {0:?}")]
    InvalidEngagementId(String),

    #[error("el nombre en clave no puede estar vacío")]
    InvalidCodename,

    #[error("objetivo fuera de alcance: {0}")]
    OutOfScope(String),

    #[error("alcance vacío: no hay ningún rango autorizado")]
    EmptyScope,

    #[error("entrada de alcance ambigua: {0} — usa la dirección de red o /32")]
    AmbiguousCidr(String),

    #[error("alcance demasiado amplio: {0} autorizaría todo el espacio de direcciones")]
    OverbroadScope(String),

    #[error("la entrada de alcance {0} no existe")]
    ScopeEntryNotFound(i64),

    #[error("dirección o rango no válido: {0}")]
    InvalidAddress(String),

    #[error("no se pudo resolver el nombre {0}")]
    UnresolvableHost(String),

    #[error("no hay ningún engagement abierto")]
    NoEngagementOpen,

    #[error("el engagement {0} no existe")]
    EngagementNotFound(String),

    #[error("la purga dejó restos en {0}")]
    PurgeIncomplete(String),

    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, AppError>;

// Los comandos de Tauri devuelven el error al frontend como cadena.
impl Serialize for AppError {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}
