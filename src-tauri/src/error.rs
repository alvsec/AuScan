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

    #[error("objetivo sin validar en el comando: {0}")]
    UnvalidatedTarget(String),

    #[error("bandera no permitida: {0}")]
    FlagNotAllowed(String),

    #[error("la bandera {0} exige la ruta privilegiada")]
    PrivilegeRequired(String),

    #[error(
        "el binario a ejecutar ({actual}) no coincide con el resuelto en preflight ({expected})"
    )]
    BinaryMismatch { expected: String, actual: String },

    #[error("dirección o rango no válido: {0}")]
    InvalidAddress(String),

    #[error("no se pudo resolver el nombre {0}")]
    UnresolvableHost(String),

    #[error("no hay ningún engagement abierto")]
    NoEngagementOpen,

    #[error("el engagement cambió durante la ejecución (se esperaba {0})")]
    EngagementChanged(String),

    #[error("el engagement {0} no existe")]
    EngagementNotFound(String),

    #[error("la purga dejó restos en {0}")]
    PurgeIncomplete(String),

    #[error("ya hay una ejecución en marcha")]
    RunAlreadyActive,

    #[error("hay una ejecución en marcha: cancélala antes de abrir o purgar un engagement")]
    EngagementBlockedByRun,

    #[error("no se encontró la herramienta {0} en el registro")]
    ToolNotFound(String),

    #[error("la instalación de {tool} falló (código {code:?}): {stderr}")]
    InstallFailed {
        tool: String,
        code: Option<i32>,
        stderr: String,
    },

    #[error("{tool} está en {actual}, pero esta fase exige al menos {minimo}")]
    ToolVersionInsuficiente {
        tool: String,
        actual: String,
        minimo: String,
    },

    #[error("no se pudo interpretar la salida de la herramienta: {0}")]
    ParseFailed(String),

    #[error("los datos parseados son inconsistentes: {0}")]
    InconsistentParse(String),

    #[error("protocolo de elevación corrupto: {0}")]
    ProtocoloElevacion(String),

    #[error("elevación fallida: {0}")]
    ElevationFailed(String),

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
