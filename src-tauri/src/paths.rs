use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::error::{AppError, Result};

pub fn index_db_path(root: &Path) -> PathBuf {
    root.join("index.db")
}

pub fn engagements_dir(root: &Path) -> PathBuf {
    root.join("engagements")
}

/// Reparsea el identificador como UUID y lo vuelve a serializar antes de
/// usarlo como nombre de directorio. Nada que no sea un UUID sobrevive,
/// así que ninguna cadena del frontend puede escapar del app-data dir.
pub fn engagement_dir(root: &Path, id: &str) -> Result<PathBuf> {
    let uuid = Uuid::parse_str(id).map_err(|_| AppError::InvalidEngagementId(id.to_string()))?;
    Ok(engagements_dir(root).join(uuid.to_string()))
}

pub fn engagement_db_path(root: &Path, id: &str) -> Result<PathBuf> {
    Ok(engagement_dir(root, id)?.join("engagement.db"))
}

pub fn raw_dir(root: &Path, id: &str) -> Result<PathBuf> {
    Ok(engagement_dir(root, id)?.join("raw"))
}
