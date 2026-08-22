use std::path::Path;

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db;
use crate::error::{AppError, Result};
use crate::paths;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngagementRef {
    pub id: String,
    pub codename: String,
    pub created_at: String,
    pub state: String,
    pub purged_at: Option<String>,
}

pub fn create(root: &Path, codename: &str) -> Result<EngagementRef> {
    let codename = codename.trim();
    if codename.is_empty() {
        return Err(AppError::InvalidEngagementId(
            "el nombre en clave no puede estar vacío".to_string(),
        ));
    }

    let id = Uuid::new_v4().to_string();
    let created_at = db::now_iso();

    // Primero el directorio y su base: si algo falla, el índice no
    // acaba apuntando a un engagement que no existe en disco.
    std::fs::create_dir_all(paths::raw_dir(root, &id)?)?;
    let mut conn = db::open(&paths::engagement_db_path(root, &id)?)?;
    db::migrate(&mut conn, db::ENGAGEMENT_MIGRATIONS)?;
    conn.execute(
        "INSERT INTO engagement (id, codename, created_at, state)
         VALUES (?1, ?2, ?3, 'draft')",
        rusqlite::params![id, codename, created_at],
    )?;
    drop(conn);

    let index = db::open_index(root)?;
    index.execute(
        "INSERT INTO engagement_ref (id, codename, created_at, state)
         VALUES (?1, ?2, ?3, 'draft')",
        rusqlite::params![id, codename, created_at],
    )?;

    Ok(EngagementRef {
        id,
        codename: codename.to_string(),
        created_at,
        state: "draft".to_string(),
        purged_at: None,
    })
}

pub fn list(root: &Path) -> Result<Vec<EngagementRef>> {
    let index = db::open_index(root)?;
    let mut st = index.prepare(
        "SELECT id, codename, created_at, state, purged_at
         FROM engagement_ref ORDER BY created_at DESC, id DESC",
    )?;
    let filas = st.query_map([], |r| {
        Ok(EngagementRef {
            id: r.get(0)?,
            codename: r.get(1)?,
            created_at: r.get(2)?,
            state: r.get(3)?,
            purged_at: r.get(4)?,
        })
    })?;
    Ok(filas.collect::<std::result::Result<Vec<_>, _>>()?)
}

pub fn get(root: &Path, id: &str) -> Result<EngagementRef> {
    list(root)?
        .into_iter()
        .find(|e| e.id == id)
        .ok_or_else(|| AppError::EngagementNotFound(id.to_string()))
}

/// Abre la base de un engagement existente. No la crea: si el fichero no
/// está, es que el engagement no existe o ya se purgó.
pub fn open(root: &Path, id: &str) -> Result<Connection> {
    let ruta = paths::engagement_db_path(root, id)?;
    if !ruta.is_file() {
        return Err(AppError::EngagementNotFound(id.to_string()));
    }
    let mut conn = db::open(&ruta)?;
    db::migrate(&mut conn, db::ENGAGEMENT_MIGRATIONS)?;
    Ok(conn)
}
