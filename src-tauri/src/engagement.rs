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

/// Devuelve la forma canónica del identificador.
///
/// `Uuid::parse_str` acepta cuatro codificaciones del mismo UUID —simple,
/// con guiones, entre llaves y urn— y todas insensibles a mayúsculas.
/// `paths::engagement_dir` las normaliza todas al mismo directorio, así que
/// cualquier comparación contra la cadena cruda del frontend puede fallar
/// mientras la ruta acierta: se borraría el directorio sin cerrar la
/// conexión ni escribir la lápida. Todo lo que cruce la frontera pasa por
/// aquí primero.
pub fn canonical_id(id: &str) -> Result<String> {
    Ok(Uuid::parse_str(id)
        .map_err(|_| AppError::InvalidEngagementId(id.to_string()))?
        .to_string())
}

pub fn create(root: &Path, codename: &str) -> Result<EngagementRef> {
    let codename = codename.trim();
    if codename.is_empty() {
        return Err(AppError::InvalidCodename);
    }

    let id = Uuid::new_v4().to_string();
    let created_at = db::now_iso();

    // Cuatro pasos pueden fallar antes de que el engagement exista de
    // verdad en ambos sitios: crear el directorio, abrir su base,
    // migrarla e insertar las dos filas. Cualquier fallo a partir de que
    // el directorio ya esté creado deja un huérfano si no se limpia
    // explícitamente, así que los cuatro comparten un único punto de
    // limpieza en vez de que solo cubriera el último paso.
    let resultado = (|| -> Result<()> {
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
        Ok(())
    })();

    if let Err(e) = resultado {
        let ruta = paths::engagement_dir(root, &id)?;
        if let Err(fallo_limpieza) = std::fs::remove_dir_all(&ruta) {
            // No se descarta en silencio: si la limpieza falla (en
            // Windows, por ejemplo, con un fichero todavía abierto), el
            // huérfano queda documentado en el mensaje de error en vez de
            // desaparecer sin que nadie se entere.
            eprintln!(
                "aviso: no se pudo limpiar {} tras un fallo en create: {fallo_limpieza}",
                ruta.display()
            );
        }
        return Err(e);
    }

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
    let id = canonical_id(id)?;
    list(root)?
        .into_iter()
        .find(|e| e.id == id)
        .ok_or_else(|| AppError::EngagementNotFound(id))
}

/// Abre la base de un engagement existente. No la crea: si el fichero no
/// está, es que el engagement no existe o ya se purgó.
pub fn open(root: &Path, id: &str) -> Result<Connection> {
    // Se canonicaliza aquí, no solo en la frontera de comandos: esta
    // función es pub y auscan_lib es una librería — cualquier llamador
    // futuro (la fase de ejecución, un test, un binario aparte) tiene
    // que recibir la misma garantía sin tener que saber por qué.
    let id = canonical_id(id)?;
    let ruta = paths::engagement_db_path(root, &id)?;
    if !ruta.is_file() {
        return Err(AppError::EngagementNotFound(id.to_string()));
    }
    let mut conn = db::open(&ruta)?;
    db::migrate(&mut conn, db::ENGAGEMENT_MIGRATIONS)?;
    Ok(conn)
}

/// Borra todo rastro local del engagement y deja una lápida en el índice.
///
/// La carpeta de exportación NO se toca: es el entregable y vive fuera
/// del control de la app. La UI debe decirlo explícitamente.
pub fn purge(root: &Path, id: &str) -> Result<EngagementRef> {
    // Canonicalizar aquí, no solo en la frontera, es lo que de verdad
    // cierra el bug: purge('{MAYUSCULAS}') tiene que dejar la misma
    // lápida que purge('minusculas'), lo llame quien lo llame.
    let id = canonical_id(id)?;
    let ruta = paths::engagement_dir(root, &id)?;

    if ruta.exists() {
        std::fs::remove_dir_all(&ruta)?;
    }

    // Verificar, no confiar.
    if ruta.exists() {
        return Err(AppError::PurgeIncomplete(ruta.display().to_string()));
    }

    let purged_at = db::now_iso();
    let index = db::open_index(root)?;
    let filas = index.execute(
        "UPDATE engagement_ref
            SET state = 'purged', purged_at = COALESCE(purged_at, ?2)
          WHERE id = ?1",
        rusqlite::params![id, purged_at],
    )?;
    if filas == 0 {
        return Err(AppError::EngagementNotFound(id));
    }

    get(root, &id)
}
