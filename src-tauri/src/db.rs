use std::path::Path;

use rusqlite::Connection;

use crate::error::Result;
use crate::paths;

pub const INDEX_MIGRATIONS: &[(&str, &str)] = &[(
    "0001_index",
    include_str!("../migrations/index/0001_index.sql"),
)];

pub const ENGAGEMENT_MIGRATIONS: &[(&str, &str)] = &[];

/// Abre una conexión con los tres pragmas obligatorios.
///
/// `temp_store = MEMORY` no es una optimización: sin él SQLite derrama
/// ficheros temporales en /var/folders, fuera del directorio del
/// engagement y por tanto fuera del alcance de la purga.
pub fn open(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path)?;
    // journal_mode devuelve una fila, así que no sirve pragma_update.
    conn.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    Ok(conn)
}

pub fn open_index(root: &Path) -> Result<Connection> {
    let mut conn = open(&paths::index_db_path(root))?;
    migrate(&mut conn, INDEX_MIGRATIONS)?;
    Ok(conn)
}

/// Migraciones versionadas y append-only. Nunca editar una ya lanzada:
/// añadir la siguiente.
///
/// Cada migración se aplica y se registra dentro de una única transacción:
/// si el proceso muere a mitad, o una sentencia posterior del mismo lote
/// falla, no debe quedar ni SQL aplicado ni fila en `_migration` — de lo
/// contrario la siguiente ejecución la reintentaría contra objetos que ya
/// existen (nuestras migraciones no usan `IF NOT EXISTS`) y quedaría
/// atascada sin recuperación salvo cirugía manual.
pub fn migrate(conn: &mut Connection, set: &[(&str, &str)]) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS _migration (
           name TEXT PRIMARY KEY,
           applied_at TEXT NOT NULL
         )",
        [],
    )?;
    for (name, sql) in set {
        let ya: i64 = conn.query_row(
            "SELECT COUNT(*) FROM _migration WHERE name = ?1",
            [name],
            |r| r.get(0),
        )?;
        if ya == 0 {
            let tx = conn.transaction()?;
            tx.execute_batch(sql)?;
            tx.execute(
                "INSERT INTO _migration (name, applied_at) VALUES (?1, ?2)",
                rusqlite::params![name, now_iso()],
            )?;
            tx.commit()?;
        }
    }
    Ok(())
}

/// Marca de tiempo ISO-8601 en UTC, con precisión de segundo.
pub fn now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    time::OffsetDateTime::from_unix_timestamp(secs as i64)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}
