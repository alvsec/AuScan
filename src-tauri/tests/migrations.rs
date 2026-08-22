use auscan_lib::db;
use rusqlite::Connection;

fn temp_db() -> (tempfile::TempDir, Connection) {
    let dir = tempfile::tempdir().unwrap();
    let conn = db::open(&dir.path().join("t.db")).unwrap();
    (dir, conn)
}

fn pragma(conn: &Connection, name: &str) -> String {
    conn.query_row(&format!("PRAGMA {name}"), [], |r| {
        r.get::<_, rusqlite::types::Value>(0)
    })
    .map(|v| match v {
        rusqlite::types::Value::Text(s) => s,
        rusqlite::types::Value::Integer(i) => i.to_string(),
        other => format!("{other:?}"),
    })
    .unwrap()
}

#[test]
fn open_aplica_los_tres_pragmas() {
    let (_d, conn) = temp_db();
    assert_eq!(pragma(&conn, "journal_mode").to_lowercase(), "wal");
    assert_eq!(pragma(&conn, "foreign_keys"), "1");
    assert_eq!(pragma(&conn, "temp_store"), "2"); // 2 = MEMORY
}

#[test]
fn migrate_crea_el_esquema_del_indice() {
    let (_d, mut conn) = temp_db();
    db::migrate(&mut conn, db::INDEX_MIGRATIONS).unwrap();
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='engagement_ref'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1);
}

#[test]
fn migrate_es_idempotente() {
    let (_d, mut conn) = temp_db();
    db::migrate(&mut conn, db::INDEX_MIGRATIONS).unwrap();
    db::migrate(&mut conn, db::INDEX_MIGRATIONS).unwrap();
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM _migration", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, db::INDEX_MIGRATIONS.len() as i64);
}

#[test]
fn migrate_es_atomica_ante_sql_invalido() {
    let (_d, mut conn) = temp_db();
    // La primera sentencia del lote es válida y, sin transacción, quedaría
    // confirmada antes de que la segunda (sintaxis rota) haga fallar el lote.
    let roto: &[(&str, &str)] = &[(
        "0002_roto",
        "CREATE TABLE partial_artifact (id INTEGER PRIMARY KEY); CREATE TABLE (",
    )];

    let r = db::migrate(&mut conn, roto);
    assert!(r.is_err(), "un lote con SQL inválido debe devolver Err");

    let registrada: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM _migration WHERE name = '0002_roto'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        registrada, 0,
        "una migración fallida no debe quedar registrada en _migration"
    );

    let artefacto: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='partial_artifact'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        artefacto, 0,
        "no debe quedar ningún artefacto de un lote parcialmente aplicado"
    );
}

#[test]
fn el_estado_de_engagement_ref_esta_restringido() {
    let (_d, mut conn) = temp_db();
    db::migrate(&mut conn, db::INDEX_MIGRATIONS).unwrap();
    let r = conn.execute(
        "INSERT INTO engagement_ref (id, codename, created_at, state) VALUES ('x','CLAVEL','2026-01-01T00:00:00Z','inventado')",
        [],
    );
    assert!(r.is_err(), "un estado fuera del CHECK debe rechazarse");
}
