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
    let (_d, conn) = temp_db();
    db::migrate(&conn, db::INDEX_MIGRATIONS).unwrap();
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
    let (_d, conn) = temp_db();
    db::migrate(&conn, db::INDEX_MIGRATIONS).unwrap();
    db::migrate(&conn, db::INDEX_MIGRATIONS).unwrap();
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM _migration", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, db::INDEX_MIGRATIONS.len() as i64);
}

#[test]
fn el_estado_de_engagement_ref_esta_restringido() {
    let (_d, conn) = temp_db();
    db::migrate(&conn, db::INDEX_MIGRATIONS).unwrap();
    let r = conn.execute(
        "INSERT INTO engagement_ref (id, codename, created_at, state) VALUES ('x','CLAVEL','2026-01-01T00:00:00Z','inventado')",
        [],
    );
    assert!(r.is_err(), "un estado fuera del CHECK debe rechazarse");
}
