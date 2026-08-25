use auscan_lib::db;
use rusqlite::Connection;

fn migrated() -> (tempfile::TempDir, Connection) {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = db::open(&dir.path().join("engagement.db")).unwrap();
    db::migrate(&mut conn, db::ENGAGEMENT_MIGRATIONS).unwrap();
    (dir, conn)
}

fn tablas(conn: &Connection) -> Vec<String> {
    let mut st = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap();
    let v = st
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    v
}

#[test]
fn estan_todas_las_tablas() {
    let (_d, conn) = migrated();
    let t = tablas(&conn);
    for esperada in [
        "engagement",
        "scope_entry",
        "tool_run",
        "host",
        "host_tag",
        "service",
        "observation",
    ] {
        assert!(
            t.contains(&esperada.to_string()),
            "falta la tabla {esperada}"
        );
    }
}

#[test]
fn engagement_admite_exactamente_una_fila() {
    let (_d, conn) = migrated();
    conn.execute(
        "INSERT INTO engagement (id, codename, created_at, state)
         VALUES ('a','CLAVEL','2026-01-01T00:00:00Z','draft')",
        [],
    )
    .unwrap();
    let segunda = conn.execute(
        "INSERT INTO engagement (id, codename, created_at, state)
         VALUES ('b','ROMERO','2026-01-01T00:00:00Z','draft')",
        [],
    );
    assert!(
        segunda.is_err(),
        "el CHECK(rowid=1) debe impedir la segunda fila"
    );
}

#[test]
fn observation_no_tiene_columna_de_severidad() {
    let (_d, conn) = migrated();
    let mut st = conn.prepare("PRAGMA table_info(observation)").unwrap();
    let cols: Vec<String> = st
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    for prohibida in ["severity", "severidad", "risk", "riesgo", "score", "cvss"] {
        assert!(
            !cols.iter().any(|c| c.eq_ignore_ascii_case(prohibida)),
            "observation no debe tener columna {prohibida}: la valoración la hace el consultor"
        );
    }
}

#[test]
fn borrar_un_host_arrastra_sus_servicios() {
    let (_d, conn) = migrated();
    conn.execute(
        "INSERT INTO host (id, ip, state) VALUES (1, '198.51.100.5', 'up')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO service (id, host_id, port, proto, state)
         VALUES (1, 1, 443, 'tcp', 'open')",
        [],
    )
    .unwrap();
    conn.execute("DELETE FROM host WHERE id = 1", []).unwrap();
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM service", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0, "foreign_keys=ON debe propagar el borrado");
}

#[test]
fn service_es_unico_por_host_puerto_protocolo() {
    let (_d, conn) = migrated();
    conn.execute(
        "INSERT INTO host (id, ip, state) VALUES (1,'198.51.100.5','up')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO service (host_id, port, proto, state) VALUES (1,443,'tcp','open')",
        [],
    )
    .unwrap();
    let dup = conn.execute(
        "INSERT INTO service (host_id, port, proto, state) VALUES (1,443,'tcp','open')",
        [],
    );
    assert!(dup.is_err());
}
