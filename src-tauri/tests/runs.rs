use std::collections::HashMap;
use std::net::IpAddr;

use auscan_lib::adapters::{HostFact, ObservationFact, ObservationKind, ServiceFact};
use auscan_lib::runs;

fn engagement_abierto() -> (tempfile::TempDir, rusqlite::Connection) {
    let dir = tempfile::tempdir().unwrap();
    let e = auscan_lib::engagement::create(dir.path(), "CLAVEL").unwrap();
    let conn = auscan_lib::engagement::open(dir.path(), &e.id).unwrap();
    (dir, conn)
}

fn host_de_prueba(ip: &str) -> HostFact {
    HostFact {
        ip: ip.parse::<IpAddr>().unwrap(),
        hostname: None,
        mac: None,
        vendor: None,
        os_guess: None,
        os_accuracy: None,
        state: Some("up".to_string()),
    }
}

fn servicio_de_prueba(ip: &str, port: u16) -> ServiceFact {
    ServiceFact {
        host_ip: ip.parse::<IpAddr>().unwrap(),
        port,
        proto: "tcp".to_string(),
        state: "open".to_string(),
        service: Some("http".to_string()),
        product: None,
        version: None,
        extrainfo: None,
        tunnel: None,
        cpe: None,
        banner: None,
    }
}

fn crear_run(conn: &rusqlite::Connection, seq: i64, phase: &str, started_at: &str) -> i64 {
    runs::crear_tool_run(
        conn,
        seq,
        "nmap",
        "7.99.0",
        "/opt/homebrew/bin/nmap",
        phase,
        "[]",
        false,
        "[]",
        started_at,
    )
    .unwrap()
}

#[test]
fn siguiente_seq_empieza_en_uno_y_crece() {
    let (_d, conn) = engagement_abierto();
    assert_eq!(runs::siguiente_seq(&conn).unwrap(), 1);
    crear_run(&conn, 1, "discovery", "2026-08-27T10:00:00Z");
    assert_eq!(runs::siguiente_seq(&conn).unwrap(), 2);
}

#[test]
fn upsert_host_inserta_la_primera_vez_y_conserva_datos_al_actualizar() {
    let (_d, conn) = engagement_abierto();
    let run1 = crear_run(&conn, 1, "discovery", "2026-08-27T10:00:00Z");
    let mut h = host_de_prueba("198.51.100.5");
    h.hostname = Some("host5.example".to_string());
    let id1 = runs::upsert_host(&conn, run1, &h).unwrap();

    let run2 = crear_run(&conn, 2, "portsweep", "2026-08-27T10:05:00Z");
    let mut h2 = host_de_prueba("198.51.100.5");
    h2.hostname = None; // esta fase no vuelve a reportar el hostname
    let id2 = runs::upsert_host(&conn, run2, &h2).unwrap();

    assert_eq!(id1, id2, "mismo host, mismo id");
    let known = runs::load_known_state(&conn).unwrap();
    assert_eq!(known.hosts.len(), 1);
    assert_eq!(
        known.hosts[0].hostname.as_deref(),
        Some("host5.example"),
        "un None de una fase posterior no debe borrar lo que ya se sabía"
    );
}

#[test]
fn upsert_service_pisa_el_estado_aunque_cambie() {
    let (_d, conn) = engagement_abierto();
    let run1 = crear_run(&conn, 1, "portsweep", "2026-08-27T10:00:00Z");
    let host_id = runs::upsert_host(&conn, run1, &host_de_prueba("198.51.100.5")).unwrap();
    let mut s = servicio_de_prueba("198.51.100.5", 80);
    s.state = "open".to_string();
    runs::upsert_service(&conn, run1, host_id, &s).unwrap();

    let run2 = crear_run(&conn, 2, "portsweep", "2026-08-27T11:00:00Z");
    let mut s2 = servicio_de_prueba("198.51.100.5", 80);
    s2.state = "closed".to_string();
    runs::upsert_service(&conn, run2, host_id, &s2).unwrap();

    let known = runs::load_known_state(&conn).unwrap();
    assert_eq!(known.services.len(), 1);
    assert_eq!(known.services[0].state, "closed");
}

#[test]
fn insertar_observaciones_no_duplica_la_misma_observacion() {
    let (_d, conn) = engagement_abierto();
    let run = crear_run(&conn, 1, "discovery", "2026-08-27T10:00:00Z");
    let host_id = runs::upsert_host(&conn, run, &host_de_prueba("198.51.100.5")).unwrap();
    let mut ids = HashMap::new();
    ids.insert("198.51.100.5".parse::<IpAddr>().unwrap(), host_id);
    let obs = vec![ObservationFact {
        host_ip: Some("198.51.100.5".parse().unwrap()),
        port: None,
        kind: ObservationKind::HostDiscovered,
        subject: "198.51.100.5".to_string(),
        statement: "Host activo".to_string(),
        evidence: None,
        evidence_ref: None,
        meta_json: None,
    }];
    runs::insertar_observaciones(&conn, run, &ids, &obs, "2026-08-27T10:00:01Z").unwrap();
    runs::insertar_observaciones(&conn, run, &ids, &obs, "2026-08-27T10:00:01Z").unwrap();

    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM observation", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1);
}

#[test]
fn insertar_observaciones_falla_si_el_host_no_esta_en_el_mapa() {
    let (_d, conn) = engagement_abierto();
    let run = crear_run(&conn, 1, "discovery", "2026-08-27T10:00:00Z");
    let ids = HashMap::new(); // vacío a propósito
    let obs = vec![ObservationFact {
        host_ip: Some("198.51.100.5".parse().unwrap()),
        port: None,
        kind: ObservationKind::HostDiscovered,
        subject: "198.51.100.5".to_string(),
        statement: "Host activo".to_string(),
        evidence: None,
        evidence_ref: None,
        meta_json: None,
    }];
    assert!(matches!(
        runs::insertar_observaciones(&conn, run, &ids, &obs, "2026-08-27T10:00:01Z"),
        Err(auscan_lib::error::AppError::InconsistentParse(_))
    ));
}

#[test]
fn cerrar_tool_run_actualiza_los_campos_finales() {
    let (_d, conn) = engagement_abierto();
    let id = crear_run(&conn, 1, "discovery", "2026-08-27T10:00:00Z");
    runs::cerrar_tool_run(
        &conn,
        id,
        "2026-08-27T10:00:05Z",
        Some(0),
        "ok",
        Some("raw/0001-nmap-discovery.xml"),
        Some(&runs::sha256_hex(b"contenido")),
        None,
    )
    .unwrap();
    let (status, exit_code): (String, Option<i32>) = conn
        .query_row(
            "SELECT status, exit_code FROM tool_run WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "ok");
    assert_eq!(exit_code, Some(0));
}

#[test]
fn sha256_hex_es_determinista_y_de_64_caracteres_hex() {
    let a = runs::sha256_hex(b"lo mismo");
    let b = runs::sha256_hex(b"lo mismo");
    assert_eq!(a, b);
    assert_eq!(a.len(), 64);
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
}
