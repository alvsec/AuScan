//! Persistencia de ejecuciones, hosts, servicios y observaciones. Sin
//! mecánica de proceso aquí: solo SQL sobre una conexión ya abierta.

use std::collections::HashMap;
use std::net::IpAddr;

use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::adapters::{HostFact, KnownState, ObservationFact, ObservationKind, ServiceFact};
use crate::error::{AppError, Result};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn kind_str(k: ObservationKind) -> &'static str {
    match k {
        ObservationKind::HostDiscovered => "host_discovered",
        ObservationKind::HostOsGuess => "host_os_guess",
        ObservationKind::ServiceOpen => "service_open",
        ObservationKind::ServiceVersionDisclosed => "service_version_disclosed",
        ObservationKind::WebTechnology => "web_technology",
        ObservationKind::WebTitle => "web_title",
        ObservationKind::WebHeaderAbsent => "web_header_absent",
        ObservationKind::TlsProtocolEnabled => "tls_protocol_enabled",
        ObservationKind::TlsCipherOffered => "tls_cipher_offered",
        ObservationKind::TlsCertificateExpiry => "tls_certificate_expiry",
        ObservationKind::SmbSigningState => "smb_signing_state",
        ObservationKind::SshAlgorithmOffered => "ssh_algorithm_offered",
        ObservationKind::TemplateMatch => "template_match",
    }
}

pub fn siguiente_seq(conn: &Connection) -> Result<i64> {
    let seq: i64 = conn.query_row("SELECT COALESCE(MAX(seq), 0) + 1 FROM tool_run", [], |r| {
        r.get(0)
    })?;
    Ok(seq)
}

#[allow(clippy::too_many_arguments)]
pub fn crear_tool_run(
    conn: &Connection,
    seq: i64,
    tool: &str,
    tool_version: &str,
    tool_path: &str,
    phase: &str,
    argv_json: &str,
    privileged: bool,
    targets_json: &str,
    started_at: &str,
) -> Result<i64> {
    conn.execute(
        "INSERT INTO tool_run (seq, tool, tool_version, tool_path, phase, argv_json, privileged, targets_json, started_at, status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'running')",
        rusqlite::params![
            seq,
            tool,
            tool_version,
            tool_path,
            phase,
            argv_json,
            privileged,
            targets_json,
            started_at,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

#[allow(clippy::too_many_arguments)]
pub fn cerrar_tool_run(
    conn: &Connection,
    id: i64,
    finished_at: &str,
    exit_code: Option<i32>,
    status: &str,
    raw_path: Option<&str>,
    raw_sha256: Option<&str>,
    stderr_path: Option<&str>,
) -> Result<()> {
    conn.execute(
        "UPDATE tool_run
         SET finished_at = ?1, exit_code = ?2, status = ?3, raw_path = ?4, raw_sha256 = ?5, stderr_path = ?6
         WHERE id = ?7",
        rusqlite::params![finished_at, exit_code, status, raw_path, raw_sha256, stderr_path, id],
    )?;
    Ok(())
}

/// Upsert de un host. Los campos mutables se conservan si la nueva
/// lectura no trae nada (`COALESCE`): una fase posterior que no vuelve
/// a reportar el hostname o el MAC de un host no debe borrar lo que una
/// fase anterior ya averiguó. `state` sigue la misma regla porque un
/// "up"/"down" de una fase vacía no debería pisar un estado ya
/// confirmado. `last_seen_run` sí se pisa siempre: cualquier ejecución
/// que toque este host cuenta como haberlo visto de nuevo.
pub fn upsert_host(conn: &Connection, tool_run_id: i64, host: &HostFact) -> Result<i64> {
    let id: i64 = conn.query_row(
        "INSERT INTO host (ip, hostname, mac, vendor, os_guess, os_accuracy, state, first_seen_run, last_seen_run)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
         ON CONFLICT(ip) DO UPDATE SET
           hostname = COALESCE(excluded.hostname, hostname),
           mac = COALESCE(excluded.mac, mac),
           vendor = COALESCE(excluded.vendor, vendor),
           os_guess = COALESCE(excluded.os_guess, os_guess),
           os_accuracy = COALESCE(excluded.os_accuracy, os_accuracy),
           state = COALESCE(excluded.state, state),
           last_seen_run = excluded.last_seen_run
         RETURNING id",
        rusqlite::params![
            host.ip.to_string(),
            host.hostname,
            host.mac,
            host.vendor,
            host.os_guess,
            host.os_accuracy,
            host.state,
            tool_run_id,
        ],
        |r| r.get(0),
    )?;
    Ok(id)
}

pub fn upsert_hosts(
    conn: &Connection,
    tool_run_id: i64,
    hosts: &[HostFact],
) -> Result<HashMap<IpAddr, i64>> {
    hosts
        .iter()
        .map(|h| Ok((h.ip, upsert_host(conn, tool_run_id, h)?)))
        .collect()
}

/// Upsert de un servicio. A diferencia de `upsert_host`, `state` se
/// pisa SIEMPRE sin `COALESCE`: el estado de un puerto puede cambiar de
/// verdad entre ejecuciones (una regla de firewall, por ejemplo), y la
/// lectura más reciente es la que debe quedar.
pub fn upsert_service(
    conn: &Connection,
    tool_run_id: i64,
    host_id: i64,
    service: &ServiceFact,
) -> Result<i64> {
    let id: i64 = conn.query_row(
        "INSERT INTO service (host_id, port, proto, state, service, product, version, extrainfo, tunnel, cpe, banner, first_seen_run, last_seen_run)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12)
         ON CONFLICT(host_id, port, proto) DO UPDATE SET
           state = excluded.state,
           service = COALESCE(excluded.service, service),
           product = COALESCE(excluded.product, product),
           version = COALESCE(excluded.version, version),
           extrainfo = COALESCE(excluded.extrainfo, extrainfo),
           tunnel = COALESCE(excluded.tunnel, tunnel),
           cpe = COALESCE(excluded.cpe, cpe),
           banner = COALESCE(excluded.banner, banner),
           last_seen_run = excluded.last_seen_run
         RETURNING id",
        rusqlite::params![
            host_id,
            service.port,
            service.proto,
            service.state,
            service.service,
            service.product,
            service.version,
            service.extrainfo,
            service.tunnel,
            service.cpe,
            service.banner,
            tool_run_id,
        ],
        |r| r.get(0),
    )?;
    Ok(id)
}

pub fn upsert_services(
    conn: &Connection,
    tool_run_id: i64,
    host_ids: &HashMap<IpAddr, i64>,
    services: &[ServiceFact],
) -> Result<()> {
    for s in services {
        let host_id = *host_ids
            .get(&s.host_ip)
            .ok_or_else(|| AppError::InconsistentParse(s.host_ip.to_string()))?;
        upsert_service(conn, tool_run_id, host_id, s)?;
    }
    Ok(())
}

/// `service_id` se deja siempre NULL: `subject` ya identifica
/// "ip:puerto/proto" por completo, y resolver el id exigiría conocer
/// el protocolo, que `ObservationFact` no lleva -- adivinar "tcp" aquí
/// filtraría conocimiento de un adaptador concreto dentro de una capa
/// que sirve a cualquiera.
pub fn insertar_observaciones(
    conn: &Connection,
    tool_run_id: i64,
    host_ids: &HashMap<IpAddr, i64>,
    observations: &[ObservationFact],
    observed_at: &str,
) -> Result<()> {
    for o in observations {
        let host_id = match o.host_ip {
            Some(ip) => Some(
                *host_ids
                    .get(&ip)
                    .ok_or_else(|| AppError::InconsistentParse(ip.to_string()))?,
            ),
            None => None,
        };
        conn.execute(
            "INSERT INTO observation (tool_run_id, host_id, service_id, kind, subject, statement, evidence, evidence_ref, meta_json, observed_at)
             VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(tool_run_id, kind, subject, statement) DO NOTHING",
            rusqlite::params![
                tool_run_id,
                host_id,
                kind_str(o.kind),
                o.subject,
                o.statement,
                o.evidence,
                o.evidence_ref,
                o.meta_json,
                observed_at,
            ],
        )?;
    }
    Ok(())
}

/// Reconstruye lo que ya se sabe de fases anteriores, para alimentar el
/// `plan()` de la siguiente.
pub fn load_known_state(conn: &Connection) -> Result<KnownState> {
    let mut hosts_stmt =
        conn.prepare("SELECT ip, hostname, mac, vendor, os_guess, os_accuracy, state FROM host")?;
    let hosts = hosts_stmt
        .query_map([], |r| {
            let ip: String = r.get(0)?;
            Ok(HostFact {
                ip: ip
                    .parse()
                    .expect("host.ip lo escribe solo upsert_host, siempre una IP válida"),
                hostname: r.get(1)?,
                mac: r.get(2)?,
                vendor: r.get(3)?,
                os_guess: r.get(4)?,
                os_accuracy: r.get(5)?,
                state: r.get(6)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let mut services_stmt = conn.prepare(
        "SELECT host.ip, service.port, service.proto, service.state, service.service,
                service.product, service.version, service.extrainfo, service.tunnel,
                service.cpe, service.banner
         FROM service JOIN host ON host.id = service.host_id",
    )?;
    let services = services_stmt
        .query_map([], |r| {
            let ip: String = r.get(0)?;
            Ok(ServiceFact {
                host_ip: ip
                    .parse()
                    .expect("host.ip lo escribe solo upsert_host, siempre una IP válida"),
                port: r.get(1)?,
                proto: r.get(2)?,
                state: r.get(3)?,
                service: r.get(4)?,
                product: r.get(5)?,
                version: r.get(6)?,
                extrainfo: r.get(7)?,
                tunnel: r.get(8)?,
                cpe: r.get(9)?,
                banner: r.get(10)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(KnownState { hosts, services })
}
