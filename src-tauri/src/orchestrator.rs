//! Encadena plan → verja → spawn → parse → persistir para una fase
//! completa. El único módulo que sabe hacer las cinco cosas a la vez;
//! cada una por separado vive en su propio fichero (`adapters`,
//! `exec`, `runs`) precisamente para que este quede como el único
//! sitio que las junta.

use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::adapters::{Invocation, ParseContext, Phase, PhaseOptions, PlanContext, ToolAdapter};
use crate::db;
use crate::error::{AppError, Result};
use crate::exec::{self, LineaOrigen};
use crate::paths;
use crate::runs;
use crate::scope::{self, SystemResolver};
use crate::state::AppState;

/// Lo que le pasa a quien esté viendo la ejecución en vivo.
pub enum SucesoRun {
    Log { origen: LineaOrigen, texto: String },
    RunTerminado { seq: i64, status: String },
    FaseTerminada,
}

fn fase_str(f: Phase) -> &'static str {
    match f {
        Phase::Discovery => "discovery",
        Phase::PortSweep => "portsweep",
        Phase::Services => "services",
        Phase::Web => "web",
        Phase::Templates => "templates",
        Phase::Tls => "tls",
        Phase::Smb => "smb",
        Phase::Ssh => "ssh",
        Phase::Mdns => "mdns",
    }
}

/// Ejecuta una fase completa: arma el `PlanContext`, pide las
/// invocaciones al adaptador, y lanza cada una en orden.
#[allow(clippy::too_many_arguments)]
pub async fn ejecutar_fase(
    state: &AppState,
    registro: &[Box<dyn ToolAdapter>],
    fase: Phase,
    tool_id: &str,
    objetivos_crudos: &[String],
    privilegio_disponible: bool,
    opciones: &PhaseOptions,
    cancelar: CancellationToken,
    mut on_suceso: impl FnMut(SucesoRun) + Send + 'static,
) -> Result<()> {
    let (invocaciones, id_engagement) = {
        // Bloque síncrono: el guard se suelta al final de este bloque,
        // antes de cualquier `.await`.
        let guard = state.open.lock().unwrap_or_else(|e| e.into_inner());
        let abierto = guard.as_ref().ok_or(AppError::NoEngagementOpen)?;
        let conn = &abierto.conn;

        let scope = scope::load(conn)?;
        let resolver = SystemResolver;
        let mut targets = Vec::new();
        for t in objetivos_crudos {
            targets.extend(scope.validate_target(t, &resolver)?);
        }

        let known = runs::load_known_state(conn)?;
        let adaptador = registro
            .iter()
            .find(|a| a.descriptor().id == tool_id)
            .ok_or_else(|| AppError::ToolNotFound(tool_id.to_string()))?;
        let ctx = PlanContext {
            phase: fase,
            scope: &scope,
            targets: &targets,
            known: &known,
            privileged: privilegio_disponible,
            options: opciones,
        };
        (adaptador.plan(&ctx)?, abierto.id.clone())
    };

    for invocacion in invocaciones {
        ejecutar_invocacion(
            state,
            registro,
            tool_id,
            &id_engagement,
            invocacion,
            privilegio_disponible,
            cancelar.clone(),
            &mut on_suceso,
        )
        .await?;
    }
    on_suceso(SucesoRun::FaseTerminada);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn ejecutar_invocacion(
    state: &AppState,
    registro: &[Box<dyn ToolAdapter>],
    tool_id: &str,
    id_engagement: &str,
    invocacion: Invocation,
    privilegio_disponible: bool,
    cancelar: CancellationToken,
    on_suceso: &mut (impl FnMut(SucesoRun) + Send + 'static),
) -> Result<()> {
    let adaptador = registro
        .iter()
        .find(|a| a.descriptor().id == tool_id)
        .ok_or_else(|| AppError::ToolNotFound(tool_id.to_string()))?;
    let descriptor = adaptador.descriptor();

    // Se resuelve UNA sola vez: esta misma ruta se usa para lanzar y
    // para el `expected_path` de la verja. El hueco de symlinks de
    // Homebrew desaparece por construcción, no por canonicalizar.
    let binario = which::which(descriptor.binaries[0])
        .map_err(|_| AppError::ToolNotFound(tool_id.to_string()))?;

    // Revalidación de versión justo antes de ejecutar: si cambió desde
    // el preflight (un `brew upgrade` de por medio), no se lanza.
    let salida_version = std::process::Command::new(&binario)
        .args(adaptador.version_argv())
        .output()
        .map_err(AppError::Io)?;
    let version = adaptador
        .parse_version(&String::from_utf8_lossy(&salida_version.stdout))
        .map_err(|_| AppError::ToolVersionInsuficiente {
            tool: tool_id.to_string(),
            actual: "desconocida".to_string(),
            minimo: descriptor.min_version.to_string(),
        })?;
    if version < descriptor.min_version {
        return Err(AppError::ToolVersionInsuficiente {
            tool: tool_id.to_string(),
            actual: version.to_string(),
            minimo: descriptor.min_version.to_string(),
        });
    }

    exec::verja(
        &invocacion,
        &binario,
        &descriptor,
        &binario,
        privilegio_disponible,
    )?;

    let (tool_run_id, seq) = {
        let guard = state.open.lock().unwrap_or_else(|e| e.into_inner());
        let abierto = guard.as_ref().ok_or(AppError::NoEngagementOpen)?;
        let conn = &abierto.conn;
        let seq = runs::siguiente_seq(conn)?;
        let targets_json = serde_json::to_string(
            &invocacion
                .targets
                .iter()
                .map(|t| t.to_string())
                .collect::<Vec<_>>(),
        )
        .expect("Vec<String> siempre serializa");
        let argv_json =
            serde_json::to_string(&invocacion.argv).expect("Vec<String> siempre serializa");
        let id = runs::crear_tool_run(
            conn,
            seq,
            descriptor.id,
            &version.to_string(),
            &binario.display().to_string(),
            fase_str(invocacion.phase),
            &argv_json,
            invocacion.needs_privilege,
            &targets_json,
            &db::now_iso(),
        )?;
        (id, seq)
    };

    let raw_dir = paths::raw_dir(&state.root, id_engagement)?;
    std::fs::create_dir_all(&raw_dir).map_err(AppError::Io)?;
    let nombre_raw = format!(
        "{seq:04}-{}-{}.xml",
        descriptor.id,
        fase_str(invocacion.phase)
    );
    let raw_rel = format!("raw/{nombre_raw}");

    let mut on_linea = |l: exec::Linea| {
        on_suceso(SucesoRun::Log {
            origen: l.origen,
            texto: l.texto,
        });
    };
    let timeout: Duration = invocacion.timeout;
    let resultado =
        exec::ejecutar(&binario, &invocacion.argv, timeout, cancelar, &mut on_linea).await?;

    std::fs::write(raw_dir.join(&nombre_raw), &resultado.raw).map_err(AppError::Io)?;
    let raw_sha256 = runs::sha256_hex(&resultado.raw);

    let status = if resultado.cancelado {
        "cancelled"
    } else if resultado.exit_code == Some(0) {
        "ok"
    } else {
        "failed"
    };

    {
        let guard = state.open.lock().unwrap_or_else(|e| e.into_inner());
        let abierto = guard.as_ref().ok_or(AppError::NoEngagementOpen)?;
        let conn = &abierto.conn;
        runs::cerrar_tool_run(
            conn,
            tool_run_id,
            &db::now_iso(),
            resultado.exit_code,
            status,
            Some(&raw_rel),
            Some(&raw_sha256),
            None,
        )?;

        if !resultado.cancelado && status == "ok" {
            let ctx = ParseContext {
                tool_run_id,
                raw_path: &raw_rel,
                observed_at: &db::now_iso(),
            };
            match adaptador.parse(&resultado.raw, &ctx) {
                Ok(normalizado) => {
                    let host_ids = runs::upsert_hosts(conn, tool_run_id, &normalizado.hosts)?;
                    runs::upsert_services(conn, tool_run_id, &host_ids, &normalizado.services)?;
                    runs::insertar_observaciones(
                        conn,
                        tool_run_id,
                        &host_ids,
                        &normalizado.observations,
                        &db::now_iso(),
                    )?;
                }
                Err(e) => {
                    on_suceso(SucesoRun::Log {
                        origen: LineaOrigen::Stderr,
                        texto: format!("no se pudo interpretar la salida: {e}"),
                    });
                }
            }
        }
    }

    on_suceso(SucesoRun::RunTerminado {
        seq,
        status: status.to_string(),
    });
    Ok(())
}
