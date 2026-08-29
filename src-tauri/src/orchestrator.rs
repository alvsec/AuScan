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
    Log {
        origen: LineaOrigen,
        texto: String,
    },
    RunTerminado {
        seq: i64,
        status: String,
    },
    /// Lo que la fase entera dejó ARCHIVADO, sumando invocación a
    /// invocación: no lo que el escáner vio ni lo que se planificó, sino
    /// lo que `parse()` normalizó y se llegó a escribir en la base.
    FaseTerminada {
        hosts: usize,
        servicios: usize,
        observaciones: usize,
    },
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

/// Calcula qué invocaciones lanzaría una fase, sin ejecutar nada. Lo usan
/// tanto `ejecutar_fase` (que sigue adelante y las ejecuta) como el
/// comando de vista previa (que solo quiere enseñárselas al operador).
///
/// Es una `fn` a secas, no `async`: en todo este tramo no hay un solo
/// `.await`, así que no hay ninguna razón para arrastrar un futuro. Eso
/// también es lo que hace que sea seguro tener el lock de `state.open`
/// cogido dentro de los bloques de abajo -- ningún `MutexGuard` puede
/// cruzar un await que no existe.
#[allow(clippy::too_many_arguments)]
pub fn planificar(
    state: &AppState,
    registro: &[Box<dyn ToolAdapter>],
    fase: Phase,
    tool_id: &str,
    objetivos_crudos: &[String],
    privilegio_disponible: bool,
    opciones: &PhaseOptions,
) -> Result<(Vec<Invocation>, String)> {
    // Etapa 1: cargar el alcance. Rápido y síncrono; el lock se suelta
    // antes de resolver ningún nombre.
    let (scope, id_engagement) = {
        let guard = state.open.lock().unwrap_or_else(|e| e.into_inner());
        let abierto = guard.as_ref().ok_or(AppError::NoEngagementOpen)?;
        (scope::load(&abierto.conn)?, abierto.id.clone())
    };

    // Etapa 2: resolver y validar los objetivos, SIN el lock cogido.
    // `SystemResolver` hace una consulta DNS síncrona y bloqueante: con
    // el mutex en la mano, un nombre con DNS lento o caído congelaría
    // todos los demás comandos (scope_list, engagement_open, purge...)
    // durante el timeout entero, además de bloquear un hilo del runtime.
    // No es un `.await`, así que la comprobación de `Send` no lo ve --
    // pero es el mismo peligro que la disciplina de locks existe para
    // evitar.
    let resolver = SystemResolver;
    let mut targets = Vec::new();
    for t in objetivos_crudos {
        targets.extend(scope.validate_target(t, &resolver)?);
    }

    // Etapa 3: recuperar el lock para leer el estado conocido y
    // planificar. Se revalida que siga siendo el mismo engagement: la
    // resolución de nombres de la etapa 2 pudo durar lo suficiente como
    // para que el operador abriera o purgara otro por el camino.
    let invocaciones = {
        let guard = state.open.lock().unwrap_or_else(|e| e.into_inner());
        let abierto = guard.as_ref().ok_or(AppError::NoEngagementOpen)?;
        if abierto.id != id_engagement {
            return Err(AppError::EngagementChanged(id_engagement));
        }
        let known = runs::load_known_state(&abierto.conn)?;
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
        adaptador.plan(&ctx)?
    };

    Ok((invocaciones, id_engagement))
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
    let (invocaciones, id_engagement) = planificar(
        state,
        registro,
        fase,
        tool_id,
        objetivos_crudos,
        privilegio_disponible,
        opciones,
    )?;

    let mut total_hosts = 0usize;
    let mut total_servicios = 0usize;
    let mut total_observaciones = 0usize;

    for invocacion in invocaciones {
        // Cancelar una fase tiene que PARARLA, no solo hacer que cada
        // invocación restante nazca muerta. Sin este corte, una fase
        // Services con una invocación por host seguía resolviendo el
        // binario, revalidando la versión, insertando una fila en
        // `tool_run`, lanzando el escáner real y matándolo acto seguido
        // -- una vez por cada host que quedara. `exec::ejecutar` también
        // comprueba el token antes de su `spawn`, pero eso solo evita el
        // proceso: el resto del trabajo (y la fila de auditoría de una
        // ejecución que nunca ocurrió) hay que evitarlo aquí.
        if cancelar.is_cancelled() {
            break;
        }
        let (hosts, servicios, observaciones) = ejecutar_invocacion(
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
        total_hosts += hosts;
        total_servicios += servicios;
        total_observaciones += observaciones;
    }
    on_suceso(SucesoRun::FaseTerminada {
        hosts: total_hosts,
        servicios: total_servicios,
        observaciones: total_observaciones,
    });
    Ok(())
}

/// Devuelve `(hosts, servicios, observaciones)`: lo que ESTA invocación
/// aportó a la base. Es `(0, 0, 0)` cuando no hubo nada que archivar --
/// se canceló, la herramienta falló, o `parse()` no supo interpretar la
/// salida --, porque el recuento tiene que contar lo que de verdad se
/// escribió, no lo que se esperaba escribir.
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
) -> Result<(usize, usize, usize)> {
    let adaptador = registro
        .iter()
        .find(|a| a.descriptor().id == tool_id)
        .ok_or_else(|| AppError::ToolNotFound(tool_id.to_string()))?;
    let descriptor = adaptador.descriptor();

    // Se resuelve UNA sola vez: esta misma ruta se usa para lanzar y
    // para el `expected_path` de la verja. El hueco de symlinks de
    // Homebrew desaparece por construcción, no por canonicalizar.
    //
    // Se prueban TODOS los nombres declarados, en orden, igual que
    // `preflight::check_tool`: si el preflight aceptó la herramienta por
    // su segundo binario, quedarse aquí con el primero la daría por
    // ausente justo al ir a lanzarla.
    let binario = descriptor
        .binaries
        .iter()
        .find_map(|b| which::which(b).ok())
        .ok_or_else(|| AppError::ToolNotFound(tool_id.to_string()))?;

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
        // El lock se soltó mientras se resolvía el binario y se
        // revalidaba la versión: comprobar que sigue abierto NO basta,
        // hay que comprobar que sigue abierto EL MISMO.
        if abierto.id != id_engagement {
            return Err(AppError::EngagementChanged(id_engagement.to_string()));
        }
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
            // El privilegio que se archiva es el REAL del proceso -- el
            // mismo que `verja()` acaba de hacer cumplir --, nunca
            // `invocacion.needs_privilege`, que es lo que el adaptador
            // dice necesitar. El registro de auditoría tiene que contar
            // lo que de verdad pasó, no lo que se pidió.
            privilegio_disponible,
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

    // Si `parse()` falla, el aviso se guarda aquí y se emite DESPUÉS de
    // soltar el lock: `std::sync::Mutex` no es reentrante, y un
    // `on_suceso` que llegara a tocar `state.open` se autobloquearía.
    let mut aviso_parseo: Option<String> = None;
    let mut recuento = (0usize, 0usize, 0usize);

    {
        let guard = state.open.lock().unwrap_or_else(|e| e.into_inner());
        let abierto = guard.as_ref().ok_or(AppError::NoEngagementOpen)?;
        // Segunda revalidación, y la que más importa: entre el bloque
        // anterior y este se esperó al proceso entero. `tool_run_id` se
        // acuñó contra la base del engagement de arriba, y como es un
        // autoincremento por base, ese mismo id puede existir ya en la
        // base de OTRO engagement -- escribir aquí a ciegas atribuiría
        // los resultados de un cliente al expediente de otro.
        if abierto.id != id_engagement {
            return Err(AppError::EngagementChanged(id_engagement.to_string()));
        }
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
                    recuento = (
                        normalizado.hosts.len(),
                        normalizado.services.len(),
                        normalizado.observations.len(),
                    );
                }
                Err(e) => {
                    aviso_parseo = Some(format!("no se pudo interpretar la salida: {e}"));
                }
            }
        }
    }

    if let Some(texto) = aviso_parseo {
        on_suceso(SucesoRun::Log {
            origen: LineaOrigen::Stderr,
            texto,
        });
    }

    on_suceso(SucesoRun::RunTerminado {
        seq,
        status: status.to_string(),
    });
    Ok(recuento)
}
