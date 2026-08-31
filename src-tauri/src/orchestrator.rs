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
use crate::preflight;
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

/// Ejecuta una fase completa: eleva (si se pidió), arma el
/// `PlanContext`, pide las invocaciones al adaptador, y lanza cada una en
/// orden.
///
/// `privilegio_disponible` ya NO es un booleano que decida quien llama:
/// se calcula aquí dentro, y solo es cierto si de verdad hay un
/// trabajador vivo y root, o si el propio proceso ya lo es.
#[allow(clippy::too_many_arguments)]
pub async fn ejecutar_fase(
    state: &AppState,
    registro: &[Box<dyn ToolAdapter>],
    fase: Phase,
    tool_id: &str,
    objetivos_crudos: &[String],
    elevar: bool,
    opciones: &PhaseOptions,
    cancelar: CancellationToken,
    mut on_suceso: impl FnMut(SucesoRun) + Send + 'static,
) -> Result<()> {
    // Elevar, si se pidió, es lo PRIMERO -- antes de cargar el alcance
    // siquiera. `PlanContext.privileged` decide qué banderas construye el
    // adaptador (descubrimiento por ARP necesita root, por sondeo TCP
    // no), así que tiene que reflejar si la elevación tuvo éxito ANTES de
    // llamar a `plan()`, no descubrirlo a mitad de camino.
    //
    // Si `elevar` es true y falla -- el operador rechaza el diálogo,
    // caduca el plazo, o (no debería pasar nunca) el trabajador dice que
    // no es root --, la fase entera falla aquí mismo. Sin fallback
    // silencioso a modo sin privilegios (spec §8.9): eso cambiaría lo que
    // se escanea sin que el operador lo decidiera, y ya vio el argv
    // previsto para `elevar=true` en la confirmación (§9.7).
    #[cfg(target_os = "macos")]
    let trabajador: Option<crate::privilege::TrabajadorActivo> = if elevar {
        let dir_control = std::env::temp_dir().join(format!("auscan-privilegio-{}", uuid_simple()));
        Some(crate::privilege::iniciar_trabajador(&dir_control).await?)
    } else {
        None
    };
    // En no-macOS no hay a qué intentar elevarse: `iniciar_trabajador` ni
    // existe. Pedirlo es un error, nunca un "sigue sin privilegios" mudo,
    // por la misma razón de arriba.
    #[cfg(not(target_os = "macos"))]
    let trabajador: Option<crate::privilege::TrabajadorActivo> = {
        if elevar {
            return Err(AppError::ElevationFailed(
                "la elevación solo está disponible en macOS".to_string(),
            ));
        }
        None
    };

    let privilegio_disponible = trabajador.is_some() || preflight::running_privileged();

    // El cuerpo va envuelto en `AtrapaPanico` y NO directamente en un
    // `.await`: un pánico dentro (`adaptador.parse()` corre sobre la
    // salida cruda de un escáner de terceros) desenrollaría esta función
    // entera, dejaría caer `trabajador` -- que a propósito no implementa
    // `Drop` -- y la parada de abajo no correría nunca. El proceso root
    // se quedaría sondeando su directorio de control para siempre, y sin
    // el manejo que lo posee ya no habría forma de volver a decirle nada.
    let resultado = AtrapaPanico::nuevo(ejecutar_fase_interna(
        state,
        registro,
        fase,
        tool_id,
        objetivos_crudos,
        privilegio_disponible,
        &trabajador,
        opciones,
        cancelar,
        &mut on_suceso,
    ))
    .await;

    cerrar_fase(resultado, trabajador).await
}

/// Cierra la fase: para el trabajador PASE LO QUE PASE y devuelve lo que
/// el cuerpo dio -- o, si el cuerpo entró en pánico, relanza ese pánico
/// una vez hecha la parada.
///
/// La parada corre también si la fase falló a mitad, o si se desenrolló:
/// dejar caer un `TrabajadorActivo` sin llamarla deja un proceso root
/// esperando órdenes para siempre (ver el comentario del tipo en
/// `privilege.rs`).
///
/// Su error NO pisa al de la fase: si la fase ya falló, lo que el
/// operador necesita leer es "objetivo fuera de alcance", no "no se pudo
/// escribir el centinela de parada". Solo cuando la fase fue bien el
/// fallo de la parada es la única noticia que hay que dar. Y un pánico
/// gana a los dos: se relanza intacto (`resume_unwind` no vuelve a
/// disparar el hook, así que la traza que ya se imprimió es la del sitio
/// real del fallo). Tragárselo aquí escondería un bug de verdad, además
/// de dejar al vigía del `JoinHandle` de `lib.rs` sin el pánico que
/// espera para descongelar la pantalla.
async fn cerrar_fase(
    resultado: std::thread::Result<Result<()>>,
    trabajador: Option<crate::privilege::TrabajadorActivo>,
) -> Result<()> {
    if let Some(t) = trabajador {
        let parada = crate::privilege::detener_trabajador(t).await;
        if matches!(resultado, Ok(Ok(()))) {
            parada?;
        }
    }

    match resultado {
        Ok(r) => r,
        Err(carga) => std::panic::resume_unwind(carga),
    }
}

/// Un futuro que envuelve a otro y le convierte el pánico en un `Err`,
/// en vez de dejar que se desenrolle a través de quien lo espera.
///
/// Existe porque `ejecutar_fase` no puede permitirse el desenrollado
/// limpio de siempre: entre arrancar el trabajador elevado y pararlo hay
/// un `.await` que puede entrar en pánico sobre entrada no confiable --
/// el mismo camino por el que `lib.rs` tiene su `GuardaEjecucion` y su
/// vigía del `JoinHandle` --, y el recurso que hay que soltar es un
/// proceso root, no un slot de un mutex.
///
/// Por qué esto y no el patrón del vigía (`spawn` + `is_panic()` sobre el
/// `JoinHandle`): ese exige `'static + Send`, y el cuerpo de la fase toma
/// prestado medio mundo (`&AppState`, el registro de adaptadores,
/// `&mut on_suceso`). La garantía que hace falta es exactamente la misma;
/// el mecanismo tiene que ser uno que sirva sobre un futuro que toma
/// prestado, y un `catch_unwind` dentro del `poll` lo es.
///
/// Se escribe a mano en vez de tirar de `futures::FutureExt::catch_unwind`
/// para no meter la familia `futures` entera como dependencia por un solo
/// combinador. `Pin<Box<F>>` -- que es `Unpin` sea cual sea `F` -- deja
/// hacer la proyección sin una línea de `unsafe`.
struct AtrapaPanico<F> {
    futuro: std::pin::Pin<Box<F>>,
}

impl<F: std::future::Future> AtrapaPanico<F> {
    fn nuevo(futuro: F) -> Self {
        Self {
            futuro: Box::pin(futuro),
        }
    }
}

impl<F: std::future::Future> std::future::Future for AtrapaPanico<F> {
    type Output = std::thread::Result<F::Output>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        use std::task::Poll;

        // `AssertUnwindSafe` porque nada de lo que sobrevive a un pánico
        // aquí se vuelve a mirar por este camino: el futuro de dentro
        // queda envenenado y no se vuelve a sondear (se devuelve `Ready`),
        // y el único estado compartido que un pánico podría dejar a medias
        // es el `Mutex` de `AppState`, que todo el proyecto abre ya con
        // `unwrap_or_else(|e| e.into_inner())` precisamente por esto.
        let futuro = &mut self.get_mut().futuro;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| futuro.as_mut().poll(cx))) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(v)) => Poll::Ready(Ok(v)),
            Err(carga) => Poll::Ready(Err(carga)),
        }
    }
}

/// Nombre único y corto para el directorio de control de una fase. No
/// hace falta un UUID de verdad (no hay ninguna propiedad criptográfica
/// que sostener aquí): basta con que dos fases de este mismo proceso, o
/// de dos procesos a la vez, no compartan directorio.
#[cfg(target_os = "macos")]
fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{nanos:x}-{}", std::process::id())
}

/// El cuerpo de la fase, ya con el privilegio decidido y el trabajador
/// (si lo hay) en marcha. Separado de `ejecutar_fase` para que el
/// arranque y la parada del trabajador queden en un solo sitio, con el
/// `?` de dentro sin poder saltarse la parada -- y, desde que se envuelve
/// en `AtrapaPanico`, tampoco un pánico de dentro.
#[allow(clippy::too_many_arguments)]
async fn ejecutar_fase_interna(
    state: &AppState,
    registro: &[Box<dyn ToolAdapter>],
    fase: Phase,
    tool_id: &str,
    objetivos_crudos: &[String],
    privilegio_disponible: bool,
    trabajador: &Option<crate::privilege::TrabajadorActivo>,
    opciones: &PhaseOptions,
    cancelar: CancellationToken,
    on_suceso: &mut (impl FnMut(SucesoRun) + Send + 'static),
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
            trabajador,
            cancelar.clone(),
            on_suceso,
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
    trabajador: &Option<crate::privilege::TrabajadorActivo>,
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
    // La única diferencia entre los dos caminos es QUÉ función lanza el
    // proceso. `ejecutar_privilegiado` devuelve exactamente la misma
    // forma que `exec::ejecutar` (`ResultadoEjecucion`, con las mismas
    // reglas para `cancelado` y `exit_code`), así que nada de lo que
    // viene después -- el crudo, el sha, el status, el parseo, el
    // recuento -- distingue una fase elevada de una que no lo está.
    let resultado = if let Some(t) = trabajador {
        crate::privilege::ejecutar_privilegiado(
            t,
            seq,
            &binario,
            &invocacion.argv,
            timeout,
            cancelar,
            &mut on_linea,
        )
        .await?
    } else {
        exec::ejecutar(&binario, &invocacion.argv, timeout, cancelar, &mut on_linea).await?
    };

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AppError;

    #[tokio::test]
    async fn atrapa_panico_deja_pasar_los_dos_finales_normales() {
        // Los mismos dos finales que distingue el vigía de `lib.rs`: el
        // `Err` del futuro NO es un pánico y tiene que llegar entero.
        let bien = AtrapaPanico::nuevo(async { Ok::<(), AppError>(()) }).await;
        assert!(matches!(bien, Ok(Ok(()))));

        let mal = AtrapaPanico::nuevo(async { Err::<(), _>(AppError::RunAlreadyActive) }).await;
        assert!(matches!(mal, Ok(Err(AppError::RunAlreadyActive))));
    }

    /// (La traza de pánico que escupe la salida del test es la de la
    /// tarea que se desenrolla a propósito: es lo que se está probando.)
    #[tokio::test]
    async fn atrapa_panico_convierte_el_desenrollado_en_un_err() {
        // El pánico ocurre DESPUÉS de un `.await`, que es donde ocurre de
        // verdad -- `adaptador.parse()` corre ya bien entrada la fase --
        // y lo que obliga a que el `catch_unwind` esté dentro del `poll`
        // y no alrededor de construir el futuro.
        let atrapado = AtrapaPanico::nuevo(async {
            tokio::task::yield_now().await;
            panic!("adaptador.parse() sobre salida no confiable");
        })
        .await;

        assert!(
            atrapado.is_err(),
            "el pánico tiene que llegar como carga, no llevarse por delante \
             a quien espera el futuro"
        );
    }

    /// El bug que motiva todo esto: un pánico en el cuerpo de la fase
    /// saltándose la parada del trabajador elevado. Sin `AtrapaPanico`,
    /// `ejecutar_fase` se desenrollaba, `trabajador` se dejaba caer sin
    /// `Drop` que valiera, y el proceso root seguía sondeando su
    /// directorio de control para siempre.
    ///
    /// Se ejercita el mecanismo de verdad -- `AtrapaPanico` + `cerrar_fase`,
    /// las dos piezas reales de `ejecutar_fase` --, con un trabajador de
    /// verdad arrancado por el camino de pruebas (sin `osascript` ni
    /// root, igual que en `tests/privilege_lifecycle.rs`) y un cuerpo de
    /// fase de mentira que solo sabe entrar en pánico. Lo único que no se
    /// puede meter aquí es la fase entera: `adaptador.parse()` no es
    /// inyectable, el registro de adaptadores es fijo.
    ///
    /// Se corre dentro de un `spawn` porque `cerrar_fase` RELANZA el
    /// pánico a propósito: el `JoinHandle` es la forma de comprobar que
    /// sigue su camino en vez de quedar tragado.
    #[tokio::test]
    async fn un_panico_en_el_cuerpo_de_la_fase_no_se_salta_la_parada_del_trabajador() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().to_path_buf();

        let bucle = tokio::spawn({
            let ruta = ruta.clone();
            async move { crate::worker::ejecutar_bucle(ruta).await.unwrap() }
        });
        for _ in 0..50 {
            if crate::privilege::leer_listo(&ruta).unwrap().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            crate::privilege::leer_listo(&ruta).unwrap().is_some(),
            "el trabajador de prueba no llegó a arrancar"
        );

        let trabajador = Some(crate::privilege::TrabajadorActivo::para_pruebas(
            ruta.clone(),
        ));
        let ruta_para_fase = ruta.clone();
        let tarea = tokio::spawn(async move {
            let resultado = AtrapaPanico::nuevo(async move {
                // El cuerpo llega a hablar con el trabajador antes de
                // reventar: así el pánico ocurre con un trabajador de
                // verdad a medio usar, no con uno recién arrancado.
                assert!(!crate::privilege::hay_detener(&ruta_para_fase));
                tokio::task::yield_now().await;
                panic!("adaptador.parse() sobre salida no confiable");
            })
            .await;
            cerrar_fase(resultado, trabajador).await
        });

        let error = tarea
            .await
            .expect_err("cerrar_fase tiene que relanzar el pánico, no tragárselo");
        assert!(
            error.is_panic(),
            "el pánico original sigue su camino: tragárselo escondería un bug \
             de verdad y dejaría al vigía de lib.rs sin nada que ver"
        );

        assert!(
            crate::privilege::hay_detener(&ruta),
            "la parada tiene que haber corrido pese al pánico: sin el \
             centinela, el proceso root sondea su directorio para siempre"
        );
        tokio::time::timeout(Duration::from_secs(5), bucle)
            .await
            .expect("el trabajador tenía que haber visto el centinela y salido")
            .unwrap();
    }

    /// El otro lado de `cerrar_fase`, que el pánico no puede tapar: sin
    /// pánico se conserva lo que ya hacía la parada -- corre igual, y su
    /// error solo se propaga cuando la fase fue bien.
    #[tokio::test]
    async fn cerrar_fase_sin_panico_para_igual_y_conserva_el_error_de_la_fase() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().to_path_buf();
        let trabajador = Some(crate::privilege::TrabajadorActivo::para_pruebas(
            ruta.clone(),
        ));

        let devuelto = cerrar_fase(Ok(Err(AppError::RunAlreadyActive)), trabajador).await;

        assert!(matches!(devuelto, Err(AppError::RunAlreadyActive)));
        assert!(crate::privilege::hay_detener(&ruta));
    }
}
