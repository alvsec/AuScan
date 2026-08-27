pub mod adapters;
pub mod db;
pub mod engagement;
pub mod error;
pub mod exec;
pub mod gen_fixtures;
pub mod orchestrator;
pub mod paths;
pub mod preflight;
pub mod runs;
pub mod scope;
pub mod state;

use tauri::Emitter;
use tauri::{Manager, State};
use tokio_util::sync::CancellationToken;

use adapters::{Phase, PhaseOptions};
use engagement::EngagementRef;
use error::Result;
use orchestrator::SucesoRun;
use scope::{ScopeEntry, ScopeKind};
use state::{AppState, OpenEngagement};

#[tauri::command]
fn engagement_create(state: State<AppState>, codename: String) -> Result<EngagementRef> {
    engagement::create(&state.root, &codename)
}

#[tauri::command]
fn engagement_list(state: State<AppState>) -> Result<Vec<EngagementRef>> {
    engagement::list(&state.root)
}

#[tauri::command]
fn engagement_open(state: State<AppState>, id: String) -> Result<EngagementRef> {
    let id = engagement::canonical_id(&id)?;
    // El lock se sostiene durante todo el trabajo de disco: si se soltara,
    // una purga concurrente podría borrar el directorio entre la
    // comprobación de existencia y la apertura, y db::open lo recrearía
    // justo después de que la purga verificase que ya no estaba.
    //
    // No se limpia el hueco al entrar: si ya había un engagement A abierto
    // y esta llamada abre B pero falla, A debe seguir abierto. Limpiar
    // primero dejaría al frontend creyendo que A sigue activo mientras el
    // backend ya no tiene ninguna conexión.
    let mut guard = state.open.lock().unwrap_or_else(|e| e.into_inner());
    let conn = engagement::open(&state.root, &id)?;
    let referencia = engagement::get(&state.root, &id)?;
    *guard = Some(OpenEngagement { id, conn });
    Ok(referencia)
}

#[tauri::command]
fn engagement_purge(state: State<AppState>, id: String) -> Result<EngagementRef> {
    let id = engagement::canonical_id(&id)?;
    // El lock se sostiene durante todo el trabajo de disco, por la misma
    // razón que en engagement_open. Solo se cierra la conexión si es la
    // del engagement que se está purgando: purgar B mientras A está
    // abierto no debe dejar a A con su conexión cerrada mientras el
    // frontend sigue mostrándolo como activo. Como ambos lados llegan ya
    // canonicalizados, la comparación es fiable sin importar en qué
    // codificación llegó cada identificador.
    let mut guard = state.open.lock().unwrap_or_else(|e| e.into_inner());
    if guard.as_ref().is_some_and(|o| o.id == id) {
        *guard = None;
    }
    engagement::purge(&state.root, &id)
}

#[tauri::command]
fn scope_list(state: State<AppState>) -> Result<Vec<ScopeEntry>> {
    state.with_open(scope::list_entries)
}

#[tauri::command]
fn scope_add(
    state: State<AppState>,
    kind: ScopeKind,
    entry: String,
    note: Option<String>,
) -> Result<ScopeEntry> {
    state.with_open(|c| scope::add_entry(c, kind, &entry, note.as_deref()))
}

#[tauri::command]
fn scope_remove(state: State<AppState>, id: i64) -> Result<()> {
    state.with_open(|c| scope::remove_entry(c, id))
}

/// Comprueba un objetivo contra el alcance vigente.
///
/// Acepta SOLO direcciones literales, no nombres. Resolver aquí convertiría
/// este comando en un oráculo de DNS: cualquier cadena que llegue de la
/// webview saldría a la red en una consulta antes de que el alcance tenga
/// nada que decir, y el error posterior haría que todo pareciese normal.
/// La resolución de nombres vive en `Scope::validate_target` y se usará al
/// lanzar una ejecución, que es un acto explícito del operador.
#[tauri::command]
fn scope_check(state: State<AppState>, target: String) -> Result<Vec<String>> {
    state.with_open(|c| {
        let s = scope::load(c)?;
        Ok(vec![s.validate(&target)?.to_string()])
    })
}

#[tauri::command]
fn preflight_run() -> preflight::PreflightReport {
    preflight::run_preflight(&adapters::registry())
}

#[tauri::command]
fn preflight_install(tool_id: String) -> Result<String> {
    let registro = adapters::registry();
    let adaptador = registro
        .iter()
        .find(|a| a.descriptor().id == tool_id)
        .ok_or_else(|| error::AppError::ToolNotFound(tool_id.clone()))?;
    let salida = preflight::run_install(
        &adaptador.descriptor().install_hint,
        preflight::current_platform(),
    )?;
    preflight::interpret_install_output(&tool_id, salida)
}

fn fase_desde_str(s: &str) -> Result<Phase> {
    match s {
        "discovery" => Ok(Phase::Discovery),
        "portsweep" => Ok(Phase::PortSweep),
        "services" => Ok(Phase::Services),
        _ => Err(error::AppError::ToolNotFound(format!(
            "fase desconocida: {s}"
        ))),
    }
}

#[tauri::command]
async fn run_start(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    phase: String,
    tool_id: String,
    targets: Vec<String>,
) -> Result<()> {
    let fase = fase_desde_str(&phase)?;
    let cancelar = CancellationToken::new();
    *state
        .ejecucion_activa
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(cancelar.clone());

    // El privilegio real lo calcula el comando, nunca el frontend: si
    // `privileged` llegase como argumento de `invoke`, cualquier llamador
    // -- o un bug de la propia UI -- podría declararse privilegiado sin
    // que el proceso lo esté de verdad, reabriendo con el frontend el
    // hueco que la Task 1 cerró para los adaptadores.
    let privileged = preflight::running_privileged();
    let opciones = PhaseOptions::default();

    // `state: State<'_, AppState>` no sobrevive dentro de la tarea
    // `spawn`eada: su lifetime está atado a esta llamada de comando, que
    // vuelve antes de que la tarea termine. `app: AppHandle` sí es
    // `Clone + Send + 'static` -- se mueve entero dentro del bloque y
    // `app.state::<AppState>()` se vuelve a pedir AHÍ DENTRO, nunca antes.
    tauri::async_runtime::spawn(async move {
        let registro = adapters::registry();
        let state_interna = app.state::<AppState>();
        let app_para_eventos = app.clone();
        let resultado = orchestrator::ejecutar_fase(
            state_interna.inner(),
            &registro,
            fase,
            &tool_id,
            &targets,
            privileged,
            &opciones,
            cancelar,
            move |suceso| {
                let _ = match suceso {
                    SucesoRun::Log { origen, texto } => app_para_eventos.emit(
                        "run:log",
                        serde_json::json!({
                            "origen": match origen {
                                exec::LineaOrigen::Stdout => "stdout",
                                exec::LineaOrigen::Stderr => "stderr",
                            },
                            "texto": texto,
                        }),
                    ),
                    SucesoRun::RunTerminado { seq, status } => app_para_eventos.emit(
                        "run:done",
                        serde_json::json!({ "seq": seq, "status": status }),
                    ),
                    SucesoRun::FaseTerminada => app_para_eventos.emit("run:fase-terminada", ()),
                };
            },
        )
        .await;
        if let Err(e) = resultado {
            let _ = app.emit(
                "run:log",
                serde_json::json!({ "origen": "stderr", "texto": e.to_string() }),
            );
        }
    });

    Ok(())
}

#[tauri::command]
fn run_cancel(state: State<AppState>) -> Result<()> {
    let guard = state
        .ejecucion_activa
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(token) = guard.as_ref() {
        token.cancel();
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let root = app.path().app_data_dir()?;
            std::fs::create_dir_all(&root)?;
            app.manage(AppState::new(root));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            engagement_create,
            engagement_list,
            engagement_open,
            engagement_purge,
            scope_list,
            scope_add,
            scope_remove,
            scope_check,
            preflight_run,
            preflight_install,
            run_start,
            run_cancel,
        ])
        .run(tauri::generate_context!())
        .expect("error al arrancar AUscan");
}
