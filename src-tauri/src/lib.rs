pub mod db;
pub mod engagement;
pub mod error;
pub mod paths;
pub mod scope;
pub mod state;

use tauri::{Manager, State};

use engagement::EngagementRef;
use error::Result;
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
    // El lock se sostiene durante todo el trabajo de disco. Si se soltara,
    // una purga concurrente podría borrar el directorio entre la
    // comprobación de existencia y la apertura, y db::open lo recrearía
    // justo después de que la purga verificase que ya no estaba.
    let mut guard = state.open.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
    let conn = engagement::open(&state.root, &id)?;
    let referencia = engagement::get(&state.root, &id)?;
    *guard = Some(OpenEngagement { id, conn });
    Ok(referencia)
}

#[tauri::command]
fn engagement_purge(state: State<AppState>, id: String) -> Result<EngagementRef> {
    let id = engagement::canonical_id(&id)?;
    // Se cierra siempre, sin comparar identificadores: hay como mucho un
    // engagement abierto, y conservar el descriptor de otro no aporta nada
    // frente al riesgo de borrar con un fichero abierto (en Windows
    // directamente falla). El lock se sostiene hasta escribir la lápida.
    let mut guard = state.open.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
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
        ])
        .run(tauri::generate_context!())
        .expect("error al arrancar AUscan");
}
