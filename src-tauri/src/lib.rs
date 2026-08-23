pub mod db;
pub mod engagement;
pub mod error;
pub mod paths;
pub mod scope;
pub mod state;

use tauri::{Manager, State};

use engagement::EngagementRef;
use error::Result;
use scope::{ScopeEntry, ScopeKind, SystemResolver};
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
    let conn = engagement::open(&state.root, &id)?;
    let referencia = engagement::get(&state.root, &id)?;
    let mut guard = state.open.lock().expect("mutex envenenado");
    *guard = Some(OpenEngagement { id, conn });
    Ok(referencia)
}

#[tauri::command]
fn engagement_purge(state: State<AppState>, id: String) -> Result<EngagementRef> {
    // Cerrar antes de borrar: en Windows un fichero abierto no se borra.
    {
        let mut guard = state.open.lock().expect("mutex envenenado");
        if guard.as_ref().is_some_and(|o| o.id == id) {
            *guard = None;
        }
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

/// Comprueba un objetivo contra el alcance vigente. Devuelve las IPs
/// autorizadas o un error explicando por qué no.
#[tauri::command]
fn scope_check(state: State<AppState>, target: String) -> Result<Vec<String>> {
    state.with_open(|c| {
        let s = scope::load(c)?;
        let t = s.validate_target(&target, &SystemResolver)?;
        Ok(t.iter().map(ToString::to_string).collect())
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
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
