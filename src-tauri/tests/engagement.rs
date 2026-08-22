use auscan_lib::{engagement, paths};

#[test]
fn create_deja_directorio_base_y_fila_en_el_indice() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let e = engagement::create(root, "CLAVEL").unwrap();

    assert_eq!(e.codename, "CLAVEL");
    assert_eq!(e.state, "draft");
    assert!(e.purged_at.is_none());

    assert!(paths::engagement_dir(root, &e.id).unwrap().is_dir());
    assert!(paths::engagement_db_path(root, &e.id).unwrap().is_file());
    assert!(paths::raw_dir(root, &e.id).unwrap().is_dir());

    let listados = engagement::list(root).unwrap();
    assert_eq!(listados.len(), 1);
    assert_eq!(listados[0].id, e.id);
}

#[test]
fn el_indice_no_guarda_nada_que_identifique_al_cliente() {
    let dir = tempfile::tempdir().unwrap();
    let conn = auscan_lib::db::open_index(dir.path()).unwrap();
    let mut st = conn.prepare("PRAGMA table_info(engagement_ref)").unwrap();
    let cols: Vec<String> = st
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    let mut esperadas = vec!["id", "codename", "created_at", "state", "purged_at"];
    esperadas.sort();
    let mut reales: Vec<&str> = cols.iter().map(String::as_str).collect();
    reales.sort();
    assert_eq!(reales, esperadas,
        "index.db solo puede contener estas columnas: alcance, autorizante y \
         ruta de exportación viven dentro del engagement y mueren con él");
}

#[test]
fn el_engagement_db_trae_su_esquema_migrado() {
    let dir = tempfile::tempdir().unwrap();
    let e = engagement::create(dir.path(), "ROMERO").unwrap();
    let conn = engagement::open(dir.path(), &e.id).unwrap();
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='observation'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1);
}

#[test]
fn engagement_db_tiene_su_propia_fila_de_engagement() {
    let dir = tempfile::tempdir().unwrap();
    let e = engagement::create(dir.path(), "ROMERO").unwrap();
    let conn = engagement::open(dir.path(), &e.id).unwrap();
    let (id, codename): (String, String) = conn
        .query_row("SELECT id, codename FROM engagement", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(id, e.id);
    assert_eq!(codename, "ROMERO");
}

#[test]
fn list_devuelve_del_mas_reciente_al_mas_antiguo() {
    let dir = tempfile::tempdir().unwrap();
    let a = engagement::create(dir.path(), "UNO").unwrap();
    let b = engagement::create(dir.path(), "DOS").unwrap();
    let l = engagement::list(dir.path()).unwrap();
    assert_eq!(l.len(), 2);
    assert!(l.iter().any(|e| e.id == a.id));
    assert!(l.iter().any(|e| e.id == b.id));
}

#[test]
fn open_de_un_id_inexistente_falla() {
    let dir = tempfile::tempdir().unwrap();
    let inexistente = "7f3a4c2e-0b1d-4e5f-8a9b-1c2d3e4f5a6b";
    assert!(engagement::open(dir.path(), inexistente).is_err());
}

#[test]
fn create_rechaza_un_codename_vacio() {
    let dir = tempfile::tempdir().unwrap();
    assert!(engagement::create(dir.path(), "   ").is_err());
}
