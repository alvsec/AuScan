use auscan_lib::{db, engagement, paths};

#[test]
fn purge_borra_el_directorio_entero() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let e = engagement::create(root, "CLAVEL").unwrap();

    // Simular trabajo hecho: un fichero en raw/ y datos en la base.
    let raw = paths::raw_dir(root, &e.id).unwrap();
    std::fs::write(raw.join("0001-nmap-sn.xml"), b"<nmaprun/>").unwrap();
    {
        let conn = engagement::open(root, &e.id).unwrap();
        conn.execute(
            "INSERT INTO host (ip, state) VALUES ('198.51.100.5','up')",
            [],
        )
        .unwrap();
    }

    let ruta = paths::engagement_dir(root, &e.id).unwrap();
    assert!(ruta.exists());

    engagement::purge(root, &e.id).unwrap();

    assert!(
        !ruta.exists(),
        "el directorio del engagement debe desaparecer"
    );
}

#[test]
fn purge_no_deja_ficheros_wal_ni_shm() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let e = engagement::create(root, "CLAVEL").unwrap();
    {
        let conn = engagement::open(root, &e.id).unwrap();
        conn.execute(
            "INSERT INTO host (ip, state) VALUES ('198.51.100.9','up')",
            [],
        )
        .unwrap();
    }
    engagement::purge(root, &e.id).unwrap();

    let restos: Vec<_> = walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|x| x.ok())
        .map(|x| x.path().display().to_string())
        .filter(|p| p.contains(&e.id))
        .collect();
    assert!(restos.is_empty(), "quedan restos: {restos:?}");
}

#[test]
fn purge_deja_lapida_en_el_indice() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let e = engagement::create(root, "CLAVEL").unwrap();

    let lapida = engagement::purge(root, &e.id).unwrap();

    assert_eq!(lapida.id, e.id);
    assert_eq!(lapida.codename, "CLAVEL");
    assert_eq!(lapida.state, "purged");
    assert!(
        lapida.purged_at.is_some(),
        "debe registrarse cuándo se purgó"
    );

    // Y sigue apareciendo al listar: la lápida es visible a propósito.
    let l = engagement::list(root).unwrap();
    assert_eq!(l.len(), 1);
    assert_eq!(l[0].state, "purged");
}

#[test]
fn purge_es_idempotente() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let e = engagement::create(root, "CLAVEL").unwrap();
    engagement::purge(root, &e.id).unwrap();
    let segunda = engagement::purge(root, &e.id).unwrap();
    assert_eq!(segunda.state, "purged");
}

#[test]
fn purge_no_toca_a_los_demas_engagements() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let a = engagement::create(root, "UNO").unwrap();
    let b = engagement::create(root, "DOS").unwrap();

    engagement::purge(root, &a.id).unwrap();

    assert!(!paths::engagement_dir(root, &a.id).unwrap().exists());
    assert!(paths::engagement_dir(root, &b.id).unwrap().is_dir());
    assert!(engagement::open(root, &b.id).is_ok());
}

#[test]
fn purge_de_un_id_invalido_falla_sin_borrar_nada() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let e = engagement::create(root, "CLAVEL").unwrap();

    assert!(engagement::purge(root, "../..").is_err());
    assert!(engagement::purge(root, "no-soy-un-uuid").is_err());

    assert!(paths::engagement_dir(root, &e.id).unwrap().is_dir());
    let _ = db::open_index(root).unwrap();
}

#[test]
fn canonical_id_normaliza_las_cuatro_codificaciones() {
    let esperado = "7f3a4c2e-0b1d-4e5f-8a9b-1c2d3e4f5a6b";
    for forma in [
        "7f3a4c2e-0b1d-4e5f-8a9b-1c2d3e4f5a6b",
        "7F3A4C2E-0B1D-4E5F-8A9B-1C2D3E4F5A6B",
        "7f3a4c2e0b1d4e5f8a9b1c2d3e4f5a6b",
        "{7f3a4c2e-0b1d-4e5f-8a9b-1c2d3e4f5a6b}",
        "urn:uuid:7f3a4c2e-0b1d-4e5f-8a9b-1c2d3e4f5a6b",
    ] {
        assert_eq!(
            engagement::canonical_id(forma).unwrap(),
            esperado,
            "{forma} debería canonicalizarse"
        );
    }
    assert!(engagement::canonical_id("../..").is_err());
    assert!(engagement::canonical_id("no-soy-un-uuid").is_err());
}

#[test]
fn purgar_con_otra_codificacion_del_mismo_id_deja_lapida() {
    // Regresión: la ruta se canonicalizaba pero la comparación con el
    // engagement abierto y el UPDATE del índice usaban la cadena cruda. Con
    // el identificador en mayúsculas y llaves se borraba el directorio, no
    // se cerraba la conexión y no se escribía la lápida: el índice seguía
    // diciendo 'draft' sobre datos que ya no existían.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let e = engagement::create(root, "CLAVEL").unwrap();

    let disfrazado = format!("{{{}}}", e.id.to_uppercase());
    assert_eq!(engagement::canonical_id(&disfrazado).unwrap(), e.id);

    // Se pasa la forma disfrazada DIRECTAMENTE a purge, sin canonicalizar
    // antes: así el test ejercita el sitio real donde estaba el bug
    // (dentro de la función, no en la frontera de comandos que la llama).
    let lapida = engagement::purge(root, &disfrazado).unwrap();
    assert_eq!(lapida.state, "purged");
    assert!(lapida.purged_at.is_some());
    assert!(!paths::engagement_dir(root, &e.id).unwrap().exists());
}

#[test]
fn si_falla_el_alta_en_el_indice_no_queda_directorio_huerfano() {
    // El índice se corrompe a propósito para forzar el fallo del INSERT.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    engagement::create(root, "PRIMERO").unwrap();
    std::fs::write(paths::index_db_path(root), b"esto no es una base sqlite").unwrap();
    for sufijo in ["-wal", "-shm"] {
        let p = paths::index_db_path(root).with_extension(format!("db{sufijo}"));
        let _ = std::fs::remove_file(p);
    }

    let antes = std::fs::read_dir(paths::engagements_dir(root))
        .unwrap()
        .count();
    let r = engagement::create(root, "SEGUNDO");
    assert!(r.is_err(), "con el índice roto, create debe fallar");
    let despues = std::fs::read_dir(paths::engagements_dir(root))
        .unwrap()
        .count();
    assert_eq!(
        antes, despues,
        "no debe quedar un directorio sin referencia"
    );
}

#[test]
fn si_falla_db_open_no_queda_directorio_huerfano() {
    // A diferencia del test de arriba (que fuerza el fallo en el ÚLTIMO
    // paso, el alta en el índice), este fabrica un choque en un paso
    // intermedio: un UUID controlado permite preparar de antemano un
    // directorio donde db::open espera abrir un fichero, algo que un
    // Uuid::new_v4() aleatorio no deja reproducir. Es la regresión real:
    // en la versión anterior de create(), solo el fallo del índice tenía
    // limpieza — create_dir_all, db::open y db::migrate estaban fuera de
    // cualquier closure de limpieza, así que un fallo ahí dejaba el
    // directorio huérfano para siempre, invisible desde list() y por
    // tanto imposible de purgar desde la UI.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let id = "11111111-1111-1111-1111-111111111111";

    // raw/ ya existe: create_dir_all lo verá como éxito (es idempotente).
    std::fs::create_dir_all(paths::raw_dir(root, id).unwrap()).unwrap();
    // engagement.db es un DIRECTORIO, no un fichero: db::open no puede
    // abrir una base de datos ahí y falla.
    std::fs::create_dir_all(paths::engagement_db_path(root, id).unwrap()).unwrap();

    let r = engagement::create_with_id(root, "CLAVEL", id);
    assert!(r.is_err(), "db::open debe fallar sobre un directorio");

    assert!(
        !paths::engagement_dir(root, id).unwrap().exists(),
        "el directorio fabricado para forzar el fallo debe quedar limpio"
    );
    assert!(
        engagement::list(root).unwrap().is_empty(),
        "no debe quedar ninguna fila en el índice"
    );
}
