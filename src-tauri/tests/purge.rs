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

    assert!(!ruta.exists(), "el directorio del engagement debe desaparecer");
}

#[test]
fn purge_no_deja_ficheros_wal_ni_shm() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let e = engagement::create(root, "CLAVEL").unwrap();
    {
        let conn = engagement::open(root, &e.id).unwrap();
        conn.execute("INSERT INTO host (ip, state) VALUES ('198.51.100.9','up')", [])
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
    assert!(lapida.purged_at.is_some(), "debe registrarse cuándo se purgó");

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
