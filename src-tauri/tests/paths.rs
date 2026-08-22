use auscan_lib::paths;
use std::path::Path;

const ROOT: &str = "/tmp/auscan-test-root";
const VALID: &str = "7f3a4c2e-0b1d-4e5f-8a9b-1c2d3e4f5a6b";

#[test]
fn engagement_dir_cuelga_de_engagements() {
    let root = Path::new(ROOT);
    let dir = paths::engagement_dir(root, VALID).expect("uuid válido");
    assert_eq!(dir, paths::engagements_dir(root).join(VALID));
    assert!(dir.starts_with(paths::engagements_dir(root)));
}

#[test]
fn rechaza_travesia_de_directorios() {
    let root = Path::new(ROOT);
    for malicioso in ["../../etc", "..", "/etc/passwd", "7f3a/../..", ""] {
        assert!(
            paths::engagement_dir(root, malicioso).is_err(),
            "debería rechazar {malicioso:?}"
        );
    }
}

#[test]
fn rechaza_uuid_malformado() {
    let root = Path::new(ROOT);
    assert!(paths::engagement_dir(root, "no-soy-un-uuid").is_err());
}

#[test]
fn index_db_esta_en_la_raiz() {
    assert_eq!(
        paths::index_db_path(Path::new(ROOT)),
        Path::new(ROOT).join("index.db")
    );
}

#[test]
fn raw_dir_cuelga_del_engagement() {
    let root = Path::new(ROOT);
    let raw = paths::raw_dir(root, VALID).unwrap();
    assert_eq!(raw, paths::engagement_dir(root, VALID).unwrap().join("raw"));
}
