use auscan_lib::error::AppError;
use auscan_lib::scope::{self, ScopeKind};
use auscan_lib::engagement;

fn engagement_abierto() -> (tempfile::TempDir, rusqlite::Connection) {
    let dir = tempfile::tempdir().unwrap();
    let e = engagement::create(dir.path(), "CLAVEL").unwrap();
    let conn = engagement::open(dir.path(), &e.id).unwrap();
    (dir, conn)
}

#[test]
fn add_entry_guarda_la_forma_canonica_y_la_familia() {
    let (_d, conn) = engagement_abierto();
    let e = scope::add_entry(&conn, ScopeKind::Allow, " 198.51.100.0/24 ", None).unwrap();
    assert_eq!(e.cidr, "198.51.100.0/24", "se guarda ya normalizada y sin espacios");
    assert_eq!(e.family, "v4");
    assert_eq!(e.kind, ScopeKind::Allow);

    let v6 = scope::add_entry(&conn, ScopeKind::Deny, "2001:db8::/32", Some("laboratorio")).unwrap();
    assert_eq!(v6.family, "v6");
    assert_eq!(v6.note.as_deref(), Some("laboratorio"));
}

#[test]
fn add_entry_rechaza_lo_que_el_parser_rechaza() {
    let (_d, conn) = engagement_abierto();
    assert!(scope::add_entry(&conn, ScopeKind::Allow, "198.51.100.5/24", None).is_err());
    assert!(scope::add_entry(&conn, ScopeKind::Allow, "basura", None).is_err());
    assert_eq!(scope::list_entries(&conn).unwrap().len(), 0, "nada se guardó");
}

#[test]
fn un_alcance_que_autoriza_todo_se_rechaza() {
    // Un allow de /0 autoriza internet entero. En una auditoría con
    // autorización escrita eso no es un alcance: es la ausencia de uno.
    let (_d, conn) = engagement_abierto();
    for todo in ["0.0.0.0/0", "::/0"] {
        assert!(
            matches!(scope::parse_entry(todo), Err(AppError::OverbroadScope(_))),
            "{todo} debería rechazarse por demasiado amplio"
        );
        assert!(scope::add_entry(&conn, ScopeKind::Allow, todo, None).is_err());
    }
    // Un prefijo ancho sigue siendo decisión del consultor, no nuestra.
    assert!(scope::parse_entry("198.51.100.0/24").is_ok());
}

#[test]
fn load_reconstruye_un_scope_que_decide_igual() {
    let (_d, conn) = engagement_abierto();
    scope::add_entry(&conn, ScopeKind::Allow, "198.51.100.0/24", None).unwrap();
    scope::add_entry(&conn, ScopeKind::Deny, "198.51.100.128/25", None).unwrap();

    let s = scope::load(&conn).unwrap();
    assert!(s.validate("198.51.100.10").is_ok());
    assert!(s.validate("198.51.100.200").is_err());
}

#[test]
fn load_de_una_base_sin_entradas_da_un_scope_vacio() {
    let (_d, conn) = engagement_abierto();
    let s = scope::load(&conn).unwrap();
    assert!(s.is_empty());
    assert!(s.validate("198.51.100.10").is_err());
}

#[test]
fn remove_entry_reduce_el_alcance() {
    let (_d, conn) = engagement_abierto();
    let a = scope::add_entry(&conn, ScopeKind::Allow, "198.51.100.0/24", None).unwrap();
    assert!(scope::load(&conn).unwrap().validate("198.51.100.10").is_ok());

    scope::remove_entry(&conn, a.id).unwrap();
    assert!(scope::load(&conn).unwrap().validate("198.51.100.10").is_err());
}

#[test]
fn no_se_puede_duplicar_una_entrada() {
    let (_d, conn) = engagement_abierto();
    scope::add_entry(&conn, ScopeKind::Allow, "198.51.100.0/24", None).unwrap();
    assert!(scope::add_entry(&conn, ScopeKind::Allow, "198.51.100.0/24", None).is_err());
}
