use auscan_lib::error::AppError;
use auscan_lib::scope::{Scope, ScopeKind};

fn scope(allow: &[&str], deny: &[&str]) -> Scope {
    let mut e: Vec<(ScopeKind, String)> = Vec::new();
    for a in allow {
        e.push((ScopeKind::Allow, (*a).to_string()));
    }
    for d in deny {
        e.push((ScopeKind::Deny, (*d).to_string()));
    }
    Scope::from_entries(&e).unwrap()
}

#[test]
fn los_limites_del_cidr_caen_del_lado_correcto() {
    // El alcance va al centro del bloque de documentación para que los
    // vecinos de ambos lados caigan también dentro de RFC 5737.
    let s = scope(&["198.51.100.64/26"], &[]);
    assert!(
        s.validate("198.51.100.64").is_ok(),
        "la dirección de red está dentro"
    );
    assert!(
        s.validate("198.51.100.127").is_ok(),
        "el broadcast está dentro"
    );
    assert!(
        s.validate("198.51.100.63").is_err(),
        "la anterior está fuera"
    );
    assert!(
        s.validate("198.51.100.128").is_err(),
        "la siguiente está fuera"
    );
}

#[test]
fn deny_gana_sobre_allow_aunque_sea_menos_especifico() {
    let s = scope(&["198.51.100.0/25"], &["198.51.100.0/24"]);
    assert!(
        matches!(s.validate("198.51.100.5"), Err(AppError::OutOfScope(_))),
        "deny gana siempre, sin importar la especificidad"
    );
}

#[test]
fn deny_anidado_dentro_de_allow_recorta_el_alcance() {
    let s = scope(&["198.51.100.0/24"], &["198.51.100.128/25"]);
    assert!(s.validate("198.51.100.127").is_ok());
    assert!(s.validate("198.51.100.128").is_err());
    assert!(s.validate("198.51.100.200").is_err());
}

#[test]
fn un_alcance_sin_allow_rechaza_todo() {
    let vacio = scope(&[], &[]);
    assert!(matches!(
        vacio.validate("198.51.100.5"),
        Err(AppError::EmptyScope)
    ));

    // Aunque haya exclusiones: sin autorización explícita no hay nada autorizado.
    let solo_deny = scope(&[], &["198.51.100.0/24"]);
    assert!(matches!(
        solo_deny.validate("203.0.113.9"),
        Err(AppError::EmptyScope)
    ));
}

#[test]
fn ipv6_funciona_igual_en_forma_comprimida_y_expandida() {
    let s = scope(&["2001:db8:a::/48"], &["2001:db8:a:dead::/64"]);
    assert!(s.validate("2001:db8:a::1").is_ok());
    assert!(s
        .validate("2001:0db8:000a:0000:0000:0000:0000:0001")
        .is_ok());
    assert!(s.validate("2001:db8:a:dead::1").is_err());
    assert!(s.validate("2001:db8:b::1").is_err());
}

#[test]
fn una_v4_mapeada_se_juzga_contra_el_alcance_v4() {
    let s = scope(&["192.0.2.0/24"], &[]);
    assert!(
        s.validate("::ffff:192.0.2.65").is_ok(),
        "escrita como v6 mapeada sigue siendo la misma dirección"
    );
    assert!(s.validate("::ffff:203.0.113.1").is_err());
}

#[test]
fn un_alcance_v4_no_autoriza_direcciones_v6() {
    let s = scope(&["192.0.2.0/24"], &[]);
    assert!(s.validate("2001:db8::1").is_err());
}

#[test]
fn lo_que_no_es_una_direccion_se_rechaza_como_invalido() {
    let s = scope(&["198.51.100.0/24"], &[]);
    for basura in ["", "  ", "no-soy-una-ip", "198.51.100.5/24", "198.51.100"] {
        assert!(
            matches!(s.validate(basura), Err(AppError::InvalidAddress(_))),
            "{basura:?} debería ser inválido"
        );
    }
}

#[test]
fn el_objetivo_validado_conserva_la_direccion_canonica() {
    let s = scope(&["192.0.2.0/24"], &[]);
    let t = s.validate("::ffff:192.0.2.65").unwrap();
    assert_eq!(
        t.to_string(),
        "192.0.2.65",
        "se pasa a la herramienta ya canónica"
    );
}

#[test]
fn un_deny_escrito_en_notacion_mapeada_excluye_de_verdad() {
    // Regresión: antes, la rama CIDR de parse_entry no canonicalizaba, así
    // que este deny se guardaba como red v6 y no excluía nada — contains()
    // entre familias distintas es siempre false. Un deny inerte es el peor
    // fallo posible en esta pieza: dice "dentro de alcance" cuando el
    // consultor había escrito explícitamente que no.
    let s = scope(&["192.0.2.0/24"], &["::ffff:192.0.2.64/122"]);
    assert!(
        s.validate("192.0.2.1").is_ok(),
        "fuera del deny, sigue autorizado"
    );
    assert!(
        matches!(s.validate("192.0.2.65"), Err(AppError::OutOfScope(_))),
        "el deny en notación mapeada debe excluir la dirección v4"
    );
}

#[test]
fn un_allow_escrito_en_notacion_mapeada_autoriza_de_verdad() {
    let s = scope(&["::ffff:198.51.100.0/120"], &[]);
    assert!(s.validate("198.51.100.9").is_ok());
    assert!(s.validate("203.0.113.9").is_err());
}
