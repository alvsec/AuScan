use auscan_lib::scope;
use std::net::IpAddr;

#[test]
fn acepta_redes_canonicas() {
    for s in [
        "198.51.100.0/24",
        "192.0.2.0/25",
        "2001:db8::/32",
        "203.0.113.7",
    ] {
        assert!(scope::parse_entry(s).is_ok(), "debería aceptar {s}");
    }
}

#[test]
fn rechaza_cidr_con_bits_de_host() {
    for s in ["198.51.100.5/24", "192.0.2.130/25", "2001:db8::1/32"] {
        let e = scope::parse_entry(s).unwrap_err();
        assert!(
            matches!(e, auscan_lib::error::AppError::AmbiguousCidr(_)),
            "{s} debería ser ambiguo, fue {e:?}"
        );
    }
}

#[test]
fn rechaza_basura() {
    for s in ["", "   ", "no-soy-una-red", "198.51.100.0/33", "999.1.1.1"] {
        assert!(scope::parse_entry(s).is_err(), "debería rechazar {s:?}");
    }
}

#[test]
fn una_ip_suelta_se_convierte_en_prefijo_completo() {
    let n = scope::parse_entry("203.0.113.7").unwrap();
    assert_eq!(n.prefix_len(), 32);
    let n6 = scope::parse_entry("2001:db8::1").unwrap();
    assert_eq!(n6.prefix_len(), 128);
}

#[test]
fn las_v4_mapeadas_se_canonicalizan_a_v4() {
    let mapeada: IpAddr = "::ffff:198.51.100.5".parse().unwrap();
    assert_eq!(
        scope::canonical_ip(mapeada),
        "198.51.100.5".parse::<IpAddr>().unwrap()
    );
}

#[test]
fn family_of_distingue_las_dos_familias() {
    assert_eq!(
        scope::family_of(&scope::parse_entry("198.51.100.0/24").unwrap()),
        "v4"
    );
    assert_eq!(
        scope::family_of(&scope::parse_entry("2001:db8::/32").unwrap()),
        "v6"
    );
}

#[test]
fn una_red_v4_mapeada_se_canonicaliza_a_red_v4() {
    let n = scope::parse_entry("::ffff:192.0.2.0/120").unwrap();
    assert_eq!(scope::family_of(&n), "v4", "debe quedar como red v4, no v6");
    assert_eq!(n.prefix_len(), 24, "/120 mapeado es /24 en v4");
    assert_eq!(n.to_string(), "192.0.2.0/24");
}

#[test]
fn una_red_mapeada_que_desborda_el_rango_se_rechaza() {
    // Con prefijo < 96 la red se sale del rango mapeado y no representa
    // ninguna red v4: recortarla en silencio sería adivinar.
    assert!(scope::parse_entry("::ffff:192.0.2.0/64").is_err());
}

#[test]
fn los_bits_de_host_se_detectan_tambien_en_notacion_mapeada() {
    let e = scope::parse_entry("::ffff:192.0.2.65/120").unwrap_err();
    assert!(matches!(e, auscan_lib::error::AppError::AmbiguousCidr(_)));
}
