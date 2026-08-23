use std::collections::HashMap;
use std::net::IpAddr;

use auscan_lib::error::AppError;
use auscan_lib::scope::{Resolver, Scope, ScopeKind};

struct FakeResolver(HashMap<String, Vec<IpAddr>>);

impl FakeResolver {
    fn con(pares: &[(&str, &[&str])]) -> Self {
        let mut m = HashMap::new();
        for (host, ips) in pares {
            m.insert(
                (*host).to_string(),
                ips.iter().map(|s| s.parse().unwrap()).collect(),
            );
        }
        Self(m)
    }
}

impl Resolver for FakeResolver {
    fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        self.0.get(host).cloned().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "sin registro")
        })
    }
}

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
fn una_ip_literal_no_pasa_por_el_resolver() {
    let s = scope(&["198.51.100.0/24"], &[]);
    let r = FakeResolver::con(&[]);
    let t = s.validate_target("198.51.100.5", &r).unwrap();
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].to_string(), "198.51.100.5");
}

#[test]
fn un_nombre_dentro_de_alcance_se_acepta() {
    let s = scope(&["198.51.100.0/24"], &[]);
    let r = FakeResolver::con(&[("srv.example", &["198.51.100.5"])]);
    let t = s.validate_target("srv.example", &r).unwrap();
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].to_string(), "198.51.100.5");
}

#[test]
fn un_nombre_con_varias_ips_todas_dentro_devuelve_todas() {
    let s = scope(&["198.51.100.0/24"], &[]);
    let r = FakeResolver::con(&[("multi.example", &["198.51.100.5", "198.51.100.6"])]);
    let t = s.validate_target("multi.example", &r).unwrap();
    assert_eq!(t.len(), 2);
}

#[test]
fn si_una_sola_ip_cae_fuera_se_rechaza_el_nombre_entero() {
    let s = scope(&["198.51.100.0/24"], &[]);
    let r = FakeResolver::con(&[("mixto.example", &["198.51.100.5", "203.0.113.9"])]);
    assert!(
        matches!(s.validate_target("mixto.example", &r), Err(AppError::OutOfScope(_))),
        "dentro y fuera a la vez no se resuelve a medias: se rechaza"
    );
}

#[test]
fn un_nombre_que_no_resuelve_falla_con_su_propio_error() {
    let s = scope(&["198.51.100.0/24"], &[]);
    let r = FakeResolver::con(&[]);
    assert!(matches!(
        s.validate_target("fantasma.example", &r),
        Err(AppError::UnresolvableHost(_))
    ));
}

#[test]
fn un_nombre_que_resuelve_a_nada_tambien_falla() {
    let s = scope(&["198.51.100.0/24"], &[]);
    let r = FakeResolver::con(&[("vacio.example", &[])]);
    assert!(matches!(
        s.validate_target("vacio.example", &r),
        Err(AppError::UnresolvableHost(_))
    ));
}
