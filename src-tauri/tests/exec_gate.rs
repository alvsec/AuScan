use auscan_lib::error::AppError;
use auscan_lib::exec::validate_targets;
use auscan_lib::scope::{Scope, ScopeKind};

fn objetivos(scope: &Scope, ips: &[&str]) -> Vec<auscan_lib::scope::ScopedTarget> {
    ips.iter().map(|ip| scope.validate(ip).unwrap()).collect()
}

fn scope_198() -> Scope {
    Scope::from_entries(&[(ScopeKind::Allow, "198.51.100.0/24".to_string())]).unwrap()
}

#[test]
fn acepta_argv_cuyas_ips_estan_todas_en_targets() {
    let scope = scope_198();
    let targets = objetivos(&scope, &["198.51.100.5", "198.51.100.9"]);
    let argv = vec![
        "-sn".to_string(),
        "198.51.100.5".to_string(),
        "198.51.100.9".to_string(),
    ];
    assert!(validate_targets(&argv, &targets).is_ok());
}

#[test]
fn rechaza_una_ip_en_argv_que_no_esta_en_targets() {
    let scope = scope_198();
    let targets = objetivos(&scope, &["198.51.100.5"]);
    // 198.51.100.9 nunca pasó por el guard: un adaptador que la
    // interpolase a mano no debe poder colarla.
    let argv = vec!["198.51.100.5".to_string(), "198.51.100.9".to_string()];
    assert!(matches!(
        validate_targets(&argv, &targets),
        Err(AppError::UnvalidatedTarget(_))
    ));
}

#[test]
fn rechaza_una_forma_cidr_aunque_alguna_ip_individual_este_autorizada() {
    let scope = scope_198();
    let targets = objetivos(&scope, &["198.51.100.5"]);
    // ScopedTarget nunca lleva rango: un token con esta forma es un
    // intento de escanear más de lo que el guard validó.
    let argv = vec!["198.51.100.0/24".to_string()];
    assert!(matches!(
        validate_targets(&argv, &targets),
        Err(AppError::UnvalidatedTarget(_))
    ));
}

#[test]
fn ignora_tokens_que_no_son_direcciones() {
    let scope = scope_198();
    let targets = objetivos(&scope, &["198.51.100.5"]);
    let argv = vec![
        "-sn".to_string(),
        "-PS80,443,22".to_string(),
        "198.51.100.5".to_string(),
    ];
    assert!(validate_targets(&argv, &targets).is_ok());
}

#[test]
fn un_argv_vacio_de_objetivos_pasa_trivialmente() {
    let targets: Vec<auscan_lib::scope::ScopedTarget> = vec![];
    assert!(validate_targets(&["-sn".to_string()], &targets).is_ok());
}

#[test]
fn recorta_espacios_antes_de_reconocer_una_ip() {
    let scope = scope_198();
    let targets = objetivos(&scope, &["198.51.100.5"]);
    let argv = vec![" 198.51.100.5 ".to_string()];
    assert!(
        validate_targets(&argv, &targets).is_ok(),
        "una IP autorizada con espacios alrededor debe seguir reconociéndose como tal"
    );
}
