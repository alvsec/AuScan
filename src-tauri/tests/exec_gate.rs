mod common;

use std::path::Path;

use auscan_lib::adapters::ToolAdapter;
use auscan_lib::error::AppError;
use auscan_lib::exec::{validate_binary, validate_flags, validate_targets, verja};
use auscan_lib::scope::{Scope, ScopeKind};
use common::FakeAdapter;

fn objetivos(scope: &Scope, ips: &[&str]) -> Vec<auscan_lib::scope::ScopedTarget> {
    ips.iter().map(|ip| scope.validate(ip).unwrap()).collect()
}

fn scope_198() -> Scope {
    Scope::from_entries(&[(ScopeKind::Allow, "198.51.100.0/24".to_string())]).unwrap()
}

fn descriptor_de_prueba() -> auscan_lib::adapters::ToolDescriptor {
    FakeAdapter.descriptor()
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

#[test]
fn rechaza_una_ip_no_autorizada_aunque_lleve_espacios_alrededor() {
    let scope = scope_198();
    let targets = objetivos(&scope, &["198.51.100.5"]);
    let argv = vec![" 198.51.100.9 ".to_string()];
    assert!(
        validate_targets(&argv, &targets).is_err(),
        "una IP fuera de targets con espacios alrededor debe seguir rechazándose"
    );
}

#[test]
fn acepta_banderas_de_la_lista_sin_privilegio() {
    let d = descriptor_de_prueba();
    let argv = vec!["-t".to_string(), "-p".to_string(), "8080".to_string()];
    assert!(validate_flags(&argv, &d, false).is_ok());
}

#[test]
fn rechaza_una_bandera_fuera_de_la_lista() {
    let d = descriptor_de_prueba();
    let argv = vec!["--script".to_string(), "vuln".to_string()];
    assert!(matches!(
        validate_flags(&argv, &d, false),
        Err(AppError::FlagNotAllowed(_))
    ));
}

#[test]
fn una_bandera_con_needs_privilege_exige_invocacion_privilegiada() {
    let d = descriptor_de_prueba();
    let argv = vec!["-x".to_string()];
    assert!(matches!(
        validate_flags(&argv, &d, false),
        Err(AppError::PrivilegeRequired(_))
    ));
    assert!(validate_flags(&argv, &d, true).is_ok());
}

#[test]
fn una_bandera_de_valor_exige_un_token_separado_para_el_valor() {
    // Nuevo contrato: el valor de una bandera `takes_value` es SIEMPRE
    // un token de argv aparte, nunca pegado al nombre de la bandera.
    let d = descriptor_de_prueba();
    let argv = vec!["-p".to_string(), "80,443,22".to_string()];
    assert!(validate_flags(&argv, &d, false).is_ok());
}

#[test]
fn una_ip_pegada_a_una_bandera_de_valor_ya_no_se_cuela() {
    // Antes del rediseño, "-p198.51.100.200" casaba por prefijo con
    // "-p". Ahora ese token completo tiene que igualar EXACTAMENTE una
    // entrada de allowed_flags, y no lo hace.
    let d = descriptor_de_prueba();
    let argv = vec!["-p198.51.100.200".to_string()];
    assert!(matches!(
        validate_flags(&argv, &d, false),
        Err(AppError::FlagNotAllowed(_))
    ));
}

#[test]
fn una_bandera_permitida_mas_corta_ya_no_deja_pasar_una_mas_larga() {
    // Reproduce el caso real de nmap que motivó el rediseño: "-s" y
    // "-sS" ya no pueden confundirse porque el emparejamiento es exacto.
    let d = auscan_lib::adapters::ToolDescriptor {
        allowed_flags: &[auscan_lib::adapters::Flag {
            name: "-s",
            needs_privilege: false,
            takes_value: false,
        }],
        ..descriptor_de_prueba()
    };
    let argv = vec!["-sS".to_string()];
    assert!(matches!(
        validate_flags(&argv, &d, false),
        Err(AppError::FlagNotAllowed(_))
    ));
}

#[test]
fn acepta_cuando_el_binario_coincide_con_el_esperado() {
    let p = Path::new("/opt/homebrew/bin/fake-tool");
    assert!(validate_binary(p, p).is_ok());
}

#[test]
fn rechaza_cuando_el_binario_no_coincide() {
    let real = Path::new("/tmp/fake-tool");
    let esperado = Path::new("/opt/homebrew/bin/fake-tool");
    assert!(matches!(
        validate_binary(real, esperado),
        Err(AppError::BinaryMismatch { .. })
    ));
}

#[test]
fn verja_encadena_las_tres_comprobaciones_en_orden() {
    let scope = scope_198();
    let target = scope.validate("198.51.100.5").unwrap();
    let d = descriptor_de_prueba();
    let bin = Path::new("/opt/homebrew/bin/fake-tool");

    let inv_ok = auscan_lib::adapters::Invocation {
        phase: auscan_lib::adapters::Phase::Discovery,
        argv: vec!["-t".to_string(), "198.51.100.5".to_string()],
        targets: vec![target],
        needs_privilege: false,
        raw_from: auscan_lib::adapters::RawSource::Stdout,
        progress_from: auscan_lib::adapters::ProgressSource::None,
        stdin: None,
        timeout: std::time::Duration::from_secs(5),
    };
    assert!(verja(&inv_ok, bin, &d, bin).is_ok());

    // Un objetivo que no está en inv.targets debe seguir tumbando la
    // verja aunque el binario y las banderas sean correctos.
    let mut inv_mal = inv_ok;
    inv_mal.argv.push("198.51.100.200".to_string());
    assert!(verja(&inv_mal, bin, &d, bin).is_err());
}

#[test]
fn verja_acepta_un_objetivo_autorizado_con_espacios_alrededor() {
    let scope = scope_198();
    let target = scope.validate("198.51.100.5").unwrap();
    let d = descriptor_de_prueba();
    let bin = Path::new("/opt/homebrew/bin/fake-tool");
    let inv = auscan_lib::adapters::Invocation {
        phase: auscan_lib::adapters::Phase::Discovery,
        argv: vec!["-t".to_string(), " 198.51.100.5 ".to_string()],
        targets: vec![target],
        needs_privilege: false,
        raw_from: auscan_lib::adapters::RawSource::Stdout,
        progress_from: auscan_lib::adapters::ProgressSource::None,
        stdin: None,
        timeout: std::time::Duration::from_secs(5),
    };
    assert!(
        verja(&inv, bin, &d, bin).is_ok(),
        "un objetivo autorizado con espacios no debe rechazarse por la verja combinada"
    );
}
