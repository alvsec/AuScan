use std::net::IpAddr;

use auscan_lib::adapters::nmap::Nmap;
use auscan_lib::adapters::{
    KnownState, ObservationKind, ParseContext, Phase, PhaseOptions, PlanContext, ServiceFact,
    ToolAdapter,
};
use auscan_lib::scope::{Scope, ScopeKind};

fn scope_198() -> Scope {
    Scope::from_entries(&[(ScopeKind::Allow, "198.51.100.0/24".to_string())]).unwrap()
}

fn servicio_abierto(ip: &str, port: u16) -> ServiceFact {
    ServiceFact {
        host_ip: ip.parse::<IpAddr>().unwrap(),
        port,
        proto: "tcp".to_string(),
        state: "open".to_string(),
        service: None,
        product: None,
        version: None,
        extrainfo: None,
        tunnel: None,
        cpe: None,
        banner: None,
    }
}

#[test]
fn plan_services_agrupa_por_host_y_ordena_los_puertos() {
    let scope = scope_198();
    let objetivo = scope.validate("198.51.100.5").unwrap();
    let known = KnownState {
        hosts: vec![],
        services: vec![
            servicio_abierto("198.51.100.5", 443),
            servicio_abierto("198.51.100.5", 22),
        ],
    };
    let opciones = PhaseOptions::default();
    let ctx = PlanContext {
        phase: Phase::Services,
        scope: &scope,
        targets: &[objetivo],
        known: &known,
        privileged: false,
        options: &opciones,
    };
    let invocaciones = Nmap.plan(&ctx).unwrap();
    assert_eq!(invocaciones.len(), 1);
    assert_eq!(
        invocaciones[0].argv,
        vec![
            "-Pn",
            "-n",
            "-sV",
            "-p",
            "22,443",
            "-oX",
            "-",
            "198.51.100.5"
        ]
    );
}

#[test]
fn plan_services_privilegiado_añade_deteccion_de_so() {
    let scope = scope_198();
    let objetivo = scope.validate("198.51.100.5").unwrap();
    let known = KnownState {
        hosts: vec![],
        services: vec![servicio_abierto("198.51.100.5", 22)],
    };
    let opciones = PhaseOptions::default();
    let ctx = PlanContext {
        phase: Phase::Services,
        scope: &scope,
        targets: &[objetivo],
        known: &known,
        privileged: true,
        options: &opciones,
    };
    let invocaciones = Nmap.plan(&ctx).unwrap();
    assert_eq!(
        invocaciones[0].argv,
        vec![
            "-Pn",
            "-n",
            "-sV",
            "-O",
            "-p",
            "22",
            "-oX",
            "-",
            "198.51.100.5"
        ]
    );
}

#[test]
fn plan_services_ignora_puertos_no_abiertos() {
    let scope = scope_198();
    let objetivo = scope.validate("198.51.100.5").unwrap();
    let mut cerrado = servicio_abierto("198.51.100.5", 8080);
    cerrado.state = "closed".to_string();
    let known = KnownState {
        hosts: vec![],
        services: vec![cerrado],
    };
    let opciones = PhaseOptions::default();
    let ctx = PlanContext {
        phase: Phase::Services,
        scope: &scope,
        targets: &[objetivo],
        known: &known,
        privileged: false,
        options: &opciones,
    };
    assert!(Nmap.plan(&ctx).unwrap().is_empty());
}

#[test]
fn plan_services_rechaza_un_host_conocido_fuera_de_targets() {
    let scope = scope_198();
    let objetivo = scope.validate("198.51.100.5").unwrap();
    // El servicio conocido está en un host (198.51.100.9) que no está
    // entre los targets validados.
    let known = KnownState {
        hosts: vec![],
        services: vec![servicio_abierto("198.51.100.9", 22)],
    };
    let opciones = PhaseOptions::default();
    let ctx = PlanContext {
        phase: Phase::Services,
        scope: &scope,
        targets: &[objetivo],
        known: &known,
        privileged: false,
        options: &opciones,
    };
    assert!(matches!(
        Nmap.plan(&ctx),
        Err(auscan_lib::error::AppError::UnvalidatedTarget(_))
    ));
}

#[test]
fn parse_services_completa_producto_version_y_so() {
    let raw = include_bytes!("../../../fixtures/nmap/0004-services.xml");
    let ctx = ParseContext {
        tool_run_id: 3,
        raw_path: "raw/0003-nmap-services.xml",
        observed_at: "2026-08-26T10:06:00Z",
    };
    let normalizado = Nmap.parse(raw, &ctx).unwrap();

    assert_eq!(normalizado.hosts.len(), 1);
    let h = &normalizado.hosts[0];
    assert_eq!(h.os_guess.as_deref(), Some("Linux 5.0 - 6.1"));
    assert_eq!(h.os_accuracy, Some(95));

    assert_eq!(normalizado.services.len(), 3);
    let https = normalizado.services.iter().find(|s| s.port == 443).unwrap();
    assert_eq!(https.product.as_deref(), Some("nginx"));
    assert_eq!(https.version.as_deref(), Some("1.24.0"));
    assert_eq!(https.tunnel.as_deref(), Some("ssl"));
    assert_eq!(https.cpe.as_deref(), Some("cpe:/a:nginx:nginx:1.24.0"));

    let ssh = normalizado.services.iter().find(|s| s.port == 22).unwrap();
    assert_eq!(ssh.extrainfo.as_deref(), Some("Ubuntu Linux; protocol 2.0"));

    let version_disclosed = normalizado
        .observations
        .iter()
        .filter(|o| o.kind == ObservationKind::ServiceVersionDisclosed)
        .count();
    assert_eq!(version_disclosed, 3);

    let os_guess_obs = normalizado
        .observations
        .iter()
        .filter(|o| o.kind == ObservationKind::HostOsGuess)
        .count();
    assert_eq!(os_guess_obs, 1);
}
