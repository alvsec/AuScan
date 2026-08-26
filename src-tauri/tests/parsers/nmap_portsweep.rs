use std::net::IpAddr;

use auscan_lib::adapters::nmap::Nmap;
use auscan_lib::adapters::{
    HostFact, KnownState, ObservationKind, ParseContext, Phase, PhaseOptions, PlanContext,
    ToolAdapter,
};
use auscan_lib::scope::{Scope, ScopeKind};

fn scope_198() -> Scope {
    Scope::from_entries(&[(ScopeKind::Allow, "198.51.100.0/24".to_string())]).unwrap()
}

fn host_de_prueba(ip: &str) -> HostFact {
    HostFact {
        ip: ip.parse::<IpAddr>().unwrap(),
        hostname: None,
        mac: None,
        vendor: None,
        os_guess: None,
        os_accuracy: None,
        state: Some("up".to_string()),
    }
}

#[test]
fn plan_portsweep_sin_privilegio_usa_connect_scan() {
    let scope = scope_198();
    let objetivo = scope.validate("198.51.100.5").unwrap();
    let known = KnownState {
        hosts: vec![host_de_prueba("198.51.100.5")],
        services: vec![],
    };
    let opciones = PhaseOptions::default();
    let ctx = PlanContext {
        phase: Phase::PortSweep,
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
        vec!["-Pn", "-n", "-sT", "-oX", "-", "198.51.100.5"]
    );
    assert!(!invocaciones[0].needs_privilege);
}

#[test]
fn plan_portsweep_privilegiado_usa_syn_scan() {
    let scope = scope_198();
    let objetivo = scope.validate("198.51.100.5").unwrap();
    let known = KnownState {
        hosts: vec![host_de_prueba("198.51.100.5")],
        services: vec![],
    };
    let opciones = PhaseOptions::default();
    let ctx = PlanContext {
        phase: Phase::PortSweep,
        scope: &scope,
        targets: &[objetivo],
        known: &known,
        privileged: true,
        options: &opciones,
    };
    let invocaciones = Nmap.plan(&ctx).unwrap();
    assert_eq!(
        invocaciones[0].argv,
        vec!["-Pn", "-n", "-sS", "-oX", "-", "198.51.100.5"]
    );
    assert!(invocaciones[0].needs_privilege);
}

#[test]
fn plan_portsweep_sin_hosts_conocidos_no_produce_nada() {
    let scope = scope_198();
    let objetivo = scope.validate("198.51.100.5").unwrap();
    let known = KnownState::default();
    let opciones = PhaseOptions::default();
    let ctx = PlanContext {
        phase: Phase::PortSweep,
        scope: &scope,
        targets: &[objetivo],
        known: &known,
        privileged: false,
        options: &opciones,
    };
    assert!(Nmap.plan(&ctx).unwrap().is_empty());
}

#[test]
fn parse_portsweep_omite_los_puertos_cerrados() {
    let raw = include_bytes!("../../../fixtures/nmap/0003-portsweep.xml");
    let ctx = ParseContext {
        tool_run_id: 2,
        raw_path: "raw/0002-nmap-portsweep.xml",
        observed_at: "2026-08-26T10:05:00Z",
    };
    let normalizado = Nmap.parse(raw, &ctx).unwrap();

    assert_eq!(normalizado.hosts.len(), 1);
    assert_eq!(
        normalizado.services,
        vec![
            auscan_lib::adapters::ServiceFact {
                host_ip: "198.51.100.5".parse::<IpAddr>().unwrap(),
                port: 22,
                proto: "tcp".to_string(),
                state: "open".to_string(),
                service: Some("ssh".to_string()),
                product: None,
                version: None,
                extrainfo: None,
                tunnel: None,
                cpe: None,
                banner: None,
            },
            auscan_lib::adapters::ServiceFact {
                host_ip: "198.51.100.5".parse::<IpAddr>().unwrap(),
                port: 80,
                proto: "tcp".to_string(),
                state: "open".to_string(),
                service: Some("http".to_string()),
                product: None,
                version: None,
                extrainfo: None,
                tunnel: None,
                cpe: None,
                banner: None,
            },
        ]
    );
    // El puerto 8080, cerrado en el fixture, no debe aparecer.
    assert!(!normalizado.services.iter().any(|s| s.port == 8080));

    let observaciones_puerto: Vec<_> = normalizado
        .observations
        .iter()
        .filter(|o| o.kind == ObservationKind::ServiceOpen)
        .collect();
    assert_eq!(observaciones_puerto.len(), 2);
}
