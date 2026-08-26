use std::net::IpAddr;

use auscan_lib::adapters::nmap::Nmap;
use auscan_lib::adapters::{
    KnownState, ObservationKind, ParseContext, Phase, PhaseOptions, PlanContext, ToolAdapter,
};
use auscan_lib::scope::{Scope, ScopeKind};

fn scope_198() -> Scope {
    Scope::from_entries(&[(ScopeKind::Allow, "198.51.100.0/24".to_string())]).unwrap()
}

#[test]
fn version_argv_pide_version_larga() {
    assert_eq!(Nmap.version_argv(), vec!["--version".to_string()]);
}

#[test]
fn parse_version_entiende_la_salida_real_de_nmap() {
    let salida = "Nmap version 7.94 ( https://nmap.org )\nPlatform: x86_64-apple-darwin23.1.0\n";
    let v = Nmap.parse_version(salida).unwrap();
    assert_eq!((v.major, v.minor, v.patch), (7, 94, 0));
}

#[test]
fn parse_version_no_duplica_el_patch_si_ya_viene() {
    let v = Nmap
        .parse_version("Nmap version 8.1.2 ( https://nmap.org )\n")
        .unwrap();
    assert_eq!((v.major, v.minor, v.patch), (8, 1, 2));
}

#[test]
fn plan_discovery_sin_privilegio_usa_sondas_tcp() {
    let scope = scope_198();
    let objetivo = scope.validate("198.51.100.5").unwrap();
    let known = KnownState::default();
    let opciones = PhaseOptions::default();
    let ctx = PlanContext {
        phase: Phase::Discovery,
        scope: &scope,
        targets: &[objetivo],
        known: &known,
        privileged: false,
        options: &opciones,
    };
    let invocaciones = Nmap.plan(&ctx).unwrap();
    assert_eq!(invocaciones.len(), 1);
    let inv = &invocaciones[0];
    assert_eq!(inv.phase, Phase::Discovery);
    assert!(!inv.needs_privilege);
    assert_eq!(
        inv.argv,
        vec![
            "-sn",
            "-PS80,443,22",
            "-PA80",
            "-n",
            "-oX",
            "-",
            "198.51.100.5"
        ]
    );
}

#[test]
fn plan_discovery_privilegiado_usa_arp() {
    let scope = scope_198();
    let objetivo = scope.validate("198.51.100.5").unwrap();
    let known = KnownState::default();
    let opciones = PhaseOptions::default();
    let ctx = PlanContext {
        phase: Phase::Discovery,
        scope: &scope,
        targets: &[objetivo],
        known: &known,
        privileged: true,
        options: &opciones,
    };
    let invocaciones = Nmap.plan(&ctx).unwrap();
    assert_eq!(invocaciones.len(), 1);
    let inv = &invocaciones[0];
    assert!(inv.needs_privilege);
    assert_eq!(
        inv.argv,
        vec!["-sn", "-PR", "-n", "-oX", "-", "198.51.100.5"]
    );
}

#[test]
fn plan_discovery_sin_objetivos_no_produce_invocaciones() {
    let scope = scope_198();
    let known = KnownState::default();
    let opciones = PhaseOptions::default();
    let ctx = PlanContext {
        phase: Phase::Discovery,
        scope: &scope,
        targets: &[],
        known: &known,
        privileged: false,
        options: &opciones,
    };
    assert!(Nmap.plan(&ctx).unwrap().is_empty());
}

#[test]
fn plan_de_una_fase_que_nmap_no_atiende_produce_vacio() {
    let scope = scope_198();
    let objetivo = scope.validate("198.51.100.5").unwrap();
    let known = KnownState::default();
    let opciones = PhaseOptions::default();
    let ctx = PlanContext {
        phase: Phase::Web,
        scope: &scope,
        targets: &[objetivo],
        known: &known,
        privileged: false,
        options: &opciones,
    };
    assert!(Nmap.plan(&ctx).unwrap().is_empty());
}

fn parse_ctx() -> ParseContext<'static> {
    ParseContext {
        tool_run_id: 1,
        raw_path: "raw/0001-nmap-sn.xml",
        observed_at: "2026-08-26T10:00:00Z",
    }
}

#[test]
fn parse_discovery_sin_privilegio_solo_incluye_hosts_arriba() {
    let raw = include_bytes!("../../../fixtures/nmap/0001-discovery-sin-privilegio.xml");
    let ctx = parse_ctx();
    let normalizado = Nmap.parse(raw, &ctx).unwrap();

    assert_eq!(
        normalizado.hosts,
        vec![
            auscan_lib::adapters::HostFact {
                ip: "198.51.100.5".parse::<IpAddr>().unwrap(),
                hostname: Some("host5.example".to_string()),
                mac: None,
                vendor: None,
                os_guess: None,
                os_accuracy: None,
                state: Some("up".to_string()),
            },
            auscan_lib::adapters::HostFact {
                ip: "198.51.100.9".parse::<IpAddr>().unwrap(),
                hostname: None,
                mac: None,
                vendor: None,
                os_guess: None,
                os_accuracy: None,
                state: Some("up".to_string()),
            },
        ]
    );
    assert!(normalizado.services.is_empty());
    assert_eq!(normalizado.observations.len(), 2);
    for o in &normalizado.observations {
        assert_eq!(o.kind, ObservationKind::HostDiscovered);
        assert_eq!(o.statement, "Host activo");
        assert!(o.evidence.as_deref().unwrap().contains("addr="));
        assert!(o
            .evidence_ref
            .as_deref()
            .unwrap()
            .starts_with("raw/0001-nmap-sn.xml#L"));
    }
}

#[test]
fn parse_discovery_privilegiado_incluye_mac_y_fabricante() {
    let raw = include_bytes!("../../../fixtures/nmap/0002-discovery-privilegiado.xml");
    let ctx = parse_ctx();
    let normalizado = Nmap.parse(raw, &ctx).unwrap();

    assert_eq!(normalizado.hosts.len(), 1);
    let h = &normalizado.hosts[0];
    assert_eq!(h.ip, "198.51.100.5".parse::<IpAddr>().unwrap());
    assert_eq!(h.mac.as_deref(), Some("02:1a:2b:00:00:05"));
    assert_eq!(h.vendor.as_deref(), Some("Synthetic Devices"));
}

#[test]
fn parse_rechaza_una_salida_de_nmap_que_no_termino_con_exito() {
    let raw = include_bytes!("../../../fixtures/nmap/0005-error.xml");
    let ctx = ParseContext {
        tool_run_id: 5,
        raw_path: "raw/0005-nmap-error.xml",
        observed_at: "2026-08-26T10:08:00Z",
    };
    let err = Nmap.parse(raw, &ctx).unwrap_err();
    assert!(matches!(err, auscan_lib::error::AppError::ParseFailed(_)));
}
