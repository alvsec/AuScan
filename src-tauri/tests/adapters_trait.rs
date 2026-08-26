mod common;

use std::net::IpAddr;

use auscan_lib::adapters::{ObservationKind, Phase, PhaseOptions, PlanContext, ToolAdapter};
use auscan_lib::scope::{Scope, ScopeKind};
use common::{known_vacio, FakeAdapter};

fn scope_de_prueba() -> Scope {
    Scope::from_entries(&[(ScopeKind::Allow, "198.51.100.0/24".to_string())]).unwrap()
}

#[test]
fn descriptor_expone_lo_minimo_para_preflight() {
    let a = FakeAdapter;
    let d = a.descriptor();
    assert_eq!(d.id, "fake");
    assert_eq!(d.binaries, &["fake-tool"]);
    assert!(!d.allowed_flags.is_empty());
}

#[test]
fn parse_version_entiende_su_propio_formato() {
    let a = FakeAdapter;
    let v = a.parse_version("fake-tool 2.3").unwrap();
    assert_eq!(v.major, 2);
    assert_eq!(v.minor, 3);
}

#[test]
fn plan_construye_una_invocacion_por_cada_objetivo_de_scope() {
    let a = FakeAdapter;
    let scope = scope_de_prueba();
    let objetivo = scope.validate("198.51.100.5").unwrap();
    let known = known_vacio();
    let opciones = PhaseOptions::default();
    let ctx = PlanContext {
        phase: Phase::Discovery,
        scope: &scope,
        targets: &[objetivo],
        known: &known,
        privileged: false,
        options: &opciones,
    };

    let invocaciones = a.plan(&ctx).unwrap();
    assert_eq!(invocaciones.len(), 1);
    assert_eq!(invocaciones[0].phase, Phase::Discovery);
    assert!(invocaciones[0].argv.contains(&"198.51.100.5".to_string()));
    assert!(!invocaciones[0].needs_privilege);
}

#[test]
fn parse_es_pura_y_produce_hechos_normalizados() {
    let a = FakeAdapter;
    let raw = b"198.51.100.5\n198.51.100.9\nno-es-una-ip\n";
    let ctx = auscan_lib::adapters::ParseContext {
        tool_run_id: 1,
        raw_path: "raw/0001-fake.txt",
        observed_at: "2026-08-25T10:00:00Z",
    };

    let normalizado = a.parse(raw, &ctx).unwrap();

    assert_eq!(normalizado.hosts.len(), 2);
    assert_eq!(
        normalizado.hosts[0].ip,
        "198.51.100.5".parse::<IpAddr>().unwrap()
    );
    assert_eq!(normalizado.observations.len(), 2);
    assert_eq!(
        normalizado.observations[0].kind,
        ObservationKind::HostDiscovered
    );
    assert_eq!(
        normalizado.observations[0].evidence_ref.as_deref(),
        Some("raw/0001-fake.txt")
    );
}

#[test]
fn el_registro_de_produccion_esta_vacio_hasta_la_fase_4() {
    assert!(auscan_lib::adapters::registry().is_empty());
}
