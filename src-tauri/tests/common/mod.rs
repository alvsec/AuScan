//! Adaptador de prueba compartido por los tests de esta fase.
//!
//! No representa ninguna herramienta real: existe para ejercitar el
//! trait, la verja y el preflight sin depender de un binario instalado
//! en la máquina que ejecuta los tests. La Fase 4 seguirá esta misma
//! forma para el adaptador de nmap de verdad.

use std::net::IpAddr;
use std::time::Duration;

use auscan_lib::adapters::{
    Flag, HostFact, InstallHint, Invocation, KnownState, Normalized, ObservationFact,
    ObservationKind, ParseContext, Phase, PlanContext, ProgressSource, RawSource, ToolAdapter,
    ToolDescriptor,
};
use auscan_lib::error::{AppError, Result};
use semver::Version;

static FLAGS: &[Flag] = &[
    Flag {
        name: "-t",
        needs_privilege: false,
        takes_value: false,
    },
    Flag {
        name: "-p",
        needs_privilege: false,
        takes_value: true,
    },
    Flag {
        name: "-x",
        needs_privilege: true,
        takes_value: false,
    },
];

pub struct FakeAdapter;

impl ToolAdapter for FakeAdapter {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            id: "fake",
            binaries: &["fake-tool"],
            min_version: Version::new(1, 0, 0),
            phases: &[Phase::Discovery],
            install_hint: InstallHint {
                brew: &["install", "fake-tool"],
                winget: &["install", "-e", "Example.FakeTool"],
            },
            allowed_flags: FLAGS,
        }
    }

    fn version_argv(&self) -> Vec<String> {
        vec!["--version".to_string()]
    }

    fn parse_version(&self, stdout: &str) -> Result<Version> {
        // Formato inventado: "fake-tool 2.3".
        let numero = stdout
            .split_whitespace()
            .last()
            .ok_or_else(|| AppError::InvalidAddress(stdout.to_string()))?;
        let con_patch = format!("{numero}.0");
        Version::parse(&con_patch).map_err(|_| AppError::InvalidAddress(stdout.to_string()))
    }

    fn plan(&self, ctx: &PlanContext) -> Result<Vec<Invocation>> {
        let mut argv = vec!["-t".to_string()];
        for t in ctx.targets {
            argv.push(t.to_string());
        }
        Ok(vec![Invocation {
            phase: Phase::Discovery,
            argv,
            targets: ctx.targets.to_vec(),
            needs_privilege: false,
            raw_from: RawSource::Stdout,
            progress_from: ProgressSource::None,
            stdin: None,
            timeout: Duration::from_secs(30),
        }])
    }

    fn parse(&self, raw: &[u8], ctx: &ParseContext) -> Result<Normalized> {
        // Formato inventado: una IP por línea.
        let texto = String::from_utf8_lossy(raw);
        let mut hosts = Vec::new();
        for linea in texto.lines() {
            if let Ok(ip) = linea.trim().parse::<IpAddr>() {
                hosts.push(HostFact {
                    ip,
                    hostname: None,
                    mac: None,
                    vendor: None,
                    os_guess: None,
                    os_accuracy: None,
                    state: Some("up".to_string()),
                });
            }
        }
        let observations = hosts
            .iter()
            .map(|h| ObservationFact {
                host_ip: Some(h.ip),
                port: None,
                kind: ObservationKind::HostDiscovered,
                subject: h.ip.to_string(),
                statement: "host detectado por fake-tool".to_string(),
                evidence: None,
                evidence_ref: Some(ctx.raw_path.to_string()),
                meta_json: None,
            })
            .collect();
        Ok(Normalized {
            hosts,
            services: Vec::new(),
            observations,
        })
    }
}

/// Construye un KnownState y un PhaseOptions vacíos, para los tests que
/// solo necesitan rellenar `targets` y `scope`.
#[allow(dead_code)]
pub fn known_vacio() -> KnownState {
    KnownState::default()
}

/// Igual que `FakeAdapter`, pero con dos nombres de binario en el
/// descriptor en vez de uno.
///
/// Existe solo para el test de `check_tool` que demuestra que se
/// recorren TODOS los binarios del descriptor, no solo el primero: con
/// el descriptor real de `FakeAdapter` (un único binario) no hay nada a
/// lo que "caer", así que esa prueba sería vacua. No se toca el
/// `binaries` de `FakeAdapter::descriptor()` porque
/// `tests/adapters_trait.rs::descriptor_expone_lo_minimo_para_preflight`
/// lo comprueba tal cual.
#[allow(dead_code)]
pub struct FakeAdapterConDosBinarios;

impl ToolAdapter for FakeAdapterConDosBinarios {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            binaries: &["nombre-que-no-existe", "fake-tool"],
            ..FakeAdapter.descriptor()
        }
    }

    fn version_argv(&self) -> Vec<String> {
        FakeAdapter.version_argv()
    }

    fn parse_version(&self, stdout: &str) -> Result<Version> {
        FakeAdapter.parse_version(stdout)
    }

    fn plan(&self, ctx: &PlanContext) -> Result<Vec<Invocation>> {
        FakeAdapter.plan(ctx)
    }

    fn parse(&self, raw: &[u8], ctx: &ParseContext) -> Result<Normalized> {
        FakeAdapter.parse(raw, ctx)
    }
}
