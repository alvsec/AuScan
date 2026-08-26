//! Adaptador de nmap. Primera herramienta real orquestada por AUscan.
//!
//! Encadena tres fases (`Discovery`, `PortSweep`, `Services`) con un solo
//! `ToolAdapter`, usando `ctx.phase` para saber cuál pide el operador y
//! `ctx.known` para saber qué hay de fases anteriores. IPv6 queda fuera
//! de esta versión: `plan()` filtra a IPv4 en todas las fases.

use std::net::IpAddr;
use std::time::Duration;

use semver::Version;

use crate::adapters::{
    Flag, HostFact, InstallHint, Invocation, Normalized, ObservationFact, ObservationKind,
    ParseContext, Phase, PlanContext, ProgressSource, RawSource, ServiceFact, ToolAdapter,
    ToolDescriptor,
};
use crate::error::{AppError, Result};
use crate::scope::ScopedTarget;

const ALLOWED_FLAGS: &[Flag] = &[
    Flag {
        name: "-sn",
        needs_privilege: false,
        takes_value: false,
    },
    // Los puertos de sondeo de -PS/-PA van pegados al nombre a
    // propósito: nmap los interpreta como parte del mismo token, no
    // como un valor en un token separado (a diferencia de -p). Como el
    // valor no varía nunca en esta fase, se declaran como literales
    // completos en vez de como banderas `takes_value`.
    Flag {
        name: "-PS80,443,22",
        needs_privilege: false,
        takes_value: false,
    },
    Flag {
        name: "-PA80",
        needs_privilege: false,
        takes_value: false,
    },
    Flag {
        name: "-PR",
        needs_privilege: true,
        takes_value: false,
    },
    Flag {
        name: "-n",
        needs_privilege: false,
        takes_value: false,
    },
    Flag {
        name: "-oX",
        needs_privilege: false,
        takes_value: true,
    },
    Flag {
        name: "-Pn",
        needs_privilege: false,
        takes_value: false,
    },
    Flag {
        name: "-sT",
        needs_privilege: false,
        takes_value: false,
    },
    Flag {
        name: "-sS",
        needs_privilege: true,
        takes_value: false,
    },
];

pub struct Nmap;

impl ToolAdapter for Nmap {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            id: "nmap",
            binaries: &["nmap"],
            min_version: Version::new(7, 80, 0),
            phases: &[Phase::Discovery, Phase::PortSweep],
            install_hint: InstallHint {
                brew: &["install", "nmap"],
                winget: &["install", "-e", "Insecure.Nmap"],
            },
            allowed_flags: ALLOWED_FLAGS,
        }
    }

    fn version_argv(&self) -> Vec<String> {
        vec!["--version".to_string()]
    }

    fn parse_version(&self, stdout: &str) -> Result<Version> {
        // "Nmap version 7.94 ( https://nmap.org )" — nmap usa versiones
        // de dos componentes; semver exige tres, así que se completa con
        // ".0" salvo que ya venga con patch (versiones futuras podrían
        // añadirlo).
        let primera = stdout.lines().next().unwrap_or("");
        let numero = primera
            .strip_prefix("Nmap version ")
            .and_then(|resto| resto.split_whitespace().next())
            .ok_or_else(|| AppError::ParseFailed(stdout.to_string()))?;
        let con_patch = if numero.matches('.').count() == 1 {
            format!("{numero}.0")
        } else {
            numero.to_string()
        };
        Version::parse(&con_patch).map_err(|_| AppError::ParseFailed(stdout.to_string()))
    }

    fn plan(&self, ctx: &PlanContext) -> Result<Vec<Invocation>> {
        match ctx.phase {
            Phase::Discovery => {
                let v4_targets: Vec<ScopedTarget> = ctx
                    .targets
                    .iter()
                    .filter(|t| t.ip().is_ipv4())
                    .copied()
                    .collect();
                if v4_targets.is_empty() {
                    return Ok(vec![]);
                }
                let mut argv = if ctx.privileged {
                    vec!["-sn".to_string(), "-PR".to_string(), "-n".to_string()]
                } else {
                    vec![
                        "-sn".to_string(),
                        "-PS80,443,22".to_string(),
                        "-PA80".to_string(),
                        "-n".to_string(),
                    ]
                };
                argv.push("-oX".to_string());
                argv.push("-".to_string());
                for t in &v4_targets {
                    argv.push(t.to_string());
                }
                Ok(vec![Invocation {
                    phase: Phase::Discovery,
                    argv,
                    targets: v4_targets,
                    needs_privilege: ctx.privileged,
                    raw_from: RawSource::Stdout,
                    progress_from: ProgressSource::None,
                    stdin: None,
                    timeout: Duration::from_secs(300),
                }])
            }
            Phase::PortSweep => {
                let ips: Vec<IpAddr> = ctx
                    .known
                    .hosts
                    .iter()
                    .map(|h| h.ip)
                    .filter(|ip| ip.is_ipv4())
                    .collect();
                if ips.is_empty() {
                    return Ok(vec![]);
                }
                let targets = ips
                    .iter()
                    .map(|ip| scoped_target_de(ctx, *ip))
                    .collect::<Result<Vec<_>>>()?;
                let mut argv = vec!["-Pn".to_string(), "-n".to_string()];
                argv.push(if ctx.privileged { "-sS" } else { "-sT" }.to_string());
                argv.push("-oX".to_string());
                argv.push("-".to_string());
                for ip in &ips {
                    argv.push(ip.to_string());
                }
                Ok(vec![Invocation {
                    phase: Phase::PortSweep,
                    argv,
                    targets,
                    needs_privilege: ctx.privileged,
                    raw_from: RawSource::Stdout,
                    progress_from: ProgressSource::None,
                    stdin: None,
                    timeout: Duration::from_secs(1800),
                }])
            }
            _ => Ok(vec![]),
        }
    }

    fn parse(&self, raw: &[u8], ctx: &ParseContext) -> Result<Normalized> {
        let texto = std::str::from_utf8(raw).map_err(|e| AppError::ParseFailed(e.to_string()))?;
        // nmap siempre emite `<!DOCTYPE nmaprun>` (sin subconjunto interno
        // ni ExternalID) delante del elemento raíz. roxmltree rechaza
        // cualquier DTD por defecto como medida de seguridad frente a
        // ataques de expansión de entidades; su comprobación de "billion
        // laughs" sigue activa aunque se permita el DTD, así que habilitarlo
        // aquí no renuncia a esa protección.
        let opciones = roxmltree::ParsingOptions {
            allow_dtd: true,
            ..Default::default()
        };
        let doc = roxmltree::Document::parse_with_options(texto, opciones)
            .map_err(|e| AppError::ParseFailed(e.to_string()))?;
        let root = doc.root_element();

        let mut hosts = Vec::new();
        let mut services = Vec::new();
        let mut observations = Vec::new();

        for host_node in root.children().filter(|n| n.has_tag_name("host")) {
            let estado = host_node
                .children()
                .find(|n| n.has_tag_name("status"))
                .and_then(|s| s.attribute("state"));
            if estado != Some("up") {
                continue;
            }

            let addr_node = host_node
                .children()
                .filter(|n| n.has_tag_name("address"))
                .find(|n| n.attribute("addrtype") == Some("ipv4"))
                .ok_or_else(|| {
                    AppError::ParseFailed(format!("host sin dirección ipv4 en {}", ctx.raw_path))
                })?;
            let ip: IpAddr = addr_node
                .attribute("addr")
                .ok_or_else(|| {
                    AppError::ParseFailed(format!("host sin atributo addr en {}", ctx.raw_path))
                })?
                .parse()
                .map_err(|_| {
                    AppError::ParseFailed(format!("dirección ipv4 inválida en {}", ctx.raw_path))
                })?;

            let mac_node = host_node
                .children()
                .filter(|n| n.has_tag_name("address"))
                .find(|n| n.attribute("addrtype") == Some("mac"));
            let mac = mac_node
                .and_then(|n| n.attribute("addr"))
                .map(|s| s.to_lowercase());
            let vendor = mac_node
                .and_then(|n| n.attribute("vendor"))
                .map(|s| s.to_string());

            let hostname = host_node
                .children()
                .find(|n| n.has_tag_name("hostnames"))
                .and_then(|hn| hn.children().find(|n| n.has_tag_name("hostname")))
                .and_then(|h| h.attribute("name"))
                .map(|s| s.to_string());

            hosts.push(HostFact {
                ip,
                hostname,
                mac,
                vendor,
                os_guess: None,
                os_accuracy: None,
                state: Some("up".to_string()),
            });

            observations.push(ObservationFact {
                host_ip: Some(ip),
                port: None,
                kind: ObservationKind::HostDiscovered,
                subject: ip.to_string(),
                statement: "Host activo".to_string(),
                evidence: Some(texto[addr_node.range()].to_string()),
                evidence_ref: Some(format!(
                    "{}#L{}",
                    ctx.raw_path,
                    linea_de(texto, addr_node.range().start)
                )),
                meta_json: None,
            });

            if let Some(ports_node) = host_node.children().find(|n| n.has_tag_name("ports")) {
                for port_node in ports_node.children().filter(|n| n.has_tag_name("port")) {
                    let proto = port_node.attribute("protocol").unwrap_or("tcp").to_string();
                    let portid: u16 = port_node
                        .attribute("portid")
                        .and_then(|s| s.parse().ok())
                        .ok_or_else(|| {
                            AppError::ParseFailed(format!("puerto sin portid en {}", ctx.raw_path))
                        })?;
                    let pstate = port_node
                        .children()
                        .find(|n| n.has_tag_name("state"))
                        .and_then(|s| s.attribute("state"))
                        .unwrap_or("unknown")
                        .to_string();
                    if pstate != "open" {
                        continue;
                    }
                    let service_node = port_node.children().find(|n| n.has_tag_name("service"));
                    let service = service_node
                        .and_then(|s| s.attribute("name"))
                        .map(|s| s.to_string());

                    services.push(ServiceFact {
                        host_ip: ip,
                        port: portid,
                        proto: proto.clone(),
                        state: pstate.clone(),
                        service: service.clone(),
                        product: None,
                        version: None,
                        extrainfo: None,
                        tunnel: None,
                        cpe: None,
                        banner: None,
                    });

                    observations.push(ObservationFact {
                        host_ip: Some(ip),
                        port: Some(portid),
                        kind: ObservationKind::ServiceOpen,
                        subject: format!("{ip}:{portid}/{proto}"),
                        statement: format!(
                            "Puerto abierto: {}",
                            service.as_deref().unwrap_or("desconocido")
                        ),
                        evidence: Some(texto[port_node.range()].to_string()),
                        evidence_ref: Some(format!(
                            "{}#L{}",
                            ctx.raw_path,
                            linea_de(texto, port_node.range().start)
                        )),
                        meta_json: None,
                    });
                }
            }
        }

        Ok(Normalized {
            hosts,
            services,
            observations,
        })
    }
}

fn linea_de(texto: &str, offset: usize) -> usize {
    texto[..offset].bytes().filter(|&b| b == b'\n').count() + 1
}

fn scoped_target_de(ctx: &PlanContext, ip: IpAddr) -> Result<ScopedTarget> {
    ctx.targets
        .iter()
        .find(|t| t.ip() == ip)
        .copied()
        .ok_or_else(|| AppError::UnvalidatedTarget(ip.to_string()))
}
