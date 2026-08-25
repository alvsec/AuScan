//! El contrato que cualquier herramienta implementa para integrarse.
//!
//! Un adaptador describe y parsea; el núcleo ejecuta. Si cada adaptador
//! lanzase su propio proceso, habría tantos sitios capaces de ejecutar
//! un comando como herramientas, y por tanto tantos sitios donde
//! saltarse el guard de alcance. La regla del alcance solo es cierta si
//! existe un único sitio que lanza — ese sitio es exec.rs, en la fase
//! siguiente.

use std::net::IpAddr;
use std::time::Duration;

use semver::Version;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::scope::{Scope, ScopedTarget};

/// Fase de una auditoría a la que pertenece una invocación.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Discovery,
    PortSweep,
    Services,
    Web,
    Templates,
    Tls,
    Smb,
    Ssh,
    Mdns,
}

/// Una bandera que un adaptador puede añadir a su argv.
///
/// `needs_privilege` es lo que convierte la regla "solo detección" en
/// mecánico: una bandera marcada no arranca sin la ruta privilegiada,
/// sin importar lo que decida el adaptador en tiempo de ejecución.
#[derive(Debug, Clone, Copy)]
pub struct Flag {
    pub name: &'static str,
    pub needs_privilege: bool,
}

/// Cómo instalar la herramienta cuando falta, por gestor de paquetes.
/// Argv ya troceado, no una cadena: evita cualquier ambigüedad de
/// *shell-splitting* si un nombre de paquete lleva un espacio.
#[derive(Debug, Clone, Copy)]
pub struct InstallHint {
    pub brew: &'static [&'static str],
    pub winget: &'static [&'static str],
}

/// Descripción de una herramienta: lo que el registro necesita para
/// saber si está instalada, qué versión mínima exige y qué puede hacer.
#[derive(Debug, Clone)]
pub struct ToolDescriptor {
    pub id: &'static str,
    pub binaries: &'static [&'static str],
    pub min_version: Version,
    pub phases: &'static [Phase],
    pub install_hint: InstallHint,
    pub allowed_flags: &'static [Flag],
}

/// De dónde sale la salida cruda de una invocación.
#[derive(Debug, Clone)]
pub enum RawSource {
    Stdout,
    File(String),
}

/// De dónde salen las líneas de progreso mientras corre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressSource {
    Stdout,
    Stderr,
    None,
}

/// Vocabulario cerrado de observaciones. Los adaptadores eligen de esta
/// lista; no pueden inventar. Es lo que hace que "observaciones
/// agrupadas" en resumen.md funcione en vez de degenerar en cien
/// categorías de una línea. Ampliarlo es una decisión de diseño visible
/// en el diff, no un efecto colateral de escribir un parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    HostDiscovered,
    HostOsGuess,
    ServiceOpen,
    ServiceVersionDisclosed,
    WebTechnology,
    WebTitle,
    WebHeaderAbsent,
    TlsProtocolEnabled,
    TlsCipherOffered,
    TlsCertificateExpiry,
    SmbSigningState,
    SshAlgorithmOffered,
    TemplateMatch,
}

/// Un host observado, sin identidad de base de datos: el núcleo resuelve
/// el id y hace el upsert. Por eso `parse` puede ser una función pura.
#[derive(Debug, Clone, PartialEq)]
pub struct HostFact {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub os_guess: Option<String>,
    pub os_accuracy: Option<i64>,
    pub state: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServiceFact {
    pub host_ip: IpAddr,
    pub port: u16,
    pub proto: String,
    pub state: String,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extrainfo: Option<String>,
    pub tunnel: Option<String>,
    pub cpe: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ObservationFact {
    pub host_ip: Option<IpAddr>,
    pub port: Option<u16>,
    pub kind: ObservationKind,
    pub subject: String,
    pub statement: String,
    pub evidence: Option<String>,
    pub evidence_ref: Option<String>,
    pub meta_json: Option<String>,
}

/// Lo que un `parse()` produce: hechos sin identidad de base de datos.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Normalized {
    pub hosts: Vec<HostFact>,
    pub services: Vec<ServiceFact>,
    pub observations: Vec<ObservationFact>,
}

/// Contexto que `parse` recibe además de los bytes crudos. El reloj se
/// inyecta aquí para que `parse` siga siendo pura: sin esto, un parser
/// que llamase a `SystemTime::now()` dejaría de ser testeable con un
/// simple `parse(fixture) == esperado`.
pub struct ParseContext<'a> {
    pub tool_run_id: i64,
    pub raw_path: &'a str,
    pub observed_at: &'a str,
}

/// Una ejecución concreta que el adaptador quiere lanzar.
pub struct Invocation {
    pub phase: Phase,
    pub argv: Vec<String>,
    pub targets: Vec<ScopedTarget>,
    pub needs_privilege: bool,
    pub raw_from: RawSource,
    pub progress_from: ProgressSource,
    pub stdin: Option<Vec<u8>>,
    pub timeout: Duration,
}

/// Lo que ya se sabe de fases anteriores, para encadenarlas sin SQL en
/// el adaptador: nmap -sV escanea solo los puertos que descubrió -sn, y
/// httpx recibe exactamente los servicios http/https detectados.
#[derive(Debug, Clone, Default)]
pub struct KnownState {
    pub hosts: Vec<HostFact>,
    pub services: Vec<ServiceFact>,
}

/// Opciones de fase que decide el operador (p. ej. -sC sí/no).
#[derive(Debug, Clone, Default)]
pub struct PhaseOptions {
    pub script_scan: bool,
}

pub struct PlanContext<'a> {
    pub scope: &'a Scope,
    pub targets: &'a [ScopedTarget],
    pub known: &'a KnownState,
    pub privileged: bool,
    pub options: &'a PhaseOptions,
}

/// Una línea de progreso interpretada, para la UI de ejecución (Fase 5).
#[derive(Debug, Clone, PartialEq)]
pub struct Progress {
    pub message: String,
    pub percent: Option<u8>,
}

/// El contrato. El adaptador describe y parsea; el núcleo ejecuta:
/// ningún método de este trait lanza un proceso.
pub trait ToolAdapter: Send + Sync {
    fn descriptor(&self) -> ToolDescriptor;

    fn version_argv(&self) -> Vec<String>;
    fn parse_version(&self, stdout: &str) -> Result<Version>;

    /// De objetivos ya validados a comandos concretos.
    fn plan(&self, ctx: &PlanContext) -> Result<Vec<Invocation>>;

    /// Función PURA. Sin IO, sin reloj, sin red.
    fn parse(&self, raw: &[u8], ctx: &ParseContext) -> Result<Normalized>;

    fn parse_progress(&self, _line: &str) -> Option<Progress> {
        None
    }
}

/// Las herramientas que la app sabe orquestar. Añadir una es un fichero
/// nuevo y una línea aquí; el núcleo no se toca. Vacío hasta que la
/// Fase 4 añada el adaptador de nmap.
pub fn registry() -> Vec<Box<dyn ToolAdapter>> {
    vec![]
}
