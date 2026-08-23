//! Autoridad única del alcance.
//!
//! Este módulo es el ÚNICO sitio del programa capaz de construir un
//! `ScopedTarget`. Cualquier ruta de ejecución que quiera tocar un
//! objetivo tiene que pedirle uno aquí, y aquí se le dice que no.

use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScopeKind {
    Allow,
    Deny,
}

impl ScopeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScopeKind::Allow => "allow",
            ScopeKind::Deny => "deny",
        }
    }
}

/// Normaliza `::ffff:a.b.c.d` a su v4 equivalente, para que el veredicto
/// no dependa de en qué forma llegó escrita la dirección.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Reduce una red v4-mapeada a su equivalente v4 real.
///
/// `::ffff:a.b.c.d/n` con n >= 96 es la red v4 `a.b.c.d/(n-96)`. Con
/// n < 96 la red desborda el rango mapeado y no representa ninguna red
/// v4: se rechaza en vez de recortarla en silencio.
///
/// Las formas compatible-v4 (`::a.b.c.d`) y NAT64 (`64:ff9b::/96`) NO se
/// convierten a propósito: `to_ipv4_mapped` devuelve None para ambas y
/// quedan como redes v6 corrientes, que no casan con objetivos v4. Falla
/// cerrado, que es el lado correcto en el que equivocarse.
fn canonical_net(net: IpNet) -> Result<IpNet> {
    match net {
        IpNet::V6(v6) => match v6.addr().to_ipv4_mapped() {
            Some(v4) => {
                let len = v6.prefix_len();
                if len < 96 {
                    return Err(AppError::InvalidAddress(net.to_string()));
                }
                Ok(IpNet::V4(
                    Ipv4Net::new(v4, len - 96)
                        .map_err(|_| AppError::InvalidAddress(net.to_string()))?,
                ))
            }
            None => Ok(IpNet::V6(v6)),
        },
        v4 => Ok(v4),
    }
}

/// Parsea una entrada de alcance a su forma canónica.
///
/// Rechaza CIDR con bits de host puestos: `198.51.100.5/24` no dice si
/// se autoriza el host o los 254 vecinos, y adivinarlo sería peor que
/// pedir que se escriba bien.
pub fn parse_entry(s: &str) -> Result<IpNet> {
    let s = s.trim();
    if s.is_empty() {
        return Err(AppError::InvalidAddress(s.to_string()));
    }

    if s.contains('/') {
        let net: IpNet = s
            .parse()
            .map_err(|_| AppError::InvalidAddress(s.to_string()))?;
        // Canonicalizar ANTES de comprobar los bits de host, para que una
        // entrada en notación mapeada acabe siendo la misma red que su
        // forma v4. Sin esto, un deny escrito como ::ffff:192.0.2.0/120
        // se guardaría como red v6 y no excluiría nada: contains() entre
        // familias distintas siempre es false.
        let net = canonical_net(net)?;
        if net.addr() != net.network() {
            return Err(AppError::AmbiguousCidr(s.to_string()));
        }
        Ok(net)
    } else {
        let ip = canonical_ip(
            s.parse::<IpAddr>()
                .map_err(|_| AppError::InvalidAddress(s.to_string()))?,
        );
        Ok(match ip {
            IpAddr::V4(a) => IpNet::V4(
                Ipv4Net::new(a, 32).map_err(|_| AppError::InvalidAddress(s.to_string()))?,
            ),
            IpAddr::V6(a) => IpNet::V6(
                Ipv6Net::new(a, 128).map_err(|_| AppError::InvalidAddress(s.to_string()))?,
            ),
        })
    }
}

pub fn family_of(net: &IpNet) -> &'static str {
    match net {
        IpNet::V4(_) => "v4",
        IpNet::V6(_) => "v6",
    }
}

/// Un objetivo que YA pasó por el guard.
///
/// El campo es privado y no hay constructor público: fuera de este
/// módulo es imposible fabricar uno. Cualquier función que reciba un
/// `ScopedTarget` sabe, por el tipo, que la dirección está autorizada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopedTarget(IpAddr);

impl ScopedTarget {
    pub fn ip(&self) -> IpAddr {
        self.0
    }
}

impl std::fmt::Display for ScopedTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Scope {
    allow: Vec<IpNet>,
    deny: Vec<IpNet>,
}

impl Scope {
    pub fn new(allow: Vec<IpNet>, deny: Vec<IpNet>) -> Self {
        Self { allow, deny }
    }

    pub fn from_entries(entries: &[(ScopeKind, String)]) -> Result<Self> {
        let mut allow = Vec::new();
        let mut deny = Vec::new();
        for (kind, raw) in entries {
            let net = parse_entry(raw)?;
            match kind {
                ScopeKind::Allow => allow.push(net),
                ScopeKind::Deny => deny.push(net),
            }
        }
        Ok(Self { allow, deny })
    }

    /// Sin ninguna entrada `allow` el alcance está vacío. El estado por
    /// defecto es "nada autorizado", nunca "todo autorizado".
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty()
    }

    pub fn allow(&self) -> &[IpNet] {
        &self.allow
    }

    pub fn deny(&self) -> &[IpNet] {
        &self.deny
    }

    /// El guard. Único constructor de `ScopedTarget` del programa.
    ///
    /// Orden deliberado: alcance vacío, luego exclusiones, luego
    /// autorizaciones. `deny` gana siempre, sin importar la especificidad.
    pub fn validate_ip(&self, ip: IpAddr) -> Result<ScopedTarget> {
        let ip = canonical_ip(ip);

        if self.allow.is_empty() {
            return Err(AppError::EmptyScope);
        }
        if self.deny.iter().any(|n| n.contains(&ip)) {
            return Err(AppError::OutOfScope(ip.to_string()));
        }
        if self.allow.iter().any(|n| n.contains(&ip)) {
            return Ok(ScopedTarget(ip));
        }
        Err(AppError::OutOfScope(ip.to_string()))
    }

    pub fn validate(&self, target: &str) -> Result<ScopedTarget> {
        let t = target.trim();
        let ip: IpAddr = t
            .parse()
            .map_err(|_| AppError::InvalidAddress(target.to_string()))?;
        self.validate_ip(ip)
    }
}

/// Resolución de nombres, inyectable para que los tests no toquen la red.
///
/// Un test que depende del DNS es un test que falla en un avión y miente
/// en CI.
pub trait Resolver: Send + Sync {
    fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>>;
}

pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        use std::net::ToSocketAddrs;
        Ok((host, 0u16).to_socket_addrs()?.map(|sa| sa.ip()).collect())
    }
}

impl Scope {
    /// Resuelve el objetivo y exige que TODAS sus direcciones estén en
    /// alcance.
    ///
    /// A las herramientas se les pasan las IPs que salen de aquí, nunca
    /// el nombre: así ninguna puede volver a resolver por su cuenta y
    /// acabar tocando algo que el guard nunca llegó a ver.
    ///
    /// Un nombre que apunta dentro y fuera a la vez se rechaza entero. No
    /// hay resolución parcial: sería justo el caso en el que un objetivo
    /// no autorizado entra por la puerta de atrás.
    pub fn validate_target(&self, target: &str, r: &dyn Resolver) -> Result<Vec<ScopedTarget>> {
        let t = target.trim();
        if t.is_empty() {
            return Err(AppError::InvalidAddress(target.to_string()));
        }

        if let Ok(ip) = t.parse::<IpAddr>() {
            return Ok(vec![self.validate_ip(ip)?]);
        }

        let ips = r
            .resolve(t)
            .map_err(|_| AppError::UnresolvableHost(t.to_string()))?;
        if ips.is_empty() {
            return Err(AppError::UnresolvableHost(t.to_string()));
        }

        // collect sobre Result corta en el primer error: todo o nada.
        ips.into_iter().map(|ip| self.validate_ip(ip)).collect()
    }
}
