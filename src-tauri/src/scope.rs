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
