//! La verja: lo que se comprueba antes de lanzar cualquier proceso.
//!
//! Esta fase implementa las comprobaciones como funciones puras. El
//! `spawn` real —y por tanto el único sitio donde se llaman en
//! producción— llega en la Fase 5. Separar la validación de la
//! ejecución es lo que las hace testeables sin lanzar ningún proceso.

use std::net::IpAddr;

use crate::error::{AppError, Result};
use crate::scope::ScopedTarget;

/// Comprobación 1 de la verja: ningún objetivo sin validar.
///
/// Escanea el argv en busca de tokens con forma de dirección y exige que
/// toda IP suelta esté entre los `targets` que el guard ya validó.
/// Cualquier token con forma de CIDR (dirección/prefijo) se rechaza sin
/// más: `ScopedTarget` nunca lleva rango, así que un adaptador que
/// interpolase uno a mano falla ruidosamente en vez de escanear a un
/// tercero.
pub fn validate_targets(argv: &[String], targets: &[ScopedTarget]) -> Result<()> {
    for token in argv {
        if let Ok(ip) = token.parse::<IpAddr>() {
            if !targets.iter().any(|t| t.ip() == ip) {
                return Err(AppError::UnvalidatedTarget(token.clone()));
            }
            continue;
        }
        if let Some((host, resto)) = token.split_once('/') {
            if host.parse::<IpAddr>().is_ok() && resto.chars().all(|c| c.is_ascii_digit()) {
                return Err(AppError::UnvalidatedTarget(token.clone()));
            }
        }
    }
    Ok(())
}
