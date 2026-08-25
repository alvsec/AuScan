//! La verja: lo que se comprueba antes de lanzar cualquier proceso.
//!
//! Esta fase implementa las comprobaciones como funciones puras. El
//! `spawn` real —y por tanto el único sitio donde se llaman en
//! producción— llega en la Fase 5. Separar la validación de la
//! ejecución es lo que las hace testeables sin lanzar ningún proceso.

use std::net::IpAddr;
use std::path::Path;

use crate::adapters::{Invocation, ToolDescriptor};
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
        let trimmed = token.trim();
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            if !targets.iter().any(|t| t.ip() == ip) {
                return Err(AppError::UnvalidatedTarget(token.clone()));
            }
            continue;
        }
        if let Some((host, resto)) = trimmed.split_once('/') {
            if host.parse::<IpAddr>().is_ok() && resto.chars().all(|c| c.is_ascii_digit()) {
                return Err(AppError::UnvalidatedTarget(token.clone()));
            }
        }
    }
    Ok(())
}

/// Comprobación 2 de la verja: ninguna bandera fuera de
/// `descriptor.allowed_flags`, y ninguna marcada `needs_privilege` sin
/// que la invocación sea privilegiada.
///
/// Los tokens que ya cubre `validate_targets` (los que parsean como
/// dirección) se ignoran aquí: lo que queda son banderas. El
/// emparejamiento es por prefijo, no exacto, porque una bandera puede
/// llevar un valor pegado (`-PS80,443,22` casa con el flag `-PS`).
///
/// **Límite conocido:** `invocation_privileged` lo pone quien llama, a
/// partir de `Invocation.needs_privilege` — y ese campo hoy lo fija el
/// propio adaptador, sin que nada lo verifique contra el privilegio real
/// del proceso (`preflight::running_privileged()` o equivalente). Es un
/// hueco identificado y en seguimiento: antes de que la Fase 5 conecte la
/// ejecución real, quien llame a `verja()` debe pasar un valor derivado
/// del privilegio efectivo, no de lo que el propio adaptador declare de sí
/// mismo — si no, un adaptador con un bug (o malicioso) podría marcar
/// `needs_privilege` y pasar esta comprobación corriendo sin privilegios.
pub fn validate_flags(
    argv: &[String],
    descriptor: &ToolDescriptor,
    invocation_privileged: bool,
) -> Result<()> {
    for token in argv {
        if token.trim().parse::<IpAddr>().is_ok() {
            continue;
        }
        let flag = descriptor
            .allowed_flags
            .iter()
            .find(|f| token.starts_with(f.name));
        match flag {
            None => return Err(AppError::FlagNotAllowed(token.clone())),
            Some(f) if f.needs_privilege && !invocation_privileged => {
                return Err(AppError::PrivilegeRequired(token.clone()));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// Comprobación 3 de la verja: el binario que el argv va a ejecutar es
/// exactamente el que preflight resolvió — ni `PATH`, ni un binario
/// aparecido en el directorio actual entre el arranque y la ejecución.
pub fn validate_binary(binary_path: &Path, expected_path: &Path) -> Result<()> {
    if binary_path != expected_path {
        return Err(AppError::BinaryMismatch {
            expected: expected_path.display().to_string(),
            actual: binary_path.display().to_string(),
        });
    }
    Ok(())
}

/// Las tres comprobaciones juntas, en el orden en que la Fase 5 las
/// llamará antes de cada `spawn`, para todos los adaptadores, sin
/// excepción.
pub fn verja(
    invocation: &Invocation,
    binary_path: &Path,
    descriptor: &ToolDescriptor,
    expected_path: &Path,
) -> Result<()> {
    validate_targets(&invocation.argv, &invocation.targets)?;
    validate_flags(&invocation.argv, descriptor, invocation.needs_privilege)?;
    validate_binary(binary_path, expected_path)?;
    Ok(())
}
