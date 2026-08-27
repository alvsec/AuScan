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
/// El emparejamiento es por igualdad EXACTA, nunca por prefijo: antes de
/// este rediseño, `"-sS".starts_with("-s")` colaba `-sS` bajo un
/// `allowed_flags` que solo pretendía permitir `-s`, y
/// `"-p198.51.100.200"` colaba una IP sin validar pegada a `-p`. Una
/// bandera marcada `takes_value` consume el siguiente token del argv
/// como valor opaco, sin intentar casarlo como otra bandera: así el
/// valor nunca puede confundirse con un flag ni con una dirección.
///
/// **Cerrado en la Fase 5:** `invocation_privileged` lo pone quien
/// llama. Antes de esta fase, la única llamadora (`verja()`) lo sacaba
/// de `Invocation.needs_privilege` — el propio adaptador
/// autocertificándose. Ahora `verja()` recibe el privilegio efectivo
/// del proceso como parámetro explícito y es eso lo que llega aquí.
pub fn validate_flags(
    argv: &[String],
    descriptor: &ToolDescriptor,
    invocation_privileged: bool,
) -> Result<()> {
    let mut i = 0;
    while i < argv.len() {
        let token = &argv[i];
        if token.trim().parse::<IpAddr>().is_ok() {
            i += 1;
            continue;
        }
        let flag = descriptor.allowed_flags.iter().find(|f| f.name == token);
        match flag {
            None => return Err(AppError::FlagNotAllowed(token.clone())),
            Some(f) if f.needs_privilege && !invocation_privileged => {
                return Err(AppError::PrivilegeRequired(token.clone()));
            }
            Some(f) if f.takes_value => i += 2,
            Some(_) => i += 1,
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

/// Las tres comprobaciones juntas, en el orden en que el orquestador las
/// llama antes de cada `spawn`, para todos los adaptadores, sin excepción.
///
/// `effective_privileged` es el privilegio REAL del proceso en este
/// instante (`preflight::running_privileged()` o equivalente) — nunca
/// `invocation.needs_privilege`, que lo declara el propio adaptador. Un
/// adaptador con un fallo (o malicioso) podría marcar `needs_privilege`
/// y aun así intentar ejecutarse sin privilegios de verdad si esta
/// función se fiase de esa autocertificación; por eso el privilegio
/// efectivo entra como parámetro aparte, puesto por quien tiene
/// autoridad para saberlo.
pub fn verja(
    invocation: &Invocation,
    binary_path: &Path,
    descriptor: &ToolDescriptor,
    expected_path: &Path,
    effective_privileged: bool,
) -> Result<()> {
    validate_targets(&invocation.argv, &invocation.targets)?;
    validate_flags(&invocation.argv, descriptor, effective_privileged)?;
    validate_binary(binary_path, expected_path)?;
    Ok(())
}
