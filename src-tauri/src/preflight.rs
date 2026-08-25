//! Detección de herramientas instaladas y matriz de capacidades.

use std::path::PathBuf;

use serde::Serialize;

use crate::adapters::ToolAdapter;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ToolStatus {
    Ok {
        path: String,
        version: String,
    },
    TooOld {
        path: String,
        version: String,
        minimum: String,
    },
    Missing,
    Unparseable {
        path: String,
        raw: String,
    },
}

/// Resuelve la versión instalada de una herramienta y la compara con el
/// mínimo exigido.
///
/// `resolve` y `run` se inyectan para poder testear sin depender de
/// binarios reales en el sistema.
pub fn check_tool(
    adapter: &dyn ToolAdapter,
    resolve: impl Fn(&str) -> Option<PathBuf>,
    run: impl Fn(&PathBuf, &[String]) -> std::io::Result<Vec<u8>>,
) -> ToolStatus {
    let descriptor = adapter.descriptor();

    let Some(path) = descriptor.binaries.iter().find_map(|b| resolve(b)) else {
        return ToolStatus::Missing;
    };

    let salida = match run(&path, &adapter.version_argv()) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(_) => {
            return ToolStatus::Unparseable {
                path: path.display().to_string(),
                raw: String::new(),
            }
        }
    };

    match adapter.parse_version(&salida) {
        Ok(v) if v >= descriptor.min_version => ToolStatus::Ok {
            path: path.display().to_string(),
            version: v.to_string(),
        },
        Ok(v) => ToolStatus::TooOld {
            path: path.display().to_string(),
            version: v.to_string(),
            minimum: descriptor.min_version.to_string(),
        },
        Err(_) => ToolStatus::Unparseable {
            path: path.display().to_string(),
            raw: salida,
        },
    }
}
