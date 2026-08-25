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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FileVaultStatus {
    On,
    Off,
    Unknown,
}

/// Interpreta la salida de `fdesetup status`. Función pura: la IO real
/// vive en `filevault_status`, más abajo.
pub fn parse_filevault_status(fdesetup_stdout: &str) -> FileVaultStatus {
    let texto = fdesetup_stdout.to_lowercase();
    if texto.contains("filevault is on") {
        FileVaultStatus::On
    } else if texto.contains("filevault is off") {
        FileVaultStatus::Off
    } else {
        FileVaultStatus::Unknown
    }
}

pub fn filevault_status() -> FileVaultStatus {
    #[cfg(target_os = "macos")]
    {
        match std::process::Command::new("fdesetup")
            .arg("status")
            .output()
        {
            Ok(o) => parse_filevault_status(&String::from_utf8_lossy(&o.stdout)),
            Err(_) => FileVaultStatus::Unknown,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        FileVaultStatus::Unknown
    }
}

/// ¿Corre YA el proceso actual con privilegios elevados? No confundir
/// con "¿podría elevarse?" — eso depende de una capacidad de elevación
/// que todavía no existe (ADR-0004 sigue en propuesta).
pub fn running_privileged() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid() no tiene precondiciones; siempre es segura.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

use crate::adapters::InstallHint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Macos,
    Windows,
}

pub fn current_platform() -> Platform {
    #[cfg(target_os = "windows")]
    {
        Platform::Windows
    }
    #[cfg(not(target_os = "windows"))]
    {
        Platform::Macos
    }
}

pub fn install_display_command(hint: &InstallHint, platform: Platform) -> String {
    match platform {
        Platform::Macos => format!("brew {}", hint.brew.join(" ")),
        Platform::Windows => format!("winget {}", hint.winget.join(" ")),
    }
}

fn install_argv(hint: &InstallHint, platform: Platform) -> (&'static str, Vec<&'static str>) {
    match platform {
        Platform::Macos => ("brew", hint.brew.to_vec()),
        Platform::Windows => ("winget", hint.winget.to_vec()),
    }
}

/// Ejecuta el comando de instalación. Se llama solo tras confirmación
/// explícita del operador — nunca automáticamente.
pub fn run_install(
    hint: &InstallHint,
    platform: Platform,
) -> std::io::Result<std::process::Output> {
    let (program, args) = install_argv(hint, platform);
    std::process::Command::new(program).args(args).output()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconoce_filevault_activado() {
        assert_eq!(
            parse_filevault_status("FileVault is On.\n"),
            FileVaultStatus::On
        );
    }

    #[test]
    fn reconoce_filevault_desactivado() {
        assert_eq!(
            parse_filevault_status("FileVault is Off.\n"),
            FileVaultStatus::Off
        );
    }

    #[test]
    fn una_salida_irreconocible_es_desconocida() {
        assert_eq!(
            parse_filevault_status("algo inesperado"),
            FileVaultStatus::Unknown
        );
    }

    #[test]
    fn el_reconocimiento_no_distingue_mayusculas() {
        assert_eq!(
            parse_filevault_status("FILEVAULT IS ON."),
            FileVaultStatus::On
        );
    }

    #[test]
    fn el_comando_de_macos_usa_brew() {
        let hint = InstallHint {
            brew: &["install", "fake-tool"],
            winget: &["install", "-e", "X"],
        };
        assert_eq!(
            install_display_command(&hint, Platform::Macos),
            "brew install fake-tool"
        );
    }

    #[test]
    fn el_comando_de_windows_usa_winget() {
        let hint = InstallHint {
            brew: &["install", "fake-tool"],
            winget: &["install", "-e", "Example.FakeTool"],
        };
        assert_eq!(
            install_display_command(&hint, Platform::Windows),
            "winget install -e Example.FakeTool"
        );
    }

    #[test]
    fn install_argv_construye_brew_o_winget_segun_la_plataforma() {
        let hint = InstallHint {
            brew: &["install", "fake-tool"],
            winget: &["install", "-e", "X"],
        };
        assert_eq!(
            install_argv(&hint, Platform::Macos),
            ("brew", vec!["install", "fake-tool"])
        );
        assert_eq!(
            install_argv(&hint, Platform::Windows),
            ("winget", vec!["install", "-e", "X"])
        );
    }
}
