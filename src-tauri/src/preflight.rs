//! Detección de herramientas instaladas y matriz de capacidades.

use std::path::PathBuf;

use serde::Serialize;

use crate::adapters::ToolAdapter;
use crate::error::{AppError, Result};

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

/// A partir de la salida cruda de un proceso de instalación, decide si
/// fue un éxito (devuelve su stdout) o un fallo (devuelve el error con
/// código de salida y stderr). Función pura: no ejecuta nada, solo
/// interpreta un `Output` ya obtenido.
pub fn interpret_install_output(tool_id: &str, salida: std::process::Output) -> Result<String> {
    if salida.status.success() {
        Ok(String::from_utf8_lossy(&salida.stdout).into_owned())
    } else {
        Err(AppError::InstallFailed {
            tool: tool_id.to_string(),
            code: salida.status.code(),
            stderr: String::from_utf8_lossy(&salida.stderr).into_owned(),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolReport {
    pub tool_id: String,
    pub status: ToolStatus,
    pub install_command: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreflightReport {
    pub tools: Vec<ToolReport>,
    pub privileged: bool,
    pub filevault: FileVaultStatus,
}

/// Ejecuta la detección completa: por cada adaptador del registro,
/// resuelve su binario en PATH y compara versión; añade la matriz de
/// capacidades. Es la única función de este módulo que hace IO real de
/// principio a fin — todo lo que envuelve ya está testeado por separado.
pub fn run_preflight(adapters: &[Box<dyn ToolAdapter>]) -> PreflightReport {
    let platform = current_platform();
    let tools = adapters
        .iter()
        .map(|a| {
            let descriptor = a.descriptor();
            let status = check_tool(
                a.as_ref(),
                |b| which::which(b).ok(),
                |path, argv| {
                    std::process::Command::new(path)
                        .args(argv)
                        .output()
                        .map(|o| o.stdout)
                },
            );
            ToolReport {
                tool_id: descriptor.id.to_string(),
                install_command: install_display_command(&descriptor.install_hint, platform),
                status,
            }
        })
        .collect();
    PreflightReport {
        tools,
        privileged: running_privileged(),
        filevault: filevault_status(),
    }
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

    // `interpret_install_output` es la lógica de decisión que antes vivía
    // sin tests dentro del comando Tauri `preflight_install`. No probamos
    // `run_install` en sí (llama a `brew`/`winget` de verdad — ver el
    // commit "eliminar test de run_install que ejecuta procesos reales");
    // en cambio, construimos un `std::process::Output` real pero inocuo
    // ejecutando `sh`/`cmd` con un script trivial, y comprobamos que la
    // función pura lo interpreta bien. Es más simple y portable entre
    // macOS y Windows (donde corre CI) que fabricar a mano un
    // `ExitStatus`, que no tiene constructor público estable y cuya
    // codificación en crudo difiere por plataforma.
    #[cfg(unix)]
    fn salida_de_exito_con_stdout() -> std::process::Output {
        std::process::Command::new("sh")
            .args(["-c", "echo hola-de-prueba"])
            .output()
            .expect("no se pudo ejecutar sh para la prueba")
    }

    #[cfg(windows)]
    fn salida_de_exito_con_stdout() -> std::process::Output {
        std::process::Command::new("cmd")
            .args(["/C", "echo hola-de-prueba"])
            .output()
            .expect("no se pudo ejecutar cmd para la prueba")
    }

    #[cfg(unix)]
    fn salida_de_fallo_con_stderr() -> std::process::Output {
        std::process::Command::new("sh")
            .args(["-c", "echo fallo-de-prueba 1>&2; exit 7"])
            .output()
            .expect("no se pudo ejecutar sh para la prueba")
    }

    #[cfg(windows)]
    fn salida_de_fallo_con_stderr() -> std::process::Output {
        std::process::Command::new("cmd")
            .args(["/C", "echo fallo-de-prueba 1>&2 & exit 7"])
            .output()
            .expect("no se pudo ejecutar cmd para la prueba")
    }

    #[test]
    fn interpret_install_output_devuelve_ok_con_el_stdout_cuando_el_proceso_tiene_exito() {
        let salida = salida_de_exito_con_stdout();
        let resultado = interpret_install_output("fake", salida);
        assert_eq!(resultado.unwrap().trim(), "hola-de-prueba");
    }

    #[test]
    fn interpret_install_output_devuelve_installfailed_con_el_codigo_cuando_el_proceso_falla() {
        let salida = salida_de_fallo_con_stderr();
        match interpret_install_output("fake", salida) {
            Err(AppError::InstallFailed { tool, code, .. }) => {
                assert_eq!(tool, "fake");
                assert_eq!(code, Some(7));
            }
            otro => panic!("se esperaba InstallFailed, fue {otro:?}"),
        }
    }

    #[test]
    fn interpret_install_output_captura_el_stderr_cuando_el_proceso_falla() {
        let salida = salida_de_fallo_con_stderr();
        match interpret_install_output("fake", salida) {
            Err(AppError::InstallFailed { stderr, .. }) => {
                assert!(stderr.contains("fallo-de-prueba"));
            }
            otro => panic!("se esperaba InstallFailed, fue {otro:?}"),
        }
    }
}
