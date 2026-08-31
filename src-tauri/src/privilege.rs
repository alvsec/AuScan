//! Protocolo de control con el trabajador elevado (Fase 6, spec §8.10).
//! Todo el intercambio con el proceso que corre `with administrator
//! privileges` pasa por ficheros normales en un directorio temporal
//! por fase -- nunca un FIFO, para no toparse con permisos entre un
//! dueño root y uno normal, y porque es literalmente el mecanismo que
//! el spike de la spec (§8.7) validó: redirigir a fichero y leerlo por
//! cuenta propia mientras el proceso elevado sigue vivo.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};

/// Lo que el proceso principal le pide al trabajador que ejecute. Solo
/// datos -- ningún campo de este tipo decide nada por sí mismo, todo lo
/// que hay aquí ya pasó por el guard y la verja antes de construirse.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Orden {
    pub binario: PathBuf,
    pub argv: Vec<String>,
    pub ruta_stdout: PathBuf,
    pub ruta_stderr: PathBuf,
}

/// Lo que el trabajador informa al terminar una orden.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Estado {
    pub exit_code: Option<i32>,
}

/// Lo que el trabajador escribe nada más arrancar, antes de aceptar
/// ninguna orden: si de verdad es root, medido DESDE DENTRO de sí
/// mismo. `osascript` puede devolver éxito sin que el script interior
/// se haya elevado de verdad si algo del entorno falla de forma rara --
/// lo único que cuenta para decidir `PlanContext.privileged` es lo que
/// el propio proceso mide sobre sí mismo, nunca lo que el lanzador
/// dijo. Ver la Global Constraint sobre `elevar` al principio del plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Listo {
    pub es_root: bool,
}

fn ruta_orden(dir_control: &Path, seq: i64) -> PathBuf {
    dir_control.join(format!("{seq:04}.orden.json"))
}

fn ruta_estado(dir_control: &Path, seq: i64) -> PathBuf {
    dir_control.join(format!("{seq:04}.estado.json"))
}

pub fn ruta_stdout(dir_control: &Path, seq: i64) -> PathBuf {
    dir_control.join(format!("{seq:04}.stdout"))
}

pub fn ruta_stderr(dir_control: &Path, seq: i64) -> PathBuf {
    dir_control.join(format!("{seq:04}.stderr"))
}

fn ruta_listo(dir_control: &Path) -> PathBuf {
    dir_control.join("listo.json")
}

fn ruta_cancelar(dir_control: &Path) -> PathBuf {
    dir_control.join("cancelar")
}

fn ruta_detener(dir_control: &Path) -> PathBuf {
    dir_control.join("detener")
}

pub fn escribir_orden(dir_control: &Path, seq: i64, orden: &Orden) -> Result<()> {
    let json = serde_json::to_string(orden).expect("Orden siempre serializa");
    std::fs::write(ruta_orden(dir_control, seq), json).map_err(AppError::Io)
}

pub fn leer_orden(dir_control: &Path, seq: i64) -> Result<Option<Orden>> {
    let ruta = ruta_orden(dir_control, seq);
    if !ruta.exists() {
        return Ok(None);
    }
    let texto = std::fs::read_to_string(&ruta).map_err(AppError::Io)?;
    serde_json::from_str(&texto)
        .map(Some)
        .map_err(|e| AppError::ProtocoloElevacion(e.to_string()))
}

pub fn escribir_estado(dir_control: &Path, seq: i64, estado: &Estado) -> Result<()> {
    let json = serde_json::to_string(estado).expect("Estado siempre serializa");
    std::fs::write(ruta_estado(dir_control, seq), json).map_err(AppError::Io)
}

pub fn leer_estado(dir_control: &Path, seq: i64) -> Result<Option<Estado>> {
    let ruta = ruta_estado(dir_control, seq);
    if !ruta.exists() {
        return Ok(None);
    }
    let texto = std::fs::read_to_string(&ruta).map_err(AppError::Io)?;
    serde_json::from_str(&texto)
        .map(Some)
        .map_err(|e| AppError::ProtocoloElevacion(e.to_string()))
}

pub fn escribir_listo(dir_control: &Path, listo: &Listo) -> Result<()> {
    let json = serde_json::to_string(listo).expect("Listo siempre serializa");
    std::fs::write(ruta_listo(dir_control), json).map_err(AppError::Io)
}

pub fn leer_listo(dir_control: &Path) -> Result<Option<Listo>> {
    let ruta = ruta_listo(dir_control);
    if !ruta.exists() {
        return Ok(None);
    }
    let texto = std::fs::read_to_string(&ruta).map_err(AppError::Io)?;
    serde_json::from_str(&texto)
        .map(Some)
        .map_err(|e| AppError::ProtocoloElevacion(e.to_string()))
}

pub fn marcar_cancelar(dir_control: &Path) -> Result<()> {
    std::fs::write(ruta_cancelar(dir_control), b"").map_err(AppError::Io)
}

pub fn hay_cancelar(dir_control: &Path) -> bool {
    ruta_cancelar(dir_control).exists()
}

pub fn marcar_detener(dir_control: &Path) -> Result<()> {
    std::fs::write(ruta_detener(dir_control), b"").map_err(AppError::Io)
}

pub fn hay_detener(dir_control: &Path) -> bool {
    ruta_detener(dir_control).exists()
}

/// Cita una cadena para pasarla como un único argumento literal a `sh`
/// — comillas simples, con el truco POSIX estándar para una comilla
/// simple embebida: se cierra la comilla, se escapa una comilla simple
/// literal, se vuelve a abrir.
///
/// `allow(dead_code)`: solo se consume desde los tests hasta la Tarea 4
/// (construcción del invocador de `osascript`), que es quien monta la
/// invocación real con esta función.
#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub(crate) fn citar_para_shell(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Cita una cadena como literal de AppleScript para interpolarla dentro
/// de un `do shell script "..."`. AppleScript escapa con `\` dentro de
/// una cadena entre comillas dobles: hay que escapar las barras
/// invertidas ANTES que las comillas, o una comilla ya escapada
/// quedaría doblemente escapada.
///
/// `allow(dead_code)`: mismo motivo que `citar_para_shell` — su
/// consumidor llega en la Tarea 4.
#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub(crate) fn citar_para_applescript(s: &str) -> String {
    let escapado = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escapado}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn una_orden_sobrevive_a_escribirse_y_leerse() {
        let dir = tempfile::tempdir().unwrap();
        let orden = Orden {
            binario: PathBuf::from("/usr/bin/true"),
            argv: vec!["-x".to_string(), "198.51.100.5".to_string()],
            ruta_stdout: dir.path().join("0001.stdout"),
            ruta_stderr: dir.path().join("0001.stderr"),
        };
        escribir_orden(dir.path(), 1, &orden).unwrap();
        let leida = leer_orden(dir.path(), 1).unwrap();
        assert_eq!(leida, Some(orden));
    }

    #[test]
    fn leer_una_orden_que_no_existe_da_none_no_error() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(leer_orden(dir.path(), 99).unwrap(), None);
    }

    #[test]
    fn un_estado_sobrevive_a_escribirse_y_leerse() {
        let dir = tempfile::tempdir().unwrap();
        let estado = Estado { exit_code: Some(0) };
        escribir_estado(dir.path(), 1, &estado).unwrap();
        assert_eq!(leer_estado(dir.path(), 1).unwrap(), Some(estado));
    }

    #[test]
    fn un_listo_sobrevive_a_escribirse_y_leerse() {
        let dir = tempfile::tempdir().unwrap();
        escribir_listo(dir.path(), &Listo { es_root: true }).unwrap();
        assert_eq!(
            leer_listo(dir.path()).unwrap(),
            Some(Listo { es_root: true })
        );
    }

    #[test]
    fn los_centinelas_empiezan_ausentes_y_se_pueden_marcar() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!hay_cancelar(dir.path()));
        assert!(!hay_detener(dir.path()));
        marcar_cancelar(dir.path()).unwrap();
        marcar_detener(dir.path()).unwrap();
        assert!(hay_cancelar(dir.path()));
        assert!(hay_detener(dir.path()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn citar_para_shell_sobrevive_a_una_ejecucion_real() {
        for entrada in [
            "sencillo",
            "con espacio",
            "con'comilla",
            "con\"comillas dobles",
            "con$variable",
            "con`backtick`",
            "con;punto y coma",
            "con\\barra invertida",
        ] {
            let citado = citar_para_shell(entrada);
            let salida = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("printf '%s' {citado}"))
                .output()
                .unwrap();
            assert_eq!(
                String::from_utf8_lossy(&salida.stdout),
                entrada,
                "citar_para_shell no sobrevivió a: {entrada:?}"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn citar_para_applescript_sobrevive_a_una_ejecucion_real() {
        for entrada in [
            "sencillo",
            "con espacio",
            "con\"comillas\"",
            "con\\barra invertida",
            "con'comilla simple",
        ] {
            let citado = citar_para_applescript(entrada);
            let salida = std::process::Command::new("osascript")
                .arg("-e")
                .arg(format!("return {citado}"))
                .output()
                .unwrap();
            assert_eq!(
                String::from_utf8_lossy(&salida.stdout).trim_end(),
                entrada,
                "citar_para_applescript no sobrevivió a: {entrada:?}"
            );
        }
    }
}
