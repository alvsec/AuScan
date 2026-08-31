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
#[cfg(target_os = "macos")]
pub(crate) fn citar_para_shell(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Cita una cadena como literal de AppleScript para interpolarla dentro
/// de un `do shell script "..."`. AppleScript escapa con `\` dentro de
/// una cadena entre comillas dobles: hay que escapar las barras
/// invertidas ANTES que las comillas, o una comilla ya escapada
/// quedaría doblemente escapada.
#[cfg(target_os = "macos")]
pub(crate) fn citar_para_applescript(s: &str) -> String {
    let escapado = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escapado}\"")
}

use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::exec::{AcumuladorLineas, Linea, LineaOrigen, ResultadoEjecucion};

const INTERVALO_SONDEO_LECTURA: Duration = Duration::from_millis(200);

/// Un trabajador elevado vivo, con su propio directorio de control.
/// `detener_trabajador` es lo único que lo cierra correctamente --
/// dejar caer este valor sin llamarla deja el proceso root esperando
/// órdenes para siempre (por diseño no se implementa `Drop`: cerrar un
/// proceso privilegiado en el destructor de un valor normal, sin poder
/// propagar el error de esa operación, es peor que exigir un cierre
/// explícito).
pub struct TrabajadorActivo {
    dir_control: PathBuf,
    #[cfg(target_os = "macos")]
    osascript: Option<tokio::process::Child>,
}

impl TrabajadorActivo {
    /// Solo para tests: construye un `TrabajadorActivo` que apunta a un
    /// trabajador ya arrancado a mano (saltándose `osascript`, como en
    /// `tests/worker.rs`), para probar `ejecutar_privilegiado` sin
    /// necesitar privilegios de verdad ni un diálogo real.
    #[doc(hidden)]
    pub fn para_pruebas(dir_control: PathBuf) -> Self {
        Self {
            dir_control,
            #[cfg(target_os = "macos")]
            osascript: None,
        }
    }
}

/// Arranca el trabajador elevado para una fase. Resuelve la ruta del
/// binario hermano del propio paquete (nunca una ruta que dependa de
/// dónde esté instalada la app en el sistema del cliente), lo lanza vía
/// `osascript ... with administrator privileges`, y espera a que el
/// propio proceso confirme por escrito que de verdad es root.
///
/// Si el operador rechaza el diálogo, si `osascript` falla, o si el
/// trabajador arranca pero NO es root (entorno raro, no debería pasar
/// nunca) -- error, sin excepción. No hay un modo "casi elevado": ver
/// la Global Constraint sobre `elevar` al principio del plan.
#[cfg(target_os = "macos")]
pub async fn iniciar_trabajador(dir_control: &Path) -> Result<TrabajadorActivo> {
    const PLAZO_ARRANQUE: Duration = Duration::from_secs(120);

    std::fs::create_dir_all(dir_control).map_err(AppError::Io)?;

    let binario_trabajador = std::env::current_exe()
        .map_err(AppError::Io)?
        .parent()
        .ok_or_else(|| {
            AppError::ElevationFailed("no se pudo localizar el binario propio".to_string())
        })?
        .join("privileged-worker");
    if !binario_trabajador.exists() {
        return Err(AppError::ElevationFailed(format!(
            "no se encontró el binario del trabajador en {}",
            binario_trabajador.display()
        )));
    }

    // Ni la ruta del binario ni la del directorio de control vienen de
    // texto libre del operador -- salen de `current_exe()` y de este
    // mismo proceso -- pero se citan lo mismo, por si acaso: es el
    // mismo principio que aplica la verja a los argv de un adaptador.
    let comando_interno = format!(
        "{} {}",
        citar_para_shell(&binario_trabajador.display().to_string()),
        citar_para_shell(&dir_control.display().to_string())
    );
    let script = format!(
        "do shell script {} with administrator privileges",
        citar_para_applescript(&comando_interno)
    );

    let osascript = tokio::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(AppError::Io)?;

    let plazo = tokio::time::Instant::now() + PLAZO_ARRANQUE;
    loop {
        if let Some(listo) = leer_listo(dir_control)? {
            if !listo.es_root {
                return Err(AppError::ElevationFailed(
                    "el trabajador arrancó pero no es root".to_string(),
                ));
            }
            return Ok(TrabajadorActivo {
                dir_control: dir_control.to_path_buf(),
                osascript: Some(osascript),
            });
        }
        if tokio::time::Instant::now() >= plazo {
            return Err(AppError::ElevationFailed(
                "el operador no autorizó la elevación a tiempo".to_string(),
            ));
        }
        tokio::time::sleep(INTERVALO_SONDEO_LECTURA).await;
    }
}

/// Para el trabajador y limpia su directorio de control. Marca el
/// centinela de detener -- el propio proceso root se apaga solo, la
/// app no puede matarlo directamente -- y espera a que `osascript`
/// termine antes de borrar nada, para no borrar ficheros que el
/// trabajador todavía pudiera tocar.
///
/// El borrado solo ocurre tras esperar de verdad a `osascript`: eso
/// es lo que demuestra que el proceso elevado ya leyó el centinela y
/// terminó -- `do shell script ... with administrator privileges` no
/// vuelve hasta que el comando interior (el propio `privileged-worker`)
/// sale. Sin esa espera, borrar el directorio justo después de escribir
/// el centinela es una carrera que el trabajador pierde siempre: su
/// próximo sondeo vería `hay_detener()` y `leer_orden()` sobre un
/// directorio que ya no existe (ambos devuelven "no está", nunca un
/// error) y se quedaría dando vueltas para siempre. Por eso, cuando
/// `trabajador` se construyó con `para_pruebas` (sin `osascript` real
/// que esperar), esta función NO borra nada -- no hay forma honesta de
/// saber desde aquí que el trabajador ya terminó -- y deja esa limpieza
/// al `tempfile::TempDir` propio del test, que borra solo al salir de
/// scope.
pub async fn detener_trabajador(mut trabajador: TrabajadorActivo) -> Result<()> {
    marcar_detener(&trabajador.dir_control)?;
    #[cfg(target_os = "macos")]
    if let Some(mut hijo) = trabajador.osascript.take() {
        let _ = hijo.wait().await;
        let _ = std::fs::remove_dir_all(&trabajador.dir_control);
    }
    Ok(())
}

/// Le pide al trabajador que ejecute `binary_path argv`, y hace tail de
/// su salida exactamente como `exec::ejecutar()` hace tail de una
/// tubería -- misma forma de retorno, mismo `AcumuladorLineas`, para
/// que quien llama (`orchestrator.rs`) no note la diferencia más allá
/// de qué función invocó.
///
/// El token se mira ANTES de escribir la orden, no solo dentro del
/// bucle de sondeo -- el mismo motivo por el que `exec::ejecutar()` lo
/// mira antes de su `spawn()` (ver el comentario allí y
/// `tests/exec_spawn.rs::ejecutar_con_el_token_ya_cancelado_ni_siquiera_lanza_el_proceso`).
/// Con una fase de varias invocaciones (Services planifica una por
/// host), no comprobarlo aquí antes de escribir la orden le pediría
/// al trabajador que lanzara igualmente un escáner de verdad contra
/// cada host restante, para matarlo un sondeo después -- exactamente
/// el bug que esa comprobación evita en el camino sin privilegios.
#[allow(clippy::too_many_arguments)]
pub async fn ejecutar_privilegiado(
    trabajador: &TrabajadorActivo,
    seq: i64,
    binary_path: &Path,
    argv: &[String],
    timeout: Duration,
    cancelar: CancellationToken,
    mut on_linea: impl FnMut(Linea),
) -> Result<ResultadoEjecucion> {
    if cancelar.is_cancelled() {
        return Ok(ResultadoEjecucion {
            raw: Vec::new(),
            stderr: Vec::new(),
            exit_code: None,
            cancelado: true,
        });
    }

    let dir_control = &trabajador.dir_control;
    let orden = Orden {
        binario: binary_path.to_path_buf(),
        argv: argv.to_vec(),
        ruta_stdout: ruta_stdout(dir_control, seq),
        ruta_stderr: ruta_stderr(dir_control, seq),
    };
    escribir_orden(dir_control, seq, &orden)?;

    let mut pos_stdout: u64 = 0;
    let mut pos_stderr: u64 = 0;
    let mut acc_stdout = AcumuladorLineas::nuevo();
    let mut acc_stderr = AcumuladorLineas::nuevo();
    let mut raw = Vec::new();
    let mut stderr_completo = Vec::new();
    let plazo = tokio::time::Instant::now() + timeout;

    loop {
        leer_nuevo(
            &orden.ruta_stdout,
            &mut pos_stdout,
            &mut acc_stdout,
            &mut raw,
            LineaOrigen::Stdout,
            &mut on_linea,
        )?;
        leer_nuevo(
            &orden.ruta_stderr,
            &mut pos_stderr,
            &mut acc_stderr,
            &mut stderr_completo,
            LineaOrigen::Stderr,
            &mut on_linea,
        )?;

        if let Some(estado) = leer_estado(dir_control, seq)? {
            // Última pasada, por si quedó algo entre el último sondeo y
            // que el trabajador escribiera el estado.
            leer_nuevo(
                &orden.ruta_stdout,
                &mut pos_stdout,
                &mut acc_stdout,
                &mut raw,
                LineaOrigen::Stdout,
                &mut on_linea,
            )?;
            leer_nuevo(
                &orden.ruta_stderr,
                &mut pos_stderr,
                &mut acc_stderr,
                &mut stderr_completo,
                LineaOrigen::Stderr,
                &mut on_linea,
            )?;
            return Ok(ResultadoEjecucion {
                raw,
                stderr: stderr_completo,
                exit_code: estado.exit_code,
                cancelado: false,
            });
        }

        if cancelar.is_cancelled() || tokio::time::Instant::now() >= plazo {
            marcar_cancelar(dir_control)?;
            // El trabajador es quien mata a su hijo -- esta función
            // solo espera a que confirme que ya lo hizo, con el mismo
            // sondeo del estado que el camino normal.
            loop {
                if leer_estado(dir_control, seq)?.is_some() {
                    break;
                }
                tokio::time::sleep(INTERVALO_SONDEO_LECTURA).await;
            }
            return Ok(ResultadoEjecucion {
                raw,
                stderr: stderr_completo,
                exit_code: None,
                cancelado: true,
            });
        }

        tokio::time::sleep(INTERVALO_SONDEO_LECTURA).await;
    }
}

#[allow(clippy::too_many_arguments)]
fn leer_nuevo(
    ruta: &Path,
    posicion: &mut u64,
    acumulador: &mut AcumuladorLineas,
    destino_bytes: &mut Vec<u8>,
    origen: LineaOrigen,
    on_linea: &mut impl FnMut(Linea),
) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom};

    let Ok(mut f) = std::fs::File::open(ruta) else {
        return Ok(()); // el trabajador todavía no ha creado el fichero
    };
    f.seek(SeekFrom::Start(*posicion)).map_err(AppError::Io)?;
    let mut buf = Vec::new();
    let leidos = f.read_to_end(&mut buf).map_err(AppError::Io)?;
    if leidos == 0 {
        return Ok(());
    }
    *posicion += leidos as u64;
    destino_bytes.extend_from_slice(&buf);
    for linea in acumulador.alimentar(&buf) {
        on_linea(Linea {
            origen,
            texto: linea,
        });
    }
    Ok(())
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
