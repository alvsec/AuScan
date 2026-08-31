//! El bucle del trabajador elevado (spec §8.8-§8.9). Este módulo no
//! sabe que corre como root -- ni falta que le hace. Su única
//! responsabilidad es mecánica: leer una orden, lanzar exactamente ese
//! proceso, redirigir su salida a los ficheros indicados, matarlo si
//! aparece el centinela de cancelar, informar, y repetir hasta que
//! aparezca el de detener. Cero lógica de alcance o de política -- eso
//! ya se decidió en el proceso principal antes de que la orden llegara
//! aquí.
//!
//! Por eso es plenamente testeable SIN privilegios de verdad: nada de
//! lo que hace este bucle depende de ser root, así que los tests lo
//! corren como un proceso normal más (`src-tauri/tests/worker.rs`).

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{AppError, Result};
use crate::exec::matar;
use crate::privilege::{self, Estado, Listo, Orden};

const INTERVALO_SONDEO: Duration = Duration::from_millis(200);

/// Tope absoluto de vida del trabajador, pase lo que pase. Defensa en
/// profundidad barata, independiente de la comprobación del padre: si
/// por lo que sea esa comprobación no viera lo que tiene que ver, este
/// proceso root no se queda dando vueltas hasta el siguiente reinicio.
///
/// No borra el directorio de control al vencer, al revés que el camino
/// del padre muerto: si el tope salta con la app viva -- una fase
/// larguísima --, el directorio sigue teniendo dueño, y es
/// `detener_trabajador` quien lo recoge. La fase en curso se entera por
/// el plazo de su invocación (`privilege::PLAZO_CONFIRMACION_CANCELACION`),
/// que ya no espera para siempre.
const VIDA_MAXIMA: Duration = Duration::from_secs(6 * 60 * 60);

/// ¿Sigue existiendo el proceso `pid`? `kill` con la señal 0 no envía
/// nada: solo comprueba que el proceso está ahí.
///
/// Cualquier error cuenta como "ya no está". El que importa es `ESRCH`
/// (no existe); `EPERM` -- existe pero no se le puede señalar -- no
/// puede darse aquí, porque quien pregunta es root y root puede
/// señalar a cualquiera.
///
/// Límite conocido y aceptado: el sistema puede reciclar un pid. Que la
/// app muera y su número lo herede otro proceso en la ventana de un
/// sondeo dejaría a este trabajador creyendo que su padre sigue vivo;
/// para eso está el tope absoluto de vida.
#[cfg(unix)]
fn sigue_vivo(pid: u32) -> bool {
    // SAFETY: `kill` con señal 0 no tiene más precondición que un pid
    // válido; no toca memoria ni envía ninguna señal.
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

#[cfg(not(unix))]
fn sigue_vivo(_pid: u32) -> bool {
    // Fuera de Unix no hay elevación en este proyecto, así que este
    // bucle no llega a correr en producción. Se compila para que el
    // módulo entero siga siendo multiplataforma.
    true
}

/// Corre el bucle entero: escribe `listo` con su propio estado de
/// privilegio, luego procesa órdenes en orden hasta que aparece el
/// centinela de detener.
///
/// `pid_padre` es el proceso de la app que lo lanzó. El trabajador lo
/// vigila en cada sondeo porque NADIE MÁS lo va a hacer: `osascript ...
/// with administrator privileges` no cuelga este proceso del que lo
/// pidió, así que si la app se cierra a la fuerza o revienta con una
/// fase elevada en marcha, aquí queda un proceso root sondeando a 5 Hz
/// para siempre un directorio con la salida cruda de escaneos de un
/// cliente dentro, y sin nadie que vaya a borrarlo nunca. Si el padre ya
/// no está, este bucle recoge su propio directorio y se va.
pub async fn ejecutar_bucle(dir_control: PathBuf, pid_padre: u32) -> Result<()> {
    privilege::escribir_listo(
        &dir_control,
        &Listo {
            es_root: crate::preflight::running_privileged(),
        },
    )?;

    let fin_de_vida = tokio::time::Instant::now() + VIDA_MAXIMA;
    let mut seq: i64 = 1;
    loop {
        if privilege::hay_detener(&dir_control) {
            return Ok(());
        }
        if !sigue_vivo(pid_padre) {
            recoger_directorio(&dir_control);
            return Ok(());
        }
        if tokio::time::Instant::now() >= fin_de_vida {
            return Ok(());
        }
        match privilege::leer_orden(&dir_control, seq)? {
            Some(orden) => match procesar_orden(&dir_control, seq, &orden, pid_padre).await? {
                FinDeOrden::Siguiente => seq += 1,
                // Apareció el centinela de detener con la orden en
                // vuelo: no se vuelve a esperar nada, la app está
                // cerrando este trabajador.
                FinDeOrden::Detener => return Ok(()),
                // Y si quien se fue es la app, con el escaneo todavía
                // en marcha: el hijo ya está muerto y aquí no queda
                // nadie más que pueda recoger este directorio.
                FinDeOrden::PadreMuerto => {
                    recoger_directorio(&dir_control);
                    return Ok(());
                }
            },
            None => {
                tokio::time::sleep(INTERVALO_SONDEO).await;
            }
        }
    }
}

/// Borra el directorio de control. De mejor esfuerzo -- si falla no hay
/// a quién contárselo --, y es lo único que separa "la app se fue" de
/// "queda un directorio temporal con la salida cruda de escaneos de un
/// cliente y ningún dueño que vaya a recogerla".
fn recoger_directorio(dir_control: &Path) {
    let _ = std::fs::remove_dir_all(dir_control);
}

/// Cómo terminó una orden, visto desde el bucle.
enum FinDeOrden {
    /// La orden terminó -- bien, mal, o matada por el centinela de
    /// cancelar --: toca esperar la siguiente.
    Siguiente,
    /// Apareció el centinela de DETENER con el hijo todavía corriendo.
    /// El hijo ya está muerto y el bucle entero se acaba: no hay
    /// "siguiente orden" que esperar.
    Detener,
    /// La app que lanzó este trabajador desapareció con el escaneo en
    /// marcha. El hijo ya está muerto: nadie iba a recoger su salida.
    PadreMuerto,
}

async fn procesar_orden(
    dir_control: &Path,
    seq: i64,
    orden: &Orden,
    pid_padre: u32,
) -> Result<FinDeOrden> {
    let stdout_f = std::fs::File::create(&orden.ruta_stdout).map_err(AppError::Io)?;
    let stderr_f = std::fs::File::create(&orden.ruta_stderr).map_err(AppError::Io)?;

    let mut comando = tokio::process::Command::new(&orden.binario);
    comando
        .args(&orden.argv)
        .stdout(std::process::Stdio::from(stdout_f))
        .stderr(std::process::Stdio::from(stderr_f))
        .stdin(std::process::Stdio::null());
    #[cfg(unix)]
    comando.process_group(0);

    let mut hijo = comando.spawn().map_err(AppError::Io)?;
    let pid = hijo.id();

    let mut fin = FinDeOrden::Siguiente;
    let exit_code = loop {
        if let Some(estado) = hijo.try_wait().map_err(AppError::Io)? {
            break estado.code();
        }
        if privilege::hay_cancelar(dir_control) {
            matar(&mut hijo, pid).await;
            break None;
        }
        // El de detener también, y en el MISMO sondeo. Antes solo se
        // miraba entre orden y orden: si el cuerpo de la fase se iba por
        // un camino que no marca el de cancelar, `detener_trabajador` se
        // quedaba esperando a que terminase un escaneo entero (que
        // pueden ser minutos u horas) antes de que este bucle llegara
        // siquiera a mirar su centinela.
        if privilege::hay_detener(dir_control) {
            matar(&mut hijo, pid).await;
            fin = FinDeOrden::Detener;
            break None;
        }
        // Y la app, aquí también y no solo entre orden y orden: un
        // escaneo de verdad dura minutos u horas, y sin esto la muerte
        // de la app no se notaría hasta que terminara -- o nunca, si el
        // escáner se queda colgado, porque el plazo de la invocación lo
        // lleva el orquestador, que es justamente quien ya no está.
        if !sigue_vivo(pid_padre) {
            matar(&mut hijo, pid).await;
            fin = FinDeOrden::PadreMuerto;
            break None;
        }
        tokio::time::sleep(INTERVALO_SONDEO).await;
    };

    // El estado se escribe igual en los tres finales, detener incluido:
    // quien esté esperando esta invocación al otro lado tiene derecho a
    // enterarse de que ya no va a llegar nada más.
    privilege::escribir_estado(dir_control, seq, &Estado { exit_code })?;
    Ok(fin)
}
