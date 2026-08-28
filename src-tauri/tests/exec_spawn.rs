use std::path::Path;
use std::time::Duration;

use auscan_lib::exec::{ejecutar, Linea, LineaOrigen};
use tokio_util::sync::CancellationToken;

#[cfg(unix)]
fn shell() -> (&'static str, &'static str) {
    ("sh", "-c")
}
#[cfg(windows)]
fn shell() -> (&'static str, &'static str) {
    ("cmd", "/C")
}

// En cada plataforma, exactamente uno de los dos parámetros se usa en el
// `let script = ...` de abajo (el otro se compila fuera vía `#[cfg]`) —
// de ahí el `allow`: no hay forma de que ambos aparezcan "usados" a la
// vez ante el lint sin duplicar esta función entera por plataforma.
#[allow(unused_variables)]
async fn correr_con(
    script_unix: &str,
    script_windows: &str,
    timeout: Duration,
    cancelar: CancellationToken,
) -> (auscan_lib::exec::ResultadoEjecucion, Vec<Linea>) {
    let (bin, flag) = shell();
    #[cfg(unix)]
    let script = script_unix;
    #[cfg(windows)]
    let script = script_windows;
    let mut lineas = Vec::new();
    let resultado = ejecutar(
        Path::new(bin),
        &[flag.to_string(), script.to_string()],
        timeout,
        cancelar,
        |l| lineas.push(l),
    )
    .await
    .unwrap();
    (resultado, lineas)
}

async fn correr(
    script_unix: &str,
    script_windows: &str,
) -> (auscan_lib::exec::ResultadoEjecucion, Vec<Linea>) {
    correr_con(
        script_unix,
        script_windows,
        Duration::from_secs(30),
        CancellationToken::new(),
    )
    .await
}

#[cfg(unix)]
#[tokio::test]
async fn ejecutar_captura_stdout_completo_byte_a_byte() {
    let (resultado, _lineas) = correr("printf 'linea1\\nlinea2\\n'", "").await;
    assert_eq!(resultado.raw, b"linea1\nlinea2\n");
    assert_eq!(resultado.exit_code, Some(0));
}

#[tokio::test]
async fn ejecutar_invoca_on_linea_por_cada_linea_de_stdout() {
    let (_resultado, lineas) = correr("echo uno; echo dos", "echo uno&& echo dos").await;
    assert_eq!(lineas.len(), 2);
    assert_eq!(
        lineas[0],
        Linea {
            origen: LineaOrigen::Stdout,
            texto: "uno".to_string()
        }
    );
    assert_eq!(
        lineas[1],
        Linea {
            origen: LineaOrigen::Stdout,
            texto: "dos".to_string()
        }
    );
}

#[tokio::test]
async fn ejecutar_separa_stderr_de_stdout() {
    let (resultado, lineas) = correr(
        "echo por-stdout; echo por-stderr 1>&2",
        "echo por-stdout&& echo por-stderr 1>&2",
    )
    .await;
    assert!(resultado.raw.starts_with(b"por-stdout"));
    assert!(resultado.stderr.starts_with(b"por-stderr"));
    assert!(lineas
        .iter()
        .any(|l| l.origen == LineaOrigen::Stdout && l.texto == "por-stdout"));
    assert!(lineas
        .iter()
        .any(|l| l.origen == LineaOrigen::Stderr && l.texto == "por-stderr"));
}

#[tokio::test]
async fn ejecutar_devuelve_el_codigo_de_salida_real() {
    let (resultado, _) = correr("exit 7", "exit 7").await;
    assert_eq!(resultado.exit_code, Some(7));
}

#[cfg(unix)]
fn dormir_mucho() -> &'static str {
    "sleep 30"
}
#[cfg(windows)]
fn dormir_mucho() -> &'static str {
    "timeout /T 30"
}

#[tokio::test]
async fn ejecutar_se_cancela_cuando_se_solicita() {
    let cancelar = CancellationToken::new();
    let señal = cancelar.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        señal.cancel();
    });
    let script = dormir_mucho();
    let (resultado, _) = correr_con(script, script, Duration::from_secs(60), cancelar).await;
    assert!(resultado.cancelado);
    assert_eq!(resultado.exit_code, None);
}

#[tokio::test]
async fn ejecutar_se_cancela_al_agotar_el_timeout() {
    let script = dormir_mucho();
    let (resultado, _) = correr_con(
        script,
        script,
        Duration::from_millis(200),
        CancellationToken::new(),
    )
    .await;
    assert!(resultado.cancelado);
}

#[tokio::test]
async fn ejecutar_se_cancela_si_el_token_ya_estaba_cancelado_antes_de_empezar() {
    // Esto prueba que un token cancelado ANTES de arrancar sigue
    // contando como cancelado, no se pierde. Ojo: esto NO distingue por
    // sí solo CancellationToken de Notify -- para esta única invocación,
    // un Notify con un permiso ya guardado (notify_one() antes de que
    // nadie esperase) pasaría este mismo caso igual de bien. La razón
    // real para usar CancellationToken es que se mantiene cancelado a
    // través de VARIAS invocaciones seguidas de ejecutar() dentro de una
    // misma fase (p. ej. Services, una por host) -- con Notify, la
    // invocación 2 consumiría el permiso guardado y la 3 arrancaría
    // fresca, sin verlo. Esa propiedad no es comprobable en aislamiento
    // aquí: se prueba de verdad en
    // `tests/orchestrator.rs::cancelar_a_media_fase_no_lanza_las_invocaciones_que_quedaban`,
    // ahora que el bucle del orquestador es ese llamador que invoca
    // ejecutar() más de una vez por fase.
    let cancelar = CancellationToken::new();
    cancelar.cancel();
    let script = dormir_mucho();
    let (resultado, _) = correr_con(script, script, Duration::from_secs(60), cancelar).await;
    assert!(resultado.cancelado);
}

/// "Cancelado" no puede significar "lanzado y matado en el acto": el
/// token se mira ANTES del `spawn`. Con la comprobación solo dentro del
/// `select!` -- que ya corre con el proceso vivo -- una fase cancelada
/// seguía arrancando un escáner de verdad por cada invocación restante.
///
/// La prueba es un binario que NO EXISTE: si `ejecutar` llegara al
/// `spawn`, devolvería `Err(Io)` sin remedio. Que devuelva un resultado
/// cancelado y bien formado es la única forma de que ni lo haya
/// intentado. (Un marcador en disco no serviría: con el token ya
/// cancelado, el proceso lanzado moriría antes de escribirlo casi
/// siempre, y el test pasaría por suerte en vez de por diseño.)
#[tokio::test]
async fn ejecutar_con_el_token_ya_cancelado_ni_siquiera_lanza_el_proceso() {
    let cancelar = CancellationToken::new();
    cancelar.cancel();
    let inexistente = Path::new("/no/existe/ningun-binario-auscan");
    assert!(!inexistente.exists());

    let mut lineas = Vec::new();
    let resultado = ejecutar(inexistente, &[], Duration::from_secs(60), cancelar, |l| {
        lineas.push(l)
    })
    .await
    .expect("no se puede fallar al lanzar algo que no se lanza");

    // Y la forma del resultado es la misma que produce la cancelación
    // desde dentro del `select!`, para que quien llama no tenga que
    // distinguir dos clases de cancelación.
    assert!(resultado.cancelado);
    assert_eq!(resultado.exit_code, None);
    assert!(resultado.raw.is_empty());
    assert!(resultado.stderr.is_empty());
    assert!(lineas.is_empty());
}
