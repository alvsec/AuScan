use std::path::PathBuf;
use std::time::Duration;

use auscan_lib::exec::{Linea, LineaOrigen};
use auscan_lib::privilege::{self, TrabajadorActivo};
use auscan_lib::worker::ejecutar_bucle;
use tokio_util::sync::CancellationToken;

async fn trabajador_de_prueba(
    dir: &std::path::Path,
) -> (tokio::task::JoinHandle<()>, TrabajadorActivo) {
    let manejo = tokio::spawn({
        let dir = dir.to_path_buf();
        async move {
            ejecutar_bucle(dir).await.unwrap();
        }
    });
    for _ in 0..50 {
        if privilege::leer_listo(dir).unwrap().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    (manejo, TrabajadorActivo::para_pruebas(dir.to_path_buf()))
}

#[tokio::test]
async fn ejecutar_privilegiado_devuelve_la_salida_completa_y_el_codigo() {
    let dir = tempfile::tempdir().unwrap();
    let (manejo, trabajador) = trabajador_de_prueba(dir.path()).await;

    let mut lineas = Vec::new();
    let resultado = privilege::ejecutar_privilegiado(
        &trabajador,
        1,
        &PathBuf::from("/bin/echo"),
        &["linea-uno".to_string()],
        Duration::from_secs(5),
        CancellationToken::new(),
        |l: Linea| lineas.push(l),
    )
    .await
    .unwrap();

    assert_eq!(resultado.exit_code, Some(0));
    assert!(!resultado.cancelado);
    assert_eq!(
        String::from_utf8_lossy(&resultado.raw).trim_end(),
        "linea-uno"
    );
    assert!(lineas
        .iter()
        .any(|l| l.origen == LineaOrigen::Stdout && l.texto == "linea-uno"));

    privilege::detener_trabajador(trabajador).await.unwrap();
    manejo.await.unwrap();
}

#[tokio::test]
async fn cancelar_durante_ejecutar_privilegiado_marca_el_centinela_y_espera_el_estado() {
    let dir = tempfile::tempdir().unwrap();
    let (manejo, trabajador) = trabajador_de_prueba(dir.path()).await;

    let token = CancellationToken::new();
    let token_para_cancelar = token.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        token_para_cancelar.cancel();
    });

    let inicio = tokio::time::Instant::now();
    let resultado = privilege::ejecutar_privilegiado(
        &trabajador,
        1,
        &PathBuf::from("/bin/sleep"),
        &["30".to_string()],
        Duration::from_secs(30),
        token,
        |_| {},
    )
    .await
    .unwrap();

    assert!(resultado.cancelado);
    assert!(inicio.elapsed() < Duration::from_secs(10));

    privilege::detener_trabajador(trabajador).await.unwrap();
    manejo.await.unwrap();
}

/// El centinela de cancelar es de la FASE, pero el plazo de una
/// invocación es de la INVOCACIÓN: son dos mecanismos distintos, y el
/// segundo marcaba el primero sin retirarlo nunca. Como el trabajador
/// mira ese centinela en cada orden, desde que aparece y para siempre,
/// una invocación vencida por plazo mataba nada más nacer a TODAS las
/// que vinieran detrás en la misma fase -- que el orquestador archivaba
/// como `tool_run` "failed" con un crudo de cero bytes: un registro
/// falso de un escaneo que nunca corrió.
///
/// Aquí el token NUNCA se cancela: lo único que vence es el plazo de la
/// primera invocación. Si tras eso la segunda no corre con normalidad,
/// el centinela se quedó puesto.
#[tokio::test]
async fn el_plazo_de_una_invocacion_no_envenena_a_la_siguiente_de_la_fase() {
    let dir = tempfile::tempdir().unwrap();
    let (manejo, trabajador) = trabajador_de_prueba(dir.path()).await;

    // Invocación 1: se pasa de plazo (500 ms contra un `sleep 30`).
    let primera = privilege::ejecutar_privilegiado(
        &trabajador,
        1,
        &PathBuf::from("/bin/sleep"),
        &["30".to_string()],
        Duration::from_millis(500),
        CancellationToken::new(),
        |_| {},
    )
    .await
    .unwrap();
    assert!(primera.cancelado, "la primera tenía que vencer por plazo");
    assert!(
        !privilege::hay_cancelar(dir.path()),
        "el centinela de cancelar es de la fase: una invocación vencida \
         por plazo no puede dejarlo puesto para las siguientes"
    );

    // Invocación 2, misma fase y mismo trabajador: tiene que correr de
    // verdad. Sin la limpieza, vuelve con exit_code None y sin salida.
    let segunda = privilege::ejecutar_privilegiado(
        &trabajador,
        2,
        &PathBuf::from("/bin/echo"),
        &["sigue-viva".to_string()],
        Duration::from_secs(10),
        CancellationToken::new(),
        |_| {},
    )
    .await
    .unwrap();

    assert!(!segunda.cancelado);
    assert_eq!(
        segunda.exit_code,
        Some(0),
        "la siguiente invocación de la fase tiene que ejecutarse de verdad"
    );
    assert_eq!(
        String::from_utf8_lossy(&segunda.raw).trim_end(),
        "sigue-viva",
        "y dejar su salida real, no un crudo vacío"
    );

    privilege::detener_trabajador(trabajador).await.unwrap();
    manejo.await.unwrap();
}

/// Espejo de
/// `tests/exec_spawn.rs::ejecutar_con_el_token_ya_cancelado_ni_siquiera_lanza_el_proceso`
/// para el camino privilegiado: un token ya cancelado antes de llamar
/// no debe llegar a pedirle nada al trabajador. Un binario que no
/// existe es la prueba -- si `ejecutar_privilegiado` escribiera la
/// orden de todas formas, el trabajador fallaría al hacer `spawn` y
/// `ejecutar_bucle` (que hace `.unwrap()` dentro de la tarea) entraría
/// en pánico. Además, tras la llamada cancelada, se reutiliza el MISMO
/// `seq` para una orden real (`/bin/echo`) -- el trabajador solo
/// atiende `seq` en orden estricto, así que si hubiera consumido ya el
/// `seq` 1 con la orden inexistente, esta segunda orden (que también
/// usa `seq` 1) nunca se atendería y la prueba colgaría en vez de
/// pasar.
#[tokio::test]
async fn ejecutar_privilegiado_con_el_token_ya_cancelado_ni_siquiera_pide_la_orden() {
    let dir = tempfile::tempdir().unwrap();
    let (manejo, trabajador) = trabajador_de_prueba(dir.path()).await;

    let cancelar = CancellationToken::new();
    cancelar.cancel();
    let inexistente = PathBuf::from("/no/existe/ningun-binario-auscan");
    assert!(!inexistente.exists());

    let resultado = privilege::ejecutar_privilegiado(
        &trabajador,
        1,
        &inexistente,
        &[],
        Duration::from_secs(60),
        cancelar,
        |_| {},
    )
    .await
    .unwrap();

    assert!(resultado.cancelado);
    assert_eq!(resultado.exit_code, None);
    assert!(resultado.raw.is_empty());
    assert!(resultado.stderr.is_empty());

    // El trabajador sigue sano: reutilizando el mismo `seq` (nunca se
    // consumió), una orden real se procesa con normalidad.
    let resultado_real = privilege::ejecutar_privilegiado(
        &trabajador,
        1,
        &PathBuf::from("/bin/echo"),
        &["sigue-vivo".to_string()],
        Duration::from_secs(5),
        CancellationToken::new(),
        |_| {},
    )
    .await
    .unwrap();
    assert_eq!(resultado_real.exit_code, Some(0));

    privilege::detener_trabajador(trabajador).await.unwrap();
    manejo.await.unwrap();
}
