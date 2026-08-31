use std::path::{Path, PathBuf};
use std::time::Duration;

use auscan_lib::privilege::{self, Orden};
use auscan_lib::worker::ejecutar_bucle;

fn dir_de_prueba() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[tokio::test]
async fn escribe_listo_con_su_propio_estado_de_privilegio_antes_de_esperar_ordenes() {
    let dir = dir_de_prueba();
    let manejo = tokio::spawn(ejecutar_bucle(dir.path().to_path_buf()));

    let listo = esperar_listo(dir.path()).await;
    // El test corre sin privilegios: el trabajador tiene que medir eso
    // de verdad, no asumir nada.
    assert!(!listo.es_root);

    privilege::marcar_detener(dir.path()).unwrap();
    manejo.await.unwrap().unwrap();
}

#[tokio::test]
async fn ejecuta_una_orden_y_escribe_su_salida_y_su_estado() {
    let dir = dir_de_prueba();
    let manejo = tokio::spawn(ejecutar_bucle(dir.path().to_path_buf()));
    esperar_listo(dir.path()).await;

    let orden = Orden {
        binario: PathBuf::from("/bin/echo"),
        argv: vec!["hola-trabajador".to_string()],
        ruta_stdout: privilege::ruta_stdout(dir.path(), 1),
        ruta_stderr: privilege::ruta_stderr(dir.path(), 1),
    };
    privilege::escribir_orden(dir.path(), 1, &orden).unwrap();

    let estado = esperar_estado(dir.path(), 1).await;
    assert_eq!(estado.exit_code, Some(0));
    let stdout = std::fs::read_to_string(&orden.ruta_stdout).unwrap();
    assert_eq!(stdout.trim_end(), "hola-trabajador");

    privilege::marcar_detener(dir.path()).unwrap();
    manejo.await.unwrap().unwrap();
}

#[tokio::test]
async fn el_centinela_de_cancelar_mata_al_hijo_en_curso() {
    let dir = dir_de_prueba();
    let manejo = tokio::spawn(ejecutar_bucle(dir.path().to_path_buf()));
    esperar_listo(dir.path()).await;

    let orden = Orden {
        binario: PathBuf::from("/bin/sleep"),
        argv: vec!["30".to_string()],
        ruta_stdout: privilege::ruta_stdout(dir.path(), 1),
        ruta_stderr: privilege::ruta_stderr(dir.path(), 1),
    };
    privilege::escribir_orden(dir.path(), 1, &orden).unwrap();

    // Le da tiempo a arrancar antes de cancelar, para que sea un
    // proceso en curso de verdad lo que se mata, no una carrera contra
    // el propio spawn.
    tokio::time::sleep(Duration::from_millis(300)).await;
    privilege::marcar_cancelar(dir.path()).unwrap();

    let inicio = tokio::time::Instant::now();
    let estado = esperar_estado(dir.path(), 1).await;
    // `sleep 30` no termina solo en menos de 30s: si el estado llega
    // mucho antes, es que el centinela lo mató de verdad.
    assert!(inicio.elapsed() < Duration::from_secs(5));
    assert_ne!(estado.exit_code, Some(0));

    privilege::marcar_detener(dir.path()).unwrap();
    manejo.await.unwrap().unwrap();
}

#[tokio::test]
async fn el_centinela_de_detener_para_el_bucle_entero() {
    let dir = dir_de_prueba();
    let manejo = tokio::spawn(ejecutar_bucle(dir.path().to_path_buf()));
    esperar_listo(dir.path()).await;

    privilege::marcar_detener(dir.path()).unwrap();
    let resultado = tokio::time::timeout(Duration::from_secs(5), manejo).await;
    assert!(
        resultado.is_ok(),
        "el bucle no salió tras el centinela de detener"
    );
}

async fn esperar_listo(dir: &Path) -> privilege::Listo {
    for _ in 0..50 {
        if let Some(l) = privilege::leer_listo(dir).unwrap() {
            return l;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("el trabajador no escribió listo.json a tiempo");
}

async fn esperar_estado(dir: &Path, seq: i64) -> privilege::Estado {
    for _ in 0..100 {
        if let Some(e) = privilege::leer_estado(dir, seq).unwrap() {
            return e;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("el trabajador no escribió el estado a tiempo");
}
