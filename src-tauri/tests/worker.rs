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
    let manejo = tokio::spawn(ejecutar_bucle(dir.path().to_path_buf(), std::process::id()));

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
    let manejo = tokio::spawn(ejecutar_bucle(dir.path().to_path_buf(), std::process::id()));
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
    let manejo = tokio::spawn(ejecutar_bucle(dir.path().to_path_buf(), std::process::id()));
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
    let manejo = tokio::spawn(ejecutar_bucle(dir.path().to_path_buf(), std::process::id()));
    esperar_listo(dir.path()).await;

    privilege::marcar_detener(dir.path()).unwrap();
    let resultado = tokio::time::timeout(Duration::from_secs(5), manejo).await;
    assert!(
        resultado.is_ok(),
        "el bucle no salió tras el centinela de detener"
    );
}

/// El centinela de detener tiene que cortar TAMBIÉN con una orden en
/// vuelo. Antes solo se miraba entre orden y orden: si el cuerpo de la
/// fase salía por un camino que no marca el de cancelar,
/// `detener_trabajador` se quedaba esperando a que terminara el escaneo
/// en curso -- que en una fase de verdad son minutos u horas -- antes de
/// que el bucle llegara siquiera a mirar su centinela.
#[tokio::test]
async fn el_centinela_de_detener_corta_tambien_con_una_orden_en_vuelo() {
    let dir = dir_de_prueba();
    let manejo = tokio::spawn(ejecutar_bucle(dir.path().to_path_buf(), std::process::id()));
    esperar_listo(dir.path()).await;

    let orden = Orden {
        binario: PathBuf::from("/bin/sleep"),
        argv: vec!["30".to_string()],
        ruta_stdout: privilege::ruta_stdout(dir.path(), 1),
        ruta_stderr: privilege::ruta_stderr(dir.path(), 1),
    };
    privilege::escribir_orden(dir.path(), 1, &orden).unwrap();

    // Con el hijo ya corriendo de verdad, no en carrera con su `spawn`.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let inicio = tokio::time::Instant::now();
    privilege::marcar_detener(dir.path()).unwrap();

    tokio::time::timeout(Duration::from_secs(10), manejo)
        .await
        .expect("el bucle tiene que salir aunque haya una orden en vuelo")
        .unwrap()
        .unwrap();
    // `sleep 30` no termina solo en menos de 30 s: salir antes solo
    // puede significar que el centinela mató al hijo.
    assert!(inicio.elapsed() < Duration::from_secs(10));
    assert!(
        privilege::leer_estado(dir.path(), 1).unwrap().is_some(),
        "quien esperaba esta invocación tiene que enterarse de que ya no llega nada"
    );
}

/// El trabajador no tiene a nadie por encima: `do shell script ... with
/// administrator privileges` no lo cuelga de la app, así que si la app
/// se cierra a la fuerza o revienta con una fase elevada en marcha, aquí
/// quedaba un proceso ROOT sondeando a 5 Hz para siempre un directorio
/// con la salida cruda de escaneos de un cliente dentro -- y sin nadie
/// que fuera a borrarlo nunca.
///
/// Con el pid de la app por parámetro, el trabajador lo vigila: si ya no
/// está, recoge su propio directorio y se va.
#[tokio::test]
async fn sin_la_app_al_otro_lado_el_trabajador_recoge_su_directorio_y_se_va() {
    // Un pid que seguro que ya no existe: se lanza un proceso, se
    // espera a que termine (y a que se recoja) y se reutiliza su
    // número.
    let mut efimero = tokio::process::Command::new("/usr/bin/true")
        .spawn()
        .unwrap();
    let pid_muerto = efimero.id().expect("acaba de lanzarse");
    efimero.wait().await.unwrap();

    let dir = dir_de_prueba();
    let dir_control = dir.path().join("control");
    std::fs::create_dir_all(&dir_control).unwrap();
    // Un resto de un escaneo real dentro: es exactamente lo que no
    // puede quedarse ahí sin dueño.
    std::fs::write(dir_control.join("0001.stdout"), b"198.51.100.5 open\n").unwrap();

    let manejo = tokio::spawn(ejecutar_bucle(dir_control.clone(), pid_muerto));
    tokio::time::timeout(Duration::from_secs(10), manejo)
        .await
        .expect("el trabajador tiene que irse solo si la app que lo lanzó ya no está")
        .unwrap()
        .unwrap();

    assert!(
        !dir_control.exists(),
        "sin la app no queda nadie que recoja el directorio: lo recoge él"
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
