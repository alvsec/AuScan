mod common;

use std::path::PathBuf;

use auscan_lib::preflight::{check_tool, ToolStatus};
use common::{FakeAdapter, FakeAdapterConDosBinarios};

#[test]
fn missing_cuando_el_binario_no_se_resuelve_en_ningun_path() {
    let estado = check_tool(&FakeAdapter, |_| None, |_, _| unreachable!());
    assert_eq!(estado, ToolStatus::Missing);
}

#[test]
fn ok_cuando_la_version_cumple_el_minimo() {
    let estado = check_tool(
        &FakeAdapter,
        |_| Some(PathBuf::from("/opt/homebrew/bin/fake-tool")),
        |_, _| Ok(b"fake-tool 2.3".to_vec()),
    );
    match estado {
        ToolStatus::Ok { path, version } => {
            assert_eq!(path, "/opt/homebrew/bin/fake-tool");
            assert_eq!(version, "2.3.0");
        }
        otro => panic!("se esperaba Ok, fue {otro:?}"),
    }
}

#[test]
fn too_old_cuando_la_version_no_llega_al_minimo() {
    // FakeAdapter exige 1.0.0; 0.9 no llega.
    let estado = check_tool(
        &FakeAdapter,
        |_| Some(PathBuf::from("/opt/homebrew/bin/fake-tool")),
        |_, _| Ok(b"fake-tool 0.9".to_vec()),
    );
    match estado {
        ToolStatus::TooOld {
            version, minimum, ..
        } => {
            assert_eq!(version, "0.9.0");
            assert_eq!(minimum, "1.0.0");
        }
        otro => panic!("se esperaba TooOld, fue {otro:?}"),
    }
}

#[test]
fn unparseable_cuando_la_salida_no_tiene_forma_de_version() {
    let estado = check_tool(
        &FakeAdapter,
        |_| Some(PathBuf::from("/opt/homebrew/bin/fake-tool")),
        |_, _| Ok(b"esto no es una version".to_vec()),
    );
    assert!(matches!(estado, ToolStatus::Unparseable { .. }));
}

#[test]
fn unparseable_cuando_ejecutar_version_falla() {
    let estado = check_tool(
        &FakeAdapter,
        |_| Some(PathBuf::from("/opt/homebrew/bin/fake-tool")),
        |_, _| Err(std::io::Error::other("no se pudo ejecutar")),
    );
    assert!(matches!(estado, ToolStatus::Unparseable { .. }));
}

#[test]
fn prueba_todos_los_binarios_del_descriptor_hasta_encontrar_uno() {
    // FakeAdapter solo declara un binario, así que no basta para
    // demostrar el recorrido: FakeAdapterConDosBinarios declara dos
    // ("nombre-que-no-existe" y "fake-tool"), y resolve() aquí solo
    // conoce el segundo. Si check_tool se detuviese en el primer
    // binario del descriptor, este test fallaría con Missing.
    let estado = check_tool(
        &FakeAdapterConDosBinarios,
        |b| (b == "fake-tool").then(|| PathBuf::from("/usr/local/bin/fake-tool")),
        |_, _| Ok(b"fake-tool 1.0".to_vec()),
    );
    assert!(matches!(estado, ToolStatus::Ok { .. }));
}
