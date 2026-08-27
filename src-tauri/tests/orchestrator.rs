use std::sync::Arc;
use std::time::Duration;

use auscan_lib::adapters::{
    Flag, HostFact, InstallHint, Invocation, Normalized, ObservationFact, ObservationKind,
    ParseContext, Phase, PhaseOptions, PlanContext, ProgressSource, RawSource, ToolAdapter,
    ToolDescriptor,
};
use auscan_lib::error::{AppError, Result};
use auscan_lib::orchestrator::{ejecutar_fase, SucesoRun};
use auscan_lib::scope::ScopeKind;
use auscan_lib::state::AppState;
use semver::Version;
use tokio_util::sync::CancellationToken;

#[cfg(unix)]
const BINARIO: &str = "sh";
#[cfg(unix)]
const BANDERA: &str = "-c";
#[cfg(windows)]
const BINARIO: &str = "cmd";
#[cfg(windows)]
const BANDERA: &str = "/C";

/// La verja exige que TODA bandera del argv esté en `allowed_flags`, así
/// que el adaptador de prueba tiene que declarar la suya como cualquier
/// herramienta real. `takes_value` es lo que hace que el script que sigue
/// a `-c` se salte como valor opaco: sin él, "echo hola" se intentaría
/// casar como otra bandera y la verja lo rechazaría.
static FLAGS: &[Flag] = &[Flag {
    name: BANDERA,
    needs_privilege: false,
    takes_value: true,
}];

/// Adaptador de prueba para el orquestador: apunta a un binario que
/// siempre existe (`sh`/`cmd`) y produce un host fijo sin leer nada de
/// su salida real -- lo que importa aquí es la orquestación, no el
/// parseo.
struct AdaptadorDePrueba;

impl ToolAdapter for AdaptadorDePrueba {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            id: "prueba",
            binaries: &[BINARIO],
            min_version: Version::new(0, 0, 1),
            phases: &[Phase::Discovery],
            install_hint: InstallHint {
                brew: &["install", "prueba"],
                winget: &["install", "-e", "Prueba"],
            },
            allowed_flags: FLAGS,
        }
    }

    fn version_argv(&self) -> Vec<String> {
        vec![BANDERA.to_string(), "echo prueba 1.0.0".to_string()]
    }

    fn parse_version(&self, stdout: &str) -> Result<Version> {
        let numero = stdout.split_whitespace().last().unwrap_or("0.0.0");
        Version::parse(numero.trim())
            .map_err(|_| auscan_lib::error::AppError::ParseFailed(stdout.to_string()))
    }

    fn plan(&self, ctx: &PlanContext) -> Result<Vec<Invocation>> {
        if ctx.targets.is_empty() {
            return Ok(vec![]);
        }
        let argv = vec![BANDERA.to_string(), "echo hola".to_string()];
        Ok(vec![Invocation {
            phase: Phase::Discovery,
            argv,
            targets: ctx.targets.to_vec(),
            needs_privilege: false,
            raw_from: RawSource::Stdout,
            progress_from: ProgressSource::None,
            stdin: None,
            timeout: Duration::from_secs(10),
        }])
    }

    fn parse(&self, _raw: &[u8], _ctx: &ParseContext) -> Result<Normalized> {
        let host = HostFact {
            ip: "198.51.100.5".parse().unwrap(),
            hostname: None,
            mac: None,
            vendor: None,
            os_guess: None,
            os_accuracy: None,
            state: Some("up".to_string()),
        };
        Ok(Normalized {
            hosts: vec![host.clone()],
            services: vec![],
            observations: vec![ObservationFact {
                host_ip: Some(host.ip),
                port: None,
                kind: ObservationKind::HostDiscovered,
                subject: host.ip.to_string(),
                statement: "Host activo".to_string(),
                evidence: None,
                evidence_ref: None,
                meta_json: None,
            }],
        })
    }
}

fn estado_de_prueba() -> (tempfile::TempDir, AppState, String) {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::new(dir.path().to_path_buf());
    let referencia = auscan_lib::engagement::create(dir.path(), "CLAVEL").unwrap();
    let conn = auscan_lib::engagement::open(dir.path(), &referencia.id).unwrap();
    auscan_lib::scope::add_entry(&conn, ScopeKind::Allow, "198.51.100.0/24", None).unwrap();
    *state.open.lock().unwrap() = Some(auscan_lib::state::OpenEngagement {
        id: referencia.id.clone(),
        conn,
    });
    (dir, state, referencia.id)
}

#[tokio::test]
async fn ejecutar_fase_persiste_lo_que_parse_devuelve() {
    let (_dir, state, _id) = estado_de_prueba();
    let registro: Vec<Box<dyn ToolAdapter>> = vec![Box::new(AdaptadorDePrueba)];
    let sucesos = Arc::new(std::sync::Mutex::new(Vec::new()));
    let s2 = sucesos.clone();

    ejecutar_fase(
        &state,
        &registro,
        Phase::Discovery,
        "prueba",
        &["198.51.100.5".to_string()],
        false,
        &PhaseOptions::default(),
        CancellationToken::new(),
        move |suceso| s2.lock().unwrap().push(suceso),
    )
    .await
    .unwrap();

    let sucesos = sucesos.lock().unwrap();
    assert!(sucesos
        .iter()
        .any(|s| matches!(s, SucesoRun::RunTerminado { status, .. } if status == "ok")));
    assert!(sucesos
        .iter()
        .any(|s| matches!(s, SucesoRun::FaseTerminada)));

    let guard = state.open.lock().unwrap();
    let conn = &guard.as_ref().unwrap().conn;
    let n_hosts: i64 = conn
        .query_row("SELECT COUNT(*) FROM host", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n_hosts, 1);
    let n_runs: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM tool_run WHERE status = 'ok'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n_runs, 1);
}

#[tokio::test]
async fn ejecutar_fase_rechaza_un_objetivo_fuera_de_alcance() {
    let (_dir, state, _id) = estado_de_prueba();
    let registro: Vec<Box<dyn ToolAdapter>> = vec![Box::new(AdaptadorDePrueba)];

    let resultado = ejecutar_fase(
        &state,
        &registro,
        Phase::Discovery,
        "prueba",
        &["203.0.113.9".to_string()], // fuera del /24 autorizado
        false,
        &PhaseOptions::default(),
        CancellationToken::new(),
        |_| {},
    )
    .await;

    // No basta con "falló": si el error fuese otro (ToolNotFound, por
    // ejemplo) el COUNT de abajo daría 0 igual y el test pasaría sin
    // haber ejercitado el alcance en absoluto.
    assert!(
        matches!(resultado, Err(AppError::OutOfScope(ref ip)) if ip == "203.0.113.9"),
        "se esperaba OutOfScope, llegó {resultado:?}"
    );
    let guard = state.open.lock().unwrap();
    let conn = &guard.as_ref().unwrap().conn;
    let n_runs: i64 = conn
        .query_row("SELECT COUNT(*) FROM tool_run", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        n_runs, 0,
        "un objetivo fuera de alcance no debe crear ningún tool_run"
    );
}

#[tokio::test]
async fn ejecutar_fase_cancelada_deja_el_tool_run_marcado_y_no_persiste_hallazgos() {
    let (dir, state, id) = estado_de_prueba();
    let registro: Vec<Box<dyn ToolAdapter>> = vec![Box::new(AdaptadorDePrueba)];
    let cancelar = CancellationToken::new();
    cancelar.cancel(); // ya cancelado antes de empezar

    ejecutar_fase(
        &state,
        &registro,
        Phase::Discovery,
        "prueba",
        &["198.51.100.5".to_string()],
        false,
        &PhaseOptions::default(),
        cancelar,
        |_| {},
    )
    .await
    .unwrap();

    let guard = state.open.lock().unwrap();
    let conn = &guard.as_ref().unwrap().conn;
    let (status, raw_path, raw_sha256, n_hosts, n_obs): (
        String,
        Option<String>,
        Option<String>,
        i64,
        i64,
    ) = conn
        .query_row(
            "SELECT status, raw_path, raw_sha256,
                    (SELECT COUNT(*) FROM host),
                    (SELECT COUNT(*) FROM observation)
             FROM tool_run LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();

    // Las dos mitades del invariante. Una cancelación NO es una
    // ejecución que no ocurrió: la fila y la salida cruda que llegó a
    // producirse son evidencia y se guardan igual...
    assert_eq!(status, "cancelled");
    let raw_path = raw_path.expect("una ejecución cancelada igualmente registra su raw_path");
    assert_eq!(raw_path, "raw/0001-prueba-discovery.xml");
    assert!(
        raw_sha256.is_some_and(|h| h.len() == 64),
        "el sha256 de la salida cruda se calcula aunque la ejecución se cancele"
    );
    assert!(
        auscan_lib::paths::engagement_dir(dir.path(), &id)
            .unwrap()
            .join(&raw_path)
            .is_file(),
        "el fichero crudo debe existir en disco, no solo su ruta en la fila"
    );

    // ...pero lo que parse() habría deducido de una salida truncada no
    // se persiste: sería inventar hallazgos a partir de datos a medias.
    assert_eq!(
        n_hosts, 0,
        "una ejecución cancelada no parsea ni persiste hallazgos"
    );
    assert_eq!(
        n_obs, 0,
        "una ejecución cancelada no parsea ni persiste observaciones"
    );
}

/// Soltar el lock a través del `.await` es correcto y obligatorio, pero
/// deja una ventana: `engagement_open` y `engagement_purge` son comandos
/// de Tauri que el operador puede disparar en cualquier momento, también
/// mientras un escaneo está corriendo. Si al recuperar el lock nadie
/// comprueba QUÉ engagement hay abierto ahora, el `tool_run_id` acuñado
/// contra la base de antes se usa para escribir en la base de después --
/// y como `tool_run.id` es un autoincremento por base, ese id suele
/// existir ya allí: los resultados de un cliente acabarían dentro del
/// expediente de otro.
///
/// El cambio se dispara desde `on_suceso`: la primera línea de log llega
/// mientras `exec::ejecutar` está corriendo, que es exactamente la
/// ventana en la que el orquestador tiene el lock soltado. No hay carrera
/// que provocar ni `sleep` que ajustar -- el propio pipeline marca el
/// instante.
#[tokio::test]
async fn cambiar_de_engagement_a_media_ejecucion_aborta_en_vez_de_escribir_en_el_otro() {
    let (dir, state, id_original) = estado_de_prueba();
    let state = Arc::new(state);
    let registro: Vec<Box<dyn ToolAdapter>> = vec![Box::new(AdaptadorDePrueba)];

    // Un segundo engagement, con su propia base y su propio alcance.
    let otro = auscan_lib::engagement::create(dir.path(), "AZAFRAN").unwrap();
    let conn_otro = auscan_lib::engagement::open(dir.path(), &otro.id).unwrap();
    auscan_lib::scope::add_entry(&conn_otro, ScopeKind::Allow, "198.51.100.0/24", None).unwrap();

    // Clave para que el test pruebe el caso GRAVE y no uno afortunado:
    // se le da al otro engagement una ejecución previa propia, así su
    // `tool_run.id = 1` ya existe. `tool_run.id` es un autoincremento
    // POR BASE, así que dos expedientes cualesquiera colisionan en los
    // primeros ids -- y sin la comprobación de identidad el UPDATE y los
    // upserts de este escaneo encajarían ahí sin violar ninguna clave
    // ajena y sin dar el menor error. Sin esta fila previa, la base
    // vacía delataría el fallo con un FOREIGN KEY constraint failed y el
    // test pasaría por el motivo equivocado.
    let seq_otro = auscan_lib::runs::siguiente_seq(&conn_otro).unwrap();
    let id_run_otro = auscan_lib::runs::crear_tool_run(
        &conn_otro,
        seq_otro,
        "prueba",
        "1.0.0",
        "/bin/sh",
        "discovery",
        "[]",
        false,
        "[]",
        "2026-01-01T00:00:00Z",
    )
    .unwrap();

    let s2 = state.clone();
    let id_otro = otro.id.clone();
    let mut conn_otro = Some(conn_otro);

    let resultado = ejecutar_fase(
        &state,
        &registro,
        Phase::Discovery,
        "prueba",
        &["198.51.100.5".to_string()],
        false,
        &PhaseOptions::default(),
        CancellationToken::new(),
        move |suceso| {
            // Al primer log, cambiar el engagement abierto bajo los pies
            // del orquestador. (Que este `lock()` no se autobloquee es de
            // paso la prueba de que `on_suceso` no se invoca con el mutex
            // cogido: `std::sync::Mutex` no es reentrante.)
            if matches!(suceso, SucesoRun::Log { .. }) {
                if let Some(conn) = conn_otro.take() {
                    *s2.open.lock().unwrap() = Some(auscan_lib::state::OpenEngagement {
                        id: id_otro.clone(),
                        conn,
                    });
                }
            }
        },
    )
    .await;

    // 1. Se aborta, y el error nombra el engagement que se esperaba.
    assert!(
        matches!(resultado, Err(AppError::EngagementChanged(ref id)) if *id == id_original),
        "se esperaba EngagementChanged({id_original}), llegó {resultado:?}"
    );

    // 2. Y lo que de verdad importa: la base del OTRO engagement no
    //    recibió absolutamente nada de un escaneo que no es suyo.
    let guard = state.open.lock().unwrap();
    let abierto = guard.as_ref().unwrap();
    assert_eq!(abierto.id, otro.id, "el swap del test sí llegó a ocurrir");
    for tabla in ["host", "service", "observation"] {
        let n: i64 = abierto
            .conn
            .query_row(&format!("SELECT COUNT(*) FROM {tabla}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            n, 0,
            "el engagement {} no debe recibir ni una fila en {tabla} de un escaneo ajeno",
            otro.id
        );
    }

    // Su propia ejecución previa sigue intacta: `cerrar_tool_run` no la
    // pisó con el exit_code, el status ni el raw_path del escaneo ajeno.
    let (n_runs, status, raw_path): (i64, String, Option<String>) = abierto
        .conn
        .query_row(
            "SELECT (SELECT COUNT(*) FROM tool_run), status, raw_path FROM tool_run WHERE id = ?1",
            [id_run_otro],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        n_runs, 1,
        "no se crearon filas nuevas en el engagement ajeno"
    );
    assert_eq!(
        status, "running",
        "su ejecución previa no debe quedar cerrada por un escaneo ajeno"
    );
    assert_eq!(
        raw_path, None,
        "ni debe apuntar al crudo de otro expediente"
    );
}

/// El invariante central de este módulo: ningún `MutexGuard` de
/// `AppState.open` sigue vivo a través de un `.await`.
///
/// Un guard retenido a través de un await pasa a formar parte del estado
/// del futuro, y como `MutexGuard` no es `Send`, el futuro entero dejaría
/// de serlo. Esta comprobación es puramente de tipos -- el cierre nunca
/// se llama -- y rompe la compilación en cuanto alguien rompa esa
/// disciplina. Los `#[tokio::test]` de arriba no la cubren: corren sobre
/// un runtime de un solo hilo y esperan el futuro en el sitio, así que
/// uno `!Send` pasaría desapercibido hasta que la Fase 6 intentase
/// lanzarlo con `tokio::spawn` desde un comando de Tauri.
#[test]
fn el_futuro_de_ejecutar_fase_es_send() {
    fn exige_send<F: Send>(_: F) {}

    let _comprobacion =
        |state: &AppState, registro: &[Box<dyn ToolAdapter>], opciones: &PhaseOptions| {
            exige_send(ejecutar_fase(
                state,
                registro,
                Phase::Discovery,
                "prueba",
                &[],
                false,
                opciones,
                CancellationToken::new(),
                |_| {},
            ));
        };
}
