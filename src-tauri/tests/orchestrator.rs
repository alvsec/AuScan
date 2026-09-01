use std::sync::Arc;
use std::time::Duration;

use auscan_lib::adapters::{
    Flag, HostFact, InstallHint, Invocation, Normalized, ObservationFact, ObservationKind,
    ParseContext, Phase, PhaseOptions, PlanContext, ProgressSource, RawSource, ToolAdapter,
    ToolDescriptor,
};
use auscan_lib::error::{AppError, Result};
use auscan_lib::orchestrator::{ejecutar_fase, planificar, SucesoRun};
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

/// Script que toca su marcador, escupe una línea y luego se queda
/// colgado, para que la invocación siga viva mientras el test la
/// cancela. El marcador es lo que distingue "no se persistió la fila" de
/// "no se llegó a lanzar el proceso": sin él, un bucle que siguiera
/// lanzando y matando escáneres pasaría igual con solo mirar la base.
///
/// El marcador se escribe ANTES de la línea de stdout a propósito: el
/// test cancela justo al recibir esa línea, así que si el orden fuera el
/// contrario la señal podría matar al proceso antes de que llegara a
/// dejar su marca, y el test fallaría por una carrera en vez de por el
/// fallo que persigue.
#[cfg(unix)]
fn script_marcador(marcador: &std::path::Path) -> String {
    format!(
        "echo lanzado > '{}'; echo hola; sleep 30",
        marcador.display()
    )
}
#[cfg(windows)]
fn script_marcador(marcador: &std::path::Path) -> String {
    format!(
        "echo lanzado> \"{}\"&& echo hola&& timeout /T 30",
        marcador.display()
    )
}

/// Adaptador que planifica UNA invocación por objetivo, que es la forma
/// que tiene la fase Services de verdad (nmap: un escaneo por host con
/// sus puertos abiertos). No se usa el adaptador de nmap real porque
/// exigiría el binario instalado en la máquina que ejecuta los tests; lo
/// que estos tests necesitan del plan es solo su cardinalidad.
///
/// Cada invocación deja un marcador en `dir_marcadores` al arrancar, así
/// que los tests pueden distinguir "no quedó fila" de "no se lanzó el
/// proceso". El directorio viaja en el propio adaptador (que el test
/// construye) en vez de en un estático compartido: los tests corren en
/// paralelo dentro del mismo binario y cada uno tiene su tempdir.
struct AdaptadorPorObjetivo {
    dir_marcadores: std::path::PathBuf,
}

impl AdaptadorPorObjetivo {
    fn marcador(&self, ip: &std::net::IpAddr) -> std::path::PathBuf {
        self.dir_marcadores.join(format!("lanzado-{ip}"))
    }
}

impl ToolAdapter for AdaptadorPorObjetivo {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            id: "por-objetivo",
            phases: &[Phase::Services],
            ..AdaptadorDePrueba.descriptor()
        }
    }

    fn version_argv(&self) -> Vec<String> {
        AdaptadorDePrueba.version_argv()
    }

    fn parse_version(&self, stdout: &str) -> Result<Version> {
        AdaptadorDePrueba.parse_version(stdout)
    }

    fn plan(&self, ctx: &PlanContext) -> Result<Vec<Invocation>> {
        Ok(ctx
            .targets
            .iter()
            .map(|t| Invocation {
                phase: ctx.phase,
                argv: vec![
                    BANDERA.to_string(),
                    script_marcador(&self.marcador(&t.ip())),
                ],
                targets: vec![*t],
                needs_privilege: false,
                raw_from: RawSource::Stdout,
                progress_from: ProgressSource::None,
                stdin: None,
                timeout: Duration::from_secs(60),
            })
            .collect())
    }

    /// Delegado a propósito: `AdaptadorDePrueba::parse` inventa un host y
    /// una observación pase lo que pase, que es justo lo que hace que un
    /// `COUNT(*) = 0` en `host`/`observation` pruebe algo (que no se
    /// parseó) en vez de ser cierto por vacío.
    fn parse(&self, raw: &[u8], ctx: &ParseContext) -> Result<Normalized> {
        AdaptadorDePrueba.parse(raw, ctx)
    }
}

/// Como `AdaptadorPorObjetivo` -- una invocación por objetivo, que es la
/// forma real de la fase Services --, pero con un script que TERMINA
/// solo: escupe una línea y sale. Lo usa el test de la numeración del
/// protocolo elevado, que necesita varias invocaciones seguidas
/// completándose de verdad contra el mismo trabajador.
struct AdaptadorEcoPorObjetivo;

impl ToolAdapter for AdaptadorEcoPorObjetivo {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            id: "eco-por-objetivo",
            phases: &[Phase::Services],
            ..AdaptadorDePrueba.descriptor()
        }
    }

    fn version_argv(&self) -> Vec<String> {
        AdaptadorDePrueba.version_argv()
    }

    fn parse_version(&self, stdout: &str) -> Result<Version> {
        AdaptadorDePrueba.parse_version(stdout)
    }

    fn plan(&self, ctx: &PlanContext) -> Result<Vec<Invocation>> {
        Ok(ctx
            .targets
            .iter()
            .map(|t| Invocation {
                phase: ctx.phase,
                argv: vec![BANDERA.to_string(), format!("echo eco-{}", t.ip())],
                targets: vec![*t],
                needs_privilege: false,
                raw_from: RawSource::Stdout,
                progress_from: ProgressSource::None,
                stdin: None,
                timeout: Duration::from_secs(10),
            })
            .collect())
    }

    fn parse(&self, raw: &[u8], ctx: &ParseContext) -> Result<Normalized> {
        AdaptadorDePrueba.parse(raw, ctx)
    }
}

/// Directorio de marcadores dentro del tempdir del test, ya creado.
fn dir_marcadores(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let d = dir.path().join("marcadores");
    std::fs::create_dir_all(&d).unwrap();
    d
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
    // El recuento del fin de fase cuenta lo que se ARCHIVÓ, y tiene que
    // cuadrar con lo que `parse()` devolvió: un host, ningún servicio,
    // una observación.
    assert!(
        sucesos.iter().any(|s| matches!(
            s,
            SucesoRun::FaseTerminada {
                hosts: 1,
                servicios: 0,
                observaciones: 1
            }
        )),
        "el fin de fase tiene que traer el recuento de lo persistido"
    );

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

/// Los directorios de control que `iniciar_trabajador` crea bajo el
/// temporal del sistema, ahora mismo. Es la huella observable de haber
/// intentado elevar: `iniciar_trabajador` crea el directorio ANTES de
/// lanzar `osascript`, así que aparece incluso si el diálogo se rechaza.
/// Nada más en toda la suite llama a `iniciar_trabajador`, así que un
/// directorio nuevo entre dos instantáneas solo puede haberlo puesto la
/// llamada que hay en medio.
fn dirs_de_control_en_temporal() -> std::collections::BTreeSet<std::path::PathBuf> {
    let Ok(entradas) = std::fs::read_dir(std::env::temp_dir()) else {
        return std::collections::BTreeSet::new();
    };
    entradas
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("auscan-privilegio-"))
        })
        .collect()
}

/// Una fase con `elevar: false` no puede ni rozar el camino de
/// elevación: nada de `osascript`, nada de diálogo, nada de esperar 120
/// segundos a que el operador autorice algo que nadie pidió.
///
/// Y de paso prueba el otro lado del cambio de firma: el sexto parámetro
/// ya NO es `privilegio_disponible`. Lo que se archiva en
/// `tool_run.privileged` -- el privilegio REAL con el que corrió la
/// herramienta -- lo calcula ahora el propio orquestador, así que tiene
/// que coincidir con `preflight::running_privileged()` sin que este test
/// se lo haya dicho. Antes, ese `false` de la posición seis era
/// literalmente lo que acababa en la columna; si alguien volviera a
/// enchufar el parámetro directamente, correr la suite como root lo
/// delataría.
#[tokio::test]
async fn una_fase_sin_elevar_no_intenta_arrancar_ningun_trabajador() {
    let (_dir, state, _id) = estado_de_prueba();
    let registro: Vec<Box<dyn ToolAdapter>> = vec![Box::new(AdaptadorDePrueba)];
    let sucesos = Arc::new(std::sync::Mutex::new(Vec::new()));
    let s2 = sucesos.clone();

    let antes = dirs_de_control_en_temporal();

    ejecutar_fase(
        &state,
        &registro,
        Phase::Discovery,
        "prueba",
        &["198.51.100.5".to_string()],
        false, // elevar
        &PhaseOptions::default(),
        CancellationToken::new(),
        move |suceso| s2.lock().unwrap().push(suceso),
    )
    .await
    .unwrap();

    // 1. Ni un directorio de control nuevo: no se intentó arrancar nada.
    //    (Que el test haya terminado ya dice bastante -- un
    //    `iniciar_trabajador` de verdad se habría quedado esperando el
    //    diálogo --, pero "no colgó" no es una aserción; esto sí.)
    let nuevos: Vec<_> = dirs_de_control_en_temporal()
        .difference(&antes)
        .cloned()
        .collect();
    assert!(
        nuevos.is_empty(),
        "una fase sin elevar no puede crear directorio de control: {nuevos:?}"
    );

    // 2. La fase siguió siendo la de siempre, recuento incluido.
    let sucesos = sucesos.lock().unwrap();
    assert!(
        sucesos.iter().any(|s| matches!(
            s,
            SucesoRun::FaseTerminada {
                hosts: 1,
                servicios: 0,
                observaciones: 1
            }
        )),
        "el camino sin elevar sigue archivando y contando lo de siempre"
    );

    // 3. Y el privilegio archivado es el que el orquestador calculó por
    //    su cuenta, no un booleano que le pasara quien llama.
    let guard = state.open.lock().unwrap();
    let conn = &guard.as_ref().unwrap().conn;
    let privilegiado: bool = conn
        .query_row("SELECT privileged FROM tool_run LIMIT 1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        privilegiado,
        auscan_lib::preflight::running_privileged(),
        "sin trabajador, el privilegio archivado es el REAL del proceso"
    );
}

/// El número con el que se numeran las órdenes del trabajador NO es el
/// `seq` de `tool_run`.
///
/// El trabajador cuenta 1, 2, 3... dentro de su propio directorio de
/// control, que nace y muere con la fase, y atiende en orden estricto:
/// si la primera orden que ve escrita no es la `0001`, se queda
/// sondeando un fichero que nadie va a escribir nunca. El `seq` que el
/// orquestador le pasaba es `runs::siguiente_seq`, que es
/// ENGAGEMENT-global (`MAX(seq)+1` sobre todo `tool_run`): funcionaba
/// solo mientras el expediente no tuviera ninguna ejecución previa, y
/// colgaba la fase entera a partir de la segunda.
///
/// Por eso el test SIEMBRA una ejecución previa: sin ella, `seq` vale 1
/// y el bug no se manifiesta -- que es exactamente por lo que ninguna
/// prueba lo vio. Y por eso comprueba las dos mitades: que el protocolo
/// numera desde 1, y que la base y los ficheros crudos siguen usando el
/// `seq` global de siempre (5 y 6), que es lo que sostiene la
/// trazabilidad del expediente.
#[tokio::test]
async fn una_fase_elevada_numera_sus_ordenes_desde_uno_aunque_el_expediente_no_este_en_uno() {
    let (dir, state, id) = estado_de_prueba();
    {
        let guard = state.open.lock().unwrap();
        let conn = &guard.as_ref().unwrap().conn;
        auscan_lib::runs::crear_tool_run(
            conn,
            4,
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
        assert_eq!(
            auscan_lib::runs::siguiente_seq(conn).unwrap(),
            5,
            "el expediente tiene que llegar a la fase con el seq global lejos de 1"
        );
    }

    // Un trabajador de verdad (el mismo bucle que corre como root en
    // producción), arrancado a mano y sin privilegios: lo que se prueba
    // es el protocolo, que no depende de ser root.
    let dir_control = tempfile::tempdir().unwrap();
    let bucle = tokio::spawn(auscan_lib::worker::ejecutar_bucle(
        dir_control.path().to_path_buf(),
        std::process::id(),
    ));
    for _ in 0..50 {
        if auscan_lib::privilege::leer_listo(dir_control.path())
            .unwrap()
            .is_some()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let trabajador = Some(auscan_lib::privilege::TrabajadorActivo::para_pruebas(
        dir_control.path().to_path_buf(),
    ));

    let registro: Vec<Box<dyn ToolAdapter>> = vec![Box::new(AdaptadorEcoPorObjetivo)];
    tokio::time::timeout(
        Duration::from_secs(60),
        auscan_lib::orchestrator::ejecutar_fase_con_trabajador_para_pruebas(
            &state,
            &registro,
            Phase::Services,
            "eco-por-objetivo",
            &["198.51.100.5".to_string(), "198.51.100.6".to_string()],
            &trabajador,
            &PhaseOptions::default(),
            CancellationToken::new(),
            |_| {},
        ),
    )
    .await
    .expect("la fase elevada no puede colgarse esperando a un trabajador que sí está vivo")
    .unwrap();

    // 1. El trabajador atendió DE VERDAD las dos órdenes, numeradas
    //    desde 1 en su propio directorio.
    for n in [1, 2] {
        assert!(
            auscan_lib::privilege::leer_estado(dir_control.path(), n)
                .unwrap()
                .is_some(),
            "el trabajador tenía que haber procesado la orden {n:04}"
        );
    }
    assert!(
        !dir_control.path().join("0005.orden.json").exists(),
        "el seq del expediente no puede acabar en el nombre de una orden"
    );

    // 2. Y la base y los crudos siguen con el seq ENGAGEMENT-global de
    //    siempre: es lo que el expediente ya archivado usa para
    //    referirse a cada ejecución. (En su propio bloque: el guard no
    //    puede seguir vivo cuando abajo se vuelve a esperar al
    //    trabajador.)
    {
        let guard = state.open.lock().unwrap();
        let conn = &guard.as_ref().unwrap().conn;
        let seqs: Vec<i64> = conn
            .prepare("SELECT seq FROM tool_run WHERE tool = 'eco-por-objetivo' ORDER BY seq")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(seqs, vec![5, 6]);
        for (seq, ip) in [(5, "198.51.100.5"), (6, "198.51.100.6")] {
            let (status, raw_path): (String, Option<String>) = conn
                .query_row(
                    "SELECT status, raw_path FROM tool_run WHERE seq = ?1",
                    [seq],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(
                status, "ok",
                "la invocación de {ip} tenía que correr entera"
            );
            assert_eq!(
                raw_path,
                Some(format!("raw/{seq:04}-eco-por-objetivo-services.xml"))
            );
            assert!(auscan_lib::paths::engagement_dir(dir.path(), &id)
                .unwrap()
                .join(raw_path.unwrap())
                .is_file());
        }
    }

    if let Some(t) = trabajador {
        auscan_lib::privilege::detener_trabajador(t).await.unwrap();
    }
    tokio::time::timeout(Duration::from_secs(5), bucle)
        .await
        .expect("el trabajador tenía que salir con el centinela de detener")
        .unwrap()
        .unwrap();
}

/// El otro lado de la Global Constraint sobre `elevar`: pedir elevación
/// donde no la hay es un error, nunca un "sigue sin privilegios" mudo.
/// Cambiar en silencio lo que se escanea sin que el operador lo decidiera
/// es exactamente el fallo que este diseño existe para impedir.
#[cfg(not(target_os = "macos"))]
#[tokio::test]
async fn pedir_elevacion_fuera_de_macos_falla_en_vez_de_seguir_sin_privilegios() {
    let (_dir, state, _id) = estado_de_prueba();
    let registro: Vec<Box<dyn ToolAdapter>> = vec![Box::new(AdaptadorDePrueba)];

    let resultado = ejecutar_fase(
        &state,
        &registro,
        Phase::Discovery,
        "prueba",
        &["198.51.100.5".to_string()],
        true, // elevar
        &PhaseOptions::default(),
        CancellationToken::new(),
        |_| {},
    )
    .await;

    assert!(
        matches!(resultado, Err(AppError::ElevationFailed(_))),
        "se esperaba ElevationFailed, llegó {resultado:?}"
    );
    // Y ni una fila: si hubiera seguido adelante sin privilegios, habría
    // lanzado el escáner igualmente y dejado su fila de auditoría.
    let guard = state.open.lock().unwrap();
    let conn = &guard.as_ref().unwrap().conn;
    let n_runs: i64 = conn
        .query_row("SELECT COUNT(*) FROM tool_run", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n_runs, 0, "una elevación fallida no ejecuta nada");
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

/// La cancelación se dispara con la invocación EN VUELO (desde el primer
/// log, como en el test de cambio de engagement), no con el token ya
/// cancelado de antemano: desde que el bucle de `ejecutar_fase` corta al
/// ver el token cancelado, una fase cancelada antes de empezar no llega
/// a ejecutar nada y por tanto no tiene ninguna fila que marcar -- ese
/// caso lo cubre `una_fase_cancelada_antes_de_empezar_no_deja_rastro`.
/// Lo que este test protege es el otro lado: lo que SÍ llegó a correr no
/// se borra por haberse cancelado.
#[tokio::test]
async fn ejecutar_fase_cancelada_deja_el_tool_run_marcado_y_no_persiste_hallazgos() {
    let (dir, state, id) = estado_de_prueba();
    let registro: Vec<Box<dyn ToolAdapter>> = vec![Box::new(AdaptadorPorObjetivo {
        dir_marcadores: dir_marcadores(&dir),
    })];
    let cancelar = CancellationToken::new();
    let señal = cancelar.clone();

    ejecutar_fase(
        &state,
        &registro,
        Phase::Services,
        "por-objetivo",
        &["198.51.100.7".to_string()],
        false,
        &PhaseOptions::default(),
        cancelar,
        move |suceso| {
            if matches!(suceso, SucesoRun::Log { .. }) {
                señal.cancel();
            }
        },
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
    assert_eq!(raw_path, "raw/0001-por-objetivo-services.xml");
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

/// La otra mitad: si el token ya venía cancelado, no hay nada que
/// registrar. Una fila en `tool_run` afirma que una herramienta se lanzó
/// contra un objetivo del cliente; escribirla por una invocación que
/// jamás llegó a existir es exactamente el tipo de afirmación falsa que
/// este expediente no puede permitirse.
///
/// La fase igualmente tiene que señalar su fin: el store del frontend
/// solo sale de "corriendo" con `FaseTerminada`, así que cortar el bucle
/// sin emitirlo dejaría la UI colgada tras cada cancelación.
#[tokio::test]
async fn una_fase_cancelada_antes_de_empezar_no_deja_rastro() {
    let (dir, state, _id) = estado_de_prueba();
    let adaptador = AdaptadorPorObjetivo {
        dir_marcadores: dir_marcadores(&dir),
    };
    let marcador = adaptador.marcador(&"198.51.100.8".parse().unwrap());
    let registro: Vec<Box<dyn ToolAdapter>> = vec![Box::new(adaptador)];
    let cancelar = CancellationToken::new();
    cancelar.cancel(); // ya cancelado antes de empezar

    let sucesos = Arc::new(std::sync::Mutex::new(Vec::new()));
    let s2 = sucesos.clone();
    ejecutar_fase(
        &state,
        &registro,
        Phase::Services,
        "por-objetivo",
        &["198.51.100.8".to_string()],
        false,
        &PhaseOptions::default(),
        cancelar,
        move |suceso| s2.lock().unwrap().push(suceso),
    )
    .await
    .unwrap();

    assert!(
        !marcador.exists(),
        "no se lanza ningún proceso con el token ya cancelado"
    );
    let guard = state.open.lock().unwrap();
    let conn = &guard.as_ref().unwrap().conn;
    let n_runs: i64 = conn
        .query_row("SELECT COUNT(*) FROM tool_run", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        n_runs, 0,
        "una invocación que nunca se ejecutó no deja fila en tool_run"
    );

    let sucesos = sucesos.lock().unwrap();
    // Y con el recuento a cero: una fase que no ejecutó nada no archivó
    // nada, así que enseñar cualquier otra cifra sería inventarla.
    assert!(
        sucesos.iter().any(|s| matches!(
            s,
            SucesoRun::FaseTerminada {
                hosts: 0,
                servicios: 0,
                observaciones: 0
            }
        )),
        "la fase tiene que señalar su fin aunque se corte por cancelación"
    );
}

/// La prueba que `tests/exec_spawn.rs` dejó pendiente ("hará falta una
/// prueba real el día que exista un llamador que invoque `ejecutar()`
/// más de una vez por fase"): ese llamador es el bucle de invocaciones
/// del orquestador.
///
/// Cancelar una fase tiene que PARARLA. Antes, el bucle seguía llamando
/// a `ejecutar_invocacion` para cada invocación restante: cada una
/// resolvía el binario, revalidaba la versión, pasaba la verja,
/// insertaba su fila en `tool_run`, lanzaba el escáner de verdad y lo
/// mataba acto seguido. En una fase Services contra una red entera eso
/// es un `spawn` -- y una fila de auditoría de una ejecución que nunca
/// llegó a escanear nada -- por cada host que quedara.
///
/// La cancelación se dispara desde `on_suceso`, al recibir la primera
/// línea de log: eso sitúa el corte con la primera invocación EN VUELO,
/// que es el caso real (el operador da a "cancelar" con el escaneo
/// corriendo), no el trivial de un token ya cancelado antes de empezar.
#[tokio::test]
async fn cancelar_a_media_fase_no_lanza_las_invocaciones_que_quedaban() {
    let (dir, state, _id) = estado_de_prueba();
    let adaptador = AdaptadorPorObjetivo {
        dir_marcadores: dir_marcadores(&dir),
    };
    let ip_primera: std::net::IpAddr = "198.51.100.5".parse().unwrap();
    let ip_segunda: std::net::IpAddr = "198.51.100.6".parse().unwrap();
    let (marcador_primera, marcador_segunda) = (
        adaptador.marcador(&ip_primera),
        adaptador.marcador(&ip_segunda),
    );
    let registro: Vec<Box<dyn ToolAdapter>> = vec![Box::new(adaptador)];

    let cancelar = CancellationToken::new();
    let señal = cancelar.clone();

    ejecutar_fase(
        &state,
        &registro,
        Phase::Services,
        "por-objetivo",
        &["198.51.100.5".to_string(), "198.51.100.6".to_string()],
        false,
        &PhaseOptions::default(),
        cancelar,
        move |suceso| {
            if matches!(suceso, SucesoRun::Log { .. }) {
                señal.cancel();
            }
        },
    )
    .await
    .unwrap();

    // 1. La primera invocación sí llegó a lanzarse: sin esto, el test
    //    pasaría igual si el plan hubiera salido vacío o el adaptador no
    //    hubiera arrancado nada, sin haber ejercitado nada.
    assert!(
        marcador_primera.is_file(),
        "la primera invocación tenía que haberse lanzado antes de cancelar"
    );

    // 2. Y la segunda no llegó a existir como proceso.
    assert!(
        !marcador_segunda.exists(),
        "cancelar la fase no debe lanzar el escáner de los objetivos que quedaban"
    );

    // 3. Ni como fila de auditoría: una invocación que nunca se ejecutó
    //    no puede dejar rastro de haberlo hecho.
    let guard = state.open.lock().unwrap();
    let conn = &guard.as_ref().unwrap().conn;
    let (n_runs, status, targets_json): (i64, String, String) = conn
        .query_row(
            "SELECT (SELECT COUNT(*) FROM tool_run), status, targets_json
             FROM tool_run LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        n_runs, 1,
        "solo la invocación en vuelo al cancelar deja fila en tool_run"
    );
    assert_eq!(status, "cancelled");
    assert!(
        targets_json.contains("198.51.100.5"),
        "la única fila tiene que ser la de la invocación en vuelo, llegó {targets_json}"
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

/// `planificar` es lo que hay detrás del comando `run_preview`: el
/// diálogo de confirmación enseña el argv REAL, no uno reconstruido en
/// la webview. Que devuelva el argv correcto es la mitad del trato.
#[test]
fn planificar_devuelve_el_argv_real_de_la_fase() {
    let (_dir, state, id) = estado_de_prueba();
    let registro: Vec<Box<dyn ToolAdapter>> = vec![Box::new(AdaptadorDePrueba)];

    let (invocaciones, id_devuelto) = planificar(
        &state,
        &registro,
        Phase::Discovery,
        "prueba",
        &["198.51.100.5".to_string()],
        false,
        &PhaseOptions::default(),
    )
    .unwrap();

    assert_eq!(id_devuelto, id);
    assert_eq!(invocaciones.len(), 1);
    assert_eq!(
        invocaciones[0].argv,
        vec![BANDERA.to_string(), "echo hola".to_string()]
    );
    // La forma exacta que `run_preview` le entrega al frontend: una
    // línea por invocación, herramienta más argv.
    assert_eq!(
        invocaciones
            .iter()
            .map(|inv| format!("prueba {}", inv.argv.join(" ")))
            .collect::<Vec<_>>(),
        vec![format!("prueba {BANDERA} echo hola")]
    );
}

/// La otra mitad, y la que de verdad importa: una "vista previa" que
/// ejecutara a escondidas sería un fallo grave -- el operador vería el
/// diálogo de confirmación DESPUÉS de que el escáner ya hubiera tocado
/// la red del cliente. Se comprueba contra un adaptador que deja
/// marcador al arrancar (para distinguir "no quedó fila" de "no se lanzó
/// el proceso") y contra la base entera.
#[test]
fn planificar_no_ejecuta_nada_ni_deja_rastro() {
    let (dir, state, id) = estado_de_prueba();
    let adaptador = AdaptadorPorObjetivo {
        dir_marcadores: dir_marcadores(&dir),
    };
    let marcador = adaptador.marcador(&"198.51.100.5".parse().unwrap());
    let registro: Vec<Box<dyn ToolAdapter>> = vec![Box::new(adaptador)];

    let (invocaciones, _) = planificar(
        &state,
        &registro,
        Phase::Services,
        "por-objetivo",
        &["198.51.100.5".to_string()],
        false,
        &PhaseOptions::default(),
    )
    .unwrap();
    assert_eq!(invocaciones.len(), 1, "sí planificó algo que ejecutar");

    assert!(
        !marcador.exists(),
        "una vista previa no puede haber lanzado ningún proceso"
    );
    // `raw/` ya existe antes de nada: lo crea `engagement::create`. Lo
    // que prueba algo es que siga VACÍO -- ni un fichero crudo dentro.
    assert_eq!(
        std::fs::read_dir(auscan_lib::paths::raw_dir(dir.path(), &id).unwrap())
            .unwrap()
            .count(),
        0,
        "una vista previa no escribe ningún fichero crudo"
    );
    let guard = state.open.lock().unwrap();
    let conn = &guard.as_ref().unwrap().conn;
    for tabla in ["tool_run", "host", "service", "observation"] {
        let n: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {tabla}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "una vista previa no puede dejar filas en {tabla}");
    }
}

/// El rechazo de alcance ocurre en `planificar`, así que llega en la
/// vista previa: el operador se entera de que su objetivo está fuera
/// ANTES de ver un diálogo de confirmación con pinta de legítimo.
#[test]
fn planificar_rechaza_un_objetivo_fuera_de_alcance() {
    let (_dir, state, _id) = estado_de_prueba();
    let registro: Vec<Box<dyn ToolAdapter>> = vec![Box::new(AdaptadorDePrueba)];

    let resultado = planificar(
        &state,
        &registro,
        Phase::Discovery,
        "prueba",
        &["203.0.113.9".to_string()],
        false,
        &PhaseOptions::default(),
    );

    assert!(
        matches!(resultado, Err(AppError::OutOfScope(ref ip)) if ip == "203.0.113.9"),
        "se esperaba OutOfScope, llegó {:?}",
        resultado.map(|(inv, _)| inv.len())
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
