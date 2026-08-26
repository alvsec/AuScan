# Modelo de amenazas de AUscan

Este documento trata las amenazas **de la propia aplicación**, no las de las
redes que audita. Cada mitigación apunta al fichero y la función que la
implementan: un modelo de amenazas que no señala código es una lista de
intenciones.

## Activos

1. El alcance autorizado. Su integridad es lo que separa una auditoría legal de
   un delito.
2. Los datos recolectados del cliente.
3. La confianza de que la app hace solo detección.

## Amenazas

### T1 · La app escanea algo fuera de alcance

La peor. `scope.rs` es la autoridad única y el **único** módulo capaz de
construir un `ScopedTarget`: el campo es privado y no hay constructor público, de
modo que fuera de ahí es imposible fabricar uno.

El orden de evaluación es deliberado: alcance vacío, luego exclusiones, luego
autorizaciones. `deny` gana siempre sobre `allow`, sin importar la especificidad,
y un alcance sin ninguna entrada `allow` **rechaza todo** — el estado por defecto
es "nada autorizado", nunca lo contrario.

Dos refuerzos concretos:

- **Los objetivos viajan como IP, nunca como nombre.** Un nombre se resuelve
  antes, se validan todas sus direcciones, y si una sola cae fuera se rechaza la
  petición entera. Así ninguna herramienta puede volver a resolver por su cuenta
  y acabar tocando algo que el guard nunca vio (`Scope::validate_target`).
- **Las entradas se canonicalizan antes de comparar.** Una exclusión escrita como
  `::ffff:192.0.2.0/120` se reduce a su red v4 real. Sin esto quedaba guardada
  como red IPv6 y no excluía nada, porque `contains()` entre familias distintas
  siempre es falso: un `deny` inerte que decía "dentro de alcance" justo donde el
  consultor había escrito lo contrario (`canonical_net`).

Un `/0` se rechaza: autorizar todo el espacio de direcciones no es un alcance,
es la ausencia de uno.

**Dónde:** `src-tauri/src/scope.rs` · `src-tauri/tests/scope_guard.rs` ·
`src-tauri/tests/scope_parity.rs` · `fixtures/scope/corpus.json`

### T2 · Datos del cliente que sobreviven al encargo

Directorio por engagement, purga que borra y **comprueba** que no queda nada, y
`temp_store = MEMORY` para que SQLite no derrame temporales fuera de ese
directorio.

**Dónde:** `src-tauri/src/engagement.rs` (`purge`) · `src-tauri/src/db.rs`
(`open`) · `src-tauri/tests/purge.rs` · [DATA-POLICY.md](DATA-POLICY.md)

### T3 · Datos del cliente que acaban en el repositorio público

Los fixtures solo pueden contener direcciones de documentación, y CI lo
comprueba: RFC 5737 para IPv4, `2001:db8::/32` para IPv6, MAC localmente
administradas. **RFC 1918 está prohibido**, precisamente porque un `192.168.1.x`
real y uno inventado son indistinguibles a simple vista.

Los nombres de host no se comprueban por expresión regular a propósito: un patrón
lo bastante amplio para pillar `srv.cliente.com` también pilla `package.json` y
`v1.2.3`, y un check que cría lobos deja de leerse. Van por revisión.

**Dónde:** `scripts/checks/fixtures.mjs` · `.github/workflows/ci.yml`

### T4 · Una herramienta invocada en modo intrusivo

Cada herramienta declarará su lista de banderas permitidas, con marca de cuáles
exigen privilegios, y el núcleo rechazará antes de lanzar cualquier argv que se
salga. Añadir una capacidad activa obliga así a tocar una lista corta y visible,
que aparece señalada en el diff.

`exec.rs` encadena tres comprobaciones puras —`validate_targets`,
`validate_flags` y `validate_binary`, combinadas en `verja()`— que correrán
antes de cualquier `spawn` real en cuanto la Fase 5 conecte la ejecución.
Desde la Fase 4, `adapters::registry()` ya incluye el adaptador de nmap con
su lista real de banderas permitidas, pero ningún camino de producción llama
todavía a `verja()`: esta fase construye y parsea, no ejecuta. La verja en sí
existe y está testeada de punta a punta, ahora también contra el descriptor
real de nmap, no solo contra el adaptador de prueba.

**Cerrado en la Fase 4:** el emparejamiento de `validate_flags` era por
prefijo y tenía un hueco identificado en la revisión de la Fase 3 —no era una
lista verdaderamente cerrada (p. ej. `-pwn` casaría con `-p`), y una dirección
sin validar podía colarse pegada a una bandera permitida—. Ahora el
emparejamiento es por igualdad exacta; una bandera marcada `takes_value`
consume el siguiente token del argv como valor opaco en vez de intentar
casarlo como otra bandera.

**Límite conocido:** `needs_privilege` se compara hoy contra la propia
invocación (`Invocation.needs_privilege`, que pone el adaptador), no contra
el privilegio real del proceso. `verja()` no puede detectar todavía una
bandera privilegiada colada en una ejecución sin privilegios de verdad —
exigir que quien la llame pase el privilegio efectivo (`running_privileged()`
o equivalente) queda como requisito de la Fase 5.

**Dónde:** `src-tauri/src/exec.rs` · `src-tauri/src/adapters/nmap.rs` ·
`src-tauri/tests/exec_gate.rs`

### T5 · Binario suplantado

`preflight.rs` resuelve la ruta de cada herramienta buscándola en `PATH`
(crate `which`) y compara la versión que reporta contra el mínimo exigido
(`check_tool`). Después, `validate_binary` en `exec.rs` exige que el binario
que de verdad se va a ejecutar sea el mismo path, byte a byte, que preflight
resolvió — así un `nmap` aparecido en el directorio actual entre el arranque
y la ejecución no puede colarse.

**Límite conocido:** `validate_binary` hoy solo compara dos rutas por
igualdad exacta; no vuelve a comprobar la versión del binario justo antes de
cada ejecución, que es lo que esta mitigación prometía originalmente.
Revalidar la versión en el momento de ejecutar sigue siendo un requisito
explícito para la Fase 5, cuando se conecte el lanzamiento de procesos real,
y todavía no está implementado.

**Dónde:** `src-tauri/src/preflight.rs` · `src-tauri/src/exec.rs`

### T6 · Inyección de comandos

El argv es un array y se ejecuta sin shell. En la ruta elevada, si el spike
concluye que hace falta, el entrecomillado pasará por un quoter propio con tests.

**Dónde:** parcialmente pendiente; el diseño está en
[ADR-0004](adr/0004-privilegios-en-macos.md).

### T7 · Exfiltración por telemetría

No existe telemetría. CI falla si aparece un cliente HTTP: para JavaScript
inspecciona el lockfile en sus tres formas —ruta, transitiva anidada y alias—, y
para Rust consulta el grafo real de dependencias del objetivo de escritorio en
vez del lockfile, porque el lockfile incluye todas las plataformas y `tauri`
arrastra `reqwest` solo para móvil.

Si `cargo` no responde, el check **sale con error** en vez de pasar en verde. Un
check que no puede comprobar tiene que decirlo: si no, deja de comprobar sin que
nadie se entere.

La webview corre con una CSP restrictiva (`default-src 'self'`, más
`form-action 'none'` y `base-uri 'none'`) y su capability concede únicamente
`core:default`. No hay plugin de apertura de URLs ni de diálogos: conceder
permisos que nadie usa solo amplía lo que alcanzaría una webview comprometida.

**Límite conocido:** Tauri solo inyecta esta CSP en el asset servido en
producción; en `tauri dev` la ventana carga directamente desde el servidor de
Vite sin CSP. La superficie real está cubierta en el binario que se distribuye,
no durante el desarrollo.

`scope_check` acepta solo direcciones literales. Resolver nombres ahí lo
convertiría en un oráculo de DNS: cualquier cadena de la webview saldría a la red
en una consulta antes de que el alcance tuviera nada que decir, y el error
posterior haría que todo pareciese normal.

**Dónde:** `scripts/checks/no-http-client.mjs` · `src-tauri/tauri.conf.json` ·
`src-tauri/capabilities/default.json` · `src-tauri/src/lib.rs` (`scope_check`)

### T8 · Abuso de la elevación de privilegios

Por ejecución y a petición explícita, sin credenciales almacenadas —la contraseña
la pide el sistema y nunca pasa por el proceso— y sin demonio persistente. La app
nunca corre entera como root.

**Dónde:** [ADR-0004](adr/0004-privilegios-en-macos.md).

### T9 · Ficheros propiedad de root en el directorio del engagement

nmap escribe su XML a stdout (`-oX -`) y lo captura el proceso sin privilegios,
que es quien crea el fichero. Aunque nmap corra como root, en `raw/` no queda
nada que exija autenticarse otra vez para purgarlo.

**Dónde:** [ADR-0004](adr/0004-privilegios-en-macos.md).

### T10 · Datos en claro en un disco robado

FileVault o BitLocker. No hay cifrado de aplicación, y el porqué está en
[ADR-0003](adr/0003-filevault-como-frontera-de-cifrado.md).

### T11 · Travesía de directorios al purgar

`purge` acaba llamando a `remove_dir_all` con una ruta derivada de un
identificador que llega del frontend. `paths::engagement_dir` parsea
ese identificador como UUID y usa el UUID **reserializado** como componente de
ruta, así que ninguna cadena sobrevive: `../../etc` no llega a ser una ruta.
`engagement_db_path` y `raw_dir` pasan las dos por esa misma función.

Además, todo identificador se canonicaliza al cruzar la frontera de comandos
(`engagement::canonical_id`). `Uuid::parse_str` acepta cuatro codificaciones del
mismo UUID, y la ruta las normalizaba todas mientras las comparaciones usaban la
cadena cruda: con el identificador entre llaves y en mayúsculas se borraba el
directorio sin cerrar la conexión ni escribir la lápida, y el índice seguía
diciendo que el engagement estaba vivo.

**Dónde:** `src-tauri/src/paths.rs` · `src-tauri/tests/paths.rs`

## Fuera del modelo

- Un atacante con ejecución de código en la máquina del consultor. Si tiene eso,
  tiene la sesión, y ningún control de esta app lo detiene.
- La seguridad de las herramientas externas. AUscan las orquesta; no las audita.
- Un consultor malintencionado. La app impone el alcance que se le declara: no
  puede saber si el documento de autorización es auténtico.
