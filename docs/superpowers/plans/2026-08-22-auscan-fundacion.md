# AUscan — Plan de implementación · Fundación (Fases 1–2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Dejar en pie el esqueleto de AUscan con persistencia por engagement, purga verificable y el guard de alcance completo y testeado, antes de que exista ningún adaptador.

**Architecture:** Tauri 2 con la base de datos en poder de Rust (el frontend nunca ve SQL). Dos bases: un `index.db` global anémico y un `engagement.db` por engagement dentro de su propio directorio, lo que hace que purgar sea borrar un directorio y comprobar que no existe. `scope.rs` es la autoridad única del alcance y el único módulo capaz de fabricar un `ScopedTarget`; el TypeScript tiene un espejo para feedback en vivo que no decide nada y que un corpus compartido obliga a mantener en paridad.

**Tech Stack:** Tauri 2 · Rust (rusqlite bundled, ipnet, uuid, thiserror, serde) · React 19 · TypeScript strict · Vite · Tailwind v4 · Zustand · i18next · vitest + testing-library · cargo test

**Spec:** `docs/superpowers/specs/2026-08-22-auscan-design.md`

## Global Constraints

Requisitos de proyecto. Se aplican implícitamente a **todas** las tareas.

- **TypeScript strict.** `tsconfig.json` con `"strict": true`. Sin `any` sin justificar en comentario.
- **`npm run check` en verde al final de cada tarea.** Es typecheck + lint + vitest + `cargo test`.
- **Un commit por tarea.** Mensajes en español, imperativo, con prefijo convencional (`feat:`, `test:`, `docs:`, `chore:`). Terminan con `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.
- **Pragmas SQLite obligatorios en toda conexión:** `journal_mode = WAL`, `foreign_keys = ON`, `temp_store = MEMORY`. El último no es opcional: sin él SQLite derrama temporales en `/var/folders`, fuera del alcance de la purga.
- **`observation` no tiene ni tendrá columna de severidad.** Si un parser futuro la necesita, va en `meta_json` bajo `tool_reported`.
- **`ScopedTarget` solo se construye dentro de `scope.rs`.** Campo privado, sin constructor público. Cualquier tarea que necesite uno lo obtiene de `Scope::validate`.
- **Evaluación del alcance:** `deny` gana siempre sobre `allow`. Alcance sin ninguna entrada `allow` rechaza **todo**. El defecto es "nada autorizado".
- **Datos sintéticos en `fixtures/`, sin excepción:** IPv4 solo `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737); IPv6 solo `2001:db8::/32` (RFC 3849); hostnames solo `.example`, `example.com`, `example.org` (RFC 2606); MAC solo localmente administradas (`02:`, `06:`, `0a:`, `0e:`). **RFC 1918 está prohibido en fixtures.**
- **Sin cliente HTTP en la app.** Prohibidos en lockfiles: `reqwest`, `ureq`, `isahc`, `axios`, `node-fetch`. La app no habla con la red; solo lo hacen las herramientas que lanza.
- **Paridad de claves i18n** entre `src/i18n/locales/es.json` y `en.json`.

## Nota sobre versiones de dependencias

El plan **no fija números de versión de crates**: cada tarea usa `cargo add <crate>` y deja que resuelva la última compatible. Las APIs empleadas (`Connection::open`, `execute`, `execute_batch`, `query_row`, `prepare`/`query_map`, `pragma_update`, `IpNet::contains`, `Uuid::parse_str`) llevan estables muchas versiones. Si algo no compila, el error de `cargo` dice exactamente qué cambió.

## Fase 0 en paralelo (no bloquea ninguna tarea)

El spike de privilegios de §8.6 de la spec es trabajo manual del operador en su propia red, no código. Puede hacerse en cualquier momento mientras corre este plan. Su resultado se escribe en ADR-0004 (Tarea 14) y decide dónde cae la Fase 9 del plan siguiente:

1. Instalar ChmodBPF (viene con Wireshark) y confirmar pertenencia al grupo `access_bpf`.
2. `nmap -sn -PR --send-eth 198.51.100.0/24` sin `sudo` sobre la red propia. ¿Hace ARP de verdad o cae a TCP?
3. Comparar el recuento de hosts con el mismo comando bajo `sudo`. Si coinciden, el spike sale bien.
4. Anotar versión de nmap, versión de macOS y salida literal de ambos comandos.

---

## Estructura de ficheros

**Rust (`src-tauri/src/`)** — un fichero, una responsabilidad:

| Fichero | Responsabilidad |
|---|---|
| `error.rs` | Tipo de error único de la app y su serialización hacia el frontend |
| `paths.rs` | Resolución de rutas del app-data dir. **Puro**: recibe la raíz como parámetro |
| `db.rs` | Apertura de conexiones con pragmas + runner de migraciones |
| `engagement.rs` | Ciclo de vida: crear, listar, abrir, purgar |
| `scope.rs` | ★ El guard. Parseo, canonicalización, `ScopedTarget`, resolución |
| `state.rs` | Estado compartido de Tauri: conexiones abiertas |
| `lib.rs` | Comandos `#[tauri::command]` + `invoke_handler`. Sin lógica |

**Migraciones (`src-tauri/migrations/`)** — dos conjuntos, append-only:
`index/0001_index.sql` · `engagement/0001_init.sql`

**TypeScript (`src/`)**:

| Fichero | Responsabilidad |
|---|---|
| `domain/scope/inScope.ts` | Espejo del guard. **Solo UX.** No decide nada |
| `domain/model/types.ts` | Tipos del dominio, espejo de las structs de Rust |
| `data/engagements.ts` | Envoltorio tipado sobre `invoke` |
| `store/useAppStore.ts` | Estado global Zustand |
| `pages/Engagements.tsx` · `pages/Scope.tsx` | Pantallas |
| `i18n/index.ts` · `i18n/locales/{es,en}.json` | Traducción |

**Tests**: `src-tauri/tests/{paths,migrations,engagement,purge,scope_guard}.rs` · `src/**/*.test.ts(x)` · `fixtures/scope/corpus.json` (compartido por Rust y TS)

**Scripts de comprobación (`scripts/`)**: `check-fixtures.mjs` · `check-no-http-client.mjs` · `check-i18n-parity.mjs`

---

## Task 1: Scaffold Tauri 2 + React 19 + TypeScript strict

**Files:**
- Create: `package.json`, `tsconfig.json`, `tsconfig.node.json`, `vite.config.ts`, `index.html`, `eslint.config.js`, `.prettierrc.json`, `.gitignore`
- Create: `src/main.tsx`, `src/App.tsx`, `src/index.css`, `src/version.ts`
- Create: `src-tauri/Cargo.toml`, `src-tauri/build.rs`, `src-tauri/tauri.conf.json`, `src-tauri/src/main.rs`, `src-tauri/src/lib.rs`
- Test: `src/version.test.ts`

**Interfaces:**
- Consumes: nada.
- Produces: `npm run check` (typecheck + lint + vitest + cargo test) y `npm run tauri:dev`. Constante `APP_VERSION` en `src/version.ts`.

- [ ] **Step 1: Generar el scaffold en un directorio aparte y traerlo**

El repo ya tiene `docs/` y `.git`, así que el generador no puede correr in situ.

```bash
cd /tmp && rm -rf auscan-scaffold
npm create tauri-app@latest auscan-scaffold -- --template react-ts --manager npm --yes
cd /Users/airunb01/Desktop/AUscan
cp -R /tmp/auscan-scaffold/{package.json,tsconfig.json,tsconfig.node.json,vite.config.ts,index.html,src,src-tauri} .
rm -rf /tmp/auscan-scaffold
```

Renombrar el proyecto a `auscan` en `package.json`, `src-tauri/Cargo.toml` y `src-tauri/tauri.conf.json` (campos `productName`, `identifier` → `com.auscan.desktop`; **no** terminar el identificador en `.app`, que colisiona con la extensión de bundle de macOS).

- [ ] **Step 2: Endurecer TypeScript y añadir el pipeline de comprobación**

En `tsconfig.json`, dentro de `compilerOptions`:

```json
{
  "strict": true,
  "noUncheckedIndexedAccess": true,
  "noImplicitOverride": true,
  "noFallthroughCasesInSwitch": true,
  "exactOptionalPropertyTypes": true
}
```

Instalar herramientas y fijar scripts:

```bash
npm i -D vitest jsdom @testing-library/react @testing-library/jest-dom \
        @testing-library/user-event @vitejs/plugin-react \
        eslint @eslint/js typescript-eslint prettier
npm i zustand i18next react-i18next clsx tailwind-merge lucide-react
npm i @tauri-apps/plugin-dialog
```

En `package.json`, sección `scripts`:

```json
{
  "dev": "vite",
  "build": "tsc && vite build",
  "tauri:dev": "tauri dev",
  "typecheck": "tsc --noEmit",
  "lint": "eslint .",
  "test": "vitest run",
  "check:rust": "cargo test --manifest-path src-tauri/Cargo.toml",
  "check": "npm run typecheck && npm run lint && npm run test && npm run check:rust"
}
```

En `vite.config.ts`, añadir la configuración de test:

```ts
test: {
  environment: "jsdom",
  globals: true,
  setupFiles: ["./src/test/setup.ts"],
},
```

Crear `src/test/setup.ts`:

```ts
import "@testing-library/jest-dom/vitest";
```

- [ ] **Step 3: Escribir el test que falla**

El scaffold no expone la versión al código. `src/version.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import pkg from "../package.json";
import { APP_VERSION } from "./version";

describe("APP_VERSION", () => {
  it("coincide con la versión de package.json", () => {
    expect(APP_VERSION).toBe(pkg.version);
  });
});
```

Requiere `"resolveJsonModule": true` en `tsconfig.json`. Sin atributos de
import: dependen de la versión de TypeScript y aquí no aportan nada.

- [ ] **Step 4: Ejecutar el test y verificar que falla**

Run: `npx vitest run src/version.test.ts`
Expected: FAIL — `Cannot find module './version'`.

- [ ] **Step 5: Implementación mínima**

`src/version.ts`:

```ts
import pkg from "../package.json";

export const APP_VERSION: string = pkg.version;
```

- [ ] **Step 6: Ejecutar la comprobación completa**

Run: `npm run check`
Expected: PASS en las cuatro etapas. `cargo test` no tiene tests todavía y termina en 0, que es correcto.

- [ ] **Step 7: Comprobar que la app arranca**

Run: `npm run tauri:dev`
Expected: se abre una ventana. Cerrarla.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "$(cat <<'MSG'
chore: scaffold Tauri 2 + React 19 + TypeScript strict

Pipeline npm run check con typecheck, lint, vitest y cargo test.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 2: Tipo de error y resolución de rutas

**Files:**
- Create: `src-tauri/src/error.rs`, `src-tauri/src/paths.rs`
- Modify: `src-tauri/src/lib.rs` (declarar los módulos)
- Test: `src-tauri/tests/paths.rs`

**Interfaces:**
- Consumes: nada.
- Produces: `AppError` (enum), `Result<T> = std::result::Result<T, AppError>`, y de `paths`: `index_db_path(root: &Path) -> PathBuf`, `engagements_dir(root: &Path) -> PathBuf`, `engagement_dir(root: &Path, id: &str) -> Result<PathBuf>`, `engagement_db_path(root: &Path, id: &str) -> Result<PathBuf>`, `raw_dir(root: &Path, id: &str) -> Result<PathBuf>`.

**Por qué existe esta tarea:** `engagement_dir` recibe un identificador que en el futuro llegará desde el frontend. Si concatenase sin validar, `"../../.."` saldría del app-data dir y la purga borraría lo que no debe. Se valida reparseando el UUID y volviéndolo a serializar: lo que no sea un UUID no sobrevive.

- [ ] **Step 1: Añadir dependencias**

```bash
cd src-tauri
cargo add thiserror serde --features serde/derive
cargo add uuid --features v4
cargo add rusqlite --features bundled
cd ..
```

- [ ] **Step 2: Escribir el test que falla**

`src-tauri/tests/paths.rs`:

```rust
use auscan_lib::paths;
use std::path::Path;

const ROOT: &str = "/tmp/auscan-test-root";
const VALID: &str = "7f3a4c2e-0b1d-4e5f-8a9b-1c2d3e4f5a6b";

#[test]
fn engagement_dir_cuelga_de_engagements() {
    let root = Path::new(ROOT);
    let dir = paths::engagement_dir(root, VALID).expect("uuid válido");
    assert_eq!(dir, paths::engagements_dir(root).join(VALID));
    assert!(dir.starts_with(paths::engagements_dir(root)));
}

#[test]
fn rechaza_travesia_de_directorios() {
    let root = Path::new(ROOT);
    for malicioso in ["../../etc", "..", "/etc/passwd", "7f3a/../..", ""] {
        assert!(
            paths::engagement_dir(root, malicioso).is_err(),
            "debería rechazar {malicioso:?}"
        );
    }
}

#[test]
fn rechaza_uuid_malformado() {
    let root = Path::new(ROOT);
    assert!(paths::engagement_dir(root, "no-soy-un-uuid").is_err());
}

#[test]
fn index_db_esta_en_la_raiz() {
    assert_eq!(
        paths::index_db_path(Path::new(ROOT)),
        Path::new(ROOT).join("index.db")
    );
}

#[test]
fn raw_dir_cuelga_del_engagement() {
    let root = Path::new(ROOT);
    let raw = paths::raw_dir(root, VALID).unwrap();
    assert_eq!(raw, paths::engagement_dir(root, VALID).unwrap().join("raw"));
}
```

- [ ] **Step 3: Ejecutar el test y verificar que falla**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test paths`
Expected: FAIL — no existe el crate `auscan_lib` o el módulo `paths`.

- [ ] **Step 4: Implementar `error.rs`**

```rust
use serde::{Serialize, Serializer};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("identificador de engagement inválido: {0:?}")]
    InvalidEngagementId(String),

    #[error("objetivo fuera de alcance: {0}")]
    OutOfScope(String),

    #[error("alcance vacío: no hay ningún rango autorizado")]
    EmptyScope,

    #[error("entrada de alcance ambigua: {0} — usa la dirección de red o /32")]
    AmbiguousCidr(String),

    #[error("dirección o rango no válido: {0}")]
    InvalidAddress(String),

    #[error("no se pudo resolver el nombre {0}")]
    UnresolvableHost(String),

    #[error("no hay ningún engagement abierto")]
    NoEngagementOpen,

    #[error("el engagement {0} no existe")]
    EngagementNotFound(String),

    #[error("la purga dejó restos en {0}")]
    PurgeIncomplete(String),

    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, AppError>;

// Los comandos de Tauri devuelven el error al frontend como cadena.
impl Serialize for AppError {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}
```

- [ ] **Step 5: Implementar `paths.rs`**

```rust
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::error::{AppError, Result};

pub fn index_db_path(root: &Path) -> PathBuf {
    root.join("index.db")
}

pub fn engagements_dir(root: &Path) -> PathBuf {
    root.join("engagements")
}

/// Reparsea el identificador como UUID y lo vuelve a serializar antes de
/// usarlo como nombre de directorio. Nada que no sea un UUID sobrevive,
/// así que ninguna cadena del frontend puede escapar del app-data dir.
pub fn engagement_dir(root: &Path, id: &str) -> Result<PathBuf> {
    let uuid = Uuid::parse_str(id).map_err(|_| AppError::InvalidEngagementId(id.to_string()))?;
    Ok(engagements_dir(root).join(uuid.to_string()))
}

pub fn engagement_db_path(root: &Path, id: &str) -> Result<PathBuf> {
    Ok(engagement_dir(root, id)?.join("engagement.db"))
}

pub fn raw_dir(root: &Path, id: &str) -> Result<PathBuf> {
    Ok(engagement_dir(root, id)?.join("raw"))
}
```

**Nota:** `Uuid::parse_str` acepta mayúsculas y minúsculas pero `Uuid::to_string` siempre emite minúsculas, así que el nombre del directorio es canónico venga como venga el identificador.

- [ ] **Step 6: Declarar los módulos en `lib.rs`**

Al principio de `src-tauri/src/lib.rs`:

```rust
pub mod error;
pub mod paths;
```

Confirmar que `src-tauri/Cargo.toml` tiene el bloque `[lib]` con `name = "auscan_lib"`. El scaffold lo genera; si no está, añadirlo:

```toml
[lib]
name = "auscan_lib"
crate-type = ["staticlib", "cdylib", "rlib"]
```

- [ ] **Step 7: Ejecutar el test y verificar que pasa**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test paths`
Expected: PASS, 5 tests.

- [ ] **Step 8: Commit**

```bash
git add src-tauri/src/error.rs src-tauri/src/paths.rs src-tauri/src/lib.rs \
        src-tauri/tests/paths.rs src-tauri/Cargo.toml src-tauri/Cargo.lock
git commit -m "$(cat <<'MSG'
feat: tipo de error y resolución de rutas con validación de UUID

engagement_dir reparsea el identificador como UUID antes de usarlo como
nombre de directorio, de modo que ninguna cadena del frontend puede
escapar del app-data dir.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 3: Conexión con pragmas, runner de migraciones y esquema de `index.db`

**Files:**
- Create: `src-tauri/src/db.rs`, `src-tauri/migrations/index/0001_index.sql`
- Modify: `src-tauri/src/lib.rs`
- Test: `src-tauri/tests/migrations.rs`

**Interfaces:**
- Consumes: `error::Result` (Tarea 2).
- Produces: `db::open(path: &Path) -> Result<Connection>`, `db::open_index(root: &Path) -> Result<Connection>`, `db::migrate(conn: &Connection, set: &[(&str, &str)]) -> Result<()>`, constantes `db::INDEX_MIGRATIONS` y `db::ENGAGEMENT_MIGRATIONS`, y `db::now_iso() -> String`.

- [ ] **Step 1: Escribir el test que falla**

`src-tauri/tests/migrations.rs`:

```rust
use auscan_lib::db;
use rusqlite::Connection;

fn temp_db() -> (tempfile::TempDir, Connection) {
    let dir = tempfile::tempdir().unwrap();
    let conn = db::open(&dir.path().join("t.db")).unwrap();
    (dir, conn)
}

fn pragma(conn: &Connection, name: &str) -> String {
    conn.query_row(&format!("PRAGMA {name}"), [], |r| {
        r.get::<_, rusqlite::types::Value>(0)
    })
    .map(|v| match v {
        rusqlite::types::Value::Text(s) => s,
        rusqlite::types::Value::Integer(i) => i.to_string(),
        other => format!("{other:?}"),
    })
    .unwrap()
}

#[test]
fn open_aplica_los_tres_pragmas() {
    let (_d, conn) = temp_db();
    assert_eq!(pragma(&conn, "journal_mode").to_lowercase(), "wal");
    assert_eq!(pragma(&conn, "foreign_keys"), "1");
    assert_eq!(pragma(&conn, "temp_store"), "2"); // 2 = MEMORY
}

#[test]
fn migrate_crea_el_esquema_del_indice() {
    let (_d, conn) = temp_db();
    db::migrate(&conn, db::INDEX_MIGRATIONS).unwrap();
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='engagement_ref'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1);
}

#[test]
fn migrate_es_idempotente() {
    let (_d, conn) = temp_db();
    db::migrate(&conn, db::INDEX_MIGRATIONS).unwrap();
    db::migrate(&conn, db::INDEX_MIGRATIONS).unwrap();
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM _migration", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, db::INDEX_MIGRATIONS.len() as i64);
}

#[test]
fn el_estado_de_engagement_ref_esta_restringido() {
    let (_d, conn) = temp_db();
    db::migrate(&conn, db::INDEX_MIGRATIONS).unwrap();
    let r = conn.execute(
        "INSERT INTO engagement_ref (id, codename, created_at, state) VALUES ('x','CLAVEL','2026-01-01T00:00:00Z','inventado')",
        [],
    );
    assert!(r.is_err(), "un estado fuera del CHECK debe rechazarse");
}
```

- [ ] **Step 2: Añadir `tempfile` como dependencia de test**

```bash
cargo add --manifest-path src-tauri/Cargo.toml --dev tempfile
```

- [ ] **Step 3: Ejecutar el test y verificar que falla**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test migrations`
Expected: FAIL — no existe el módulo `db`.

- [ ] **Step 4: Escribir la migración del índice**

`src-tauri/migrations/index/0001_index.sql`:

```sql
-- Registro global. Deliberadamente anémico: nada aquí puede identificar
-- a un cliente. Sin alcance, sin autorizante, sin ruta de exportación.
CREATE TABLE engagement_ref (
  id          TEXT PRIMARY KEY,
  codename    TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  state       TEXT NOT NULL CHECK (state IN
                ('draft','scoped','running','exported','purged')),
  purged_at   TEXT
);

CREATE INDEX idx_engagement_ref_state ON engagement_ref (state);
```

- [ ] **Step 5: Implementar `db.rs`**

```rust
use std::path::Path;

use rusqlite::Connection;

use crate::error::Result;
use crate::paths;

pub const INDEX_MIGRATIONS: &[(&str, &str)] = &[(
    "0001_index",
    include_str!("../migrations/index/0001_index.sql"),
)];

pub const ENGAGEMENT_MIGRATIONS: &[(&str, &str)] = &[];

/// Abre una conexión con los tres pragmas obligatorios.
///
/// `temp_store = MEMORY` no es una optimización: sin él SQLite derrama
/// ficheros temporales en /var/folders, fuera del directorio del
/// engagement y por tanto fuera del alcance de la purga.
pub fn open(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path)?;
    // journal_mode devuelve una fila, así que no sirve pragma_update.
    conn.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    Ok(conn)
}

pub fn open_index(root: &Path) -> Result<Connection> {
    let conn = open(&paths::index_db_path(root))?;
    migrate(&conn, INDEX_MIGRATIONS)?;
    Ok(conn)
}

/// Migraciones versionadas y append-only. Nunca editar una ya lanzada:
/// añadir la siguiente.
pub fn migrate(conn: &Connection, set: &[(&str, &str)]) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS _migration (
           name TEXT PRIMARY KEY,
           applied_at TEXT NOT NULL
         )",
        [],
    )?;
    for (name, sql) in set {
        let ya: i64 = conn.query_row(
            "SELECT COUNT(*) FROM _migration WHERE name = ?1",
            [name],
            |r| r.get(0),
        )?;
        if ya == 0 {
            conn.execute_batch(sql)?;
            conn.execute(
                "INSERT INTO _migration (name, applied_at) VALUES (?1, ?2)",
                rusqlite::params![name, now_iso()],
            )?;
        }
    }
    Ok(())
}

/// Marca de tiempo ISO-8601 en UTC, con precisión de segundo.
pub fn now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    time::OffsetDateTime::from_unix_timestamp(secs as i64)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}
```

```bash
cargo add --manifest-path src-tauri/Cargo.toml time --features formatting
```

- [ ] **Step 6: Declarar el módulo en `lib.rs`**

```rust
pub mod db;
```

- [ ] **Step 7: Ejecutar el test y verificar que pasa**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test migrations`
Expected: PASS, 4 tests.

- [ ] **Step 8: Commit**

```bash
git add src-tauri/src/db.rs src-tauri/migrations src-tauri/src/lib.rs \
        src-tauri/tests/migrations.rs src-tauri/Cargo.toml src-tauri/Cargo.lock
git commit -m "$(cat <<'MSG'
feat: conexión con pragmas, runner de migraciones y esquema de index.db

temp_store=MEMORY evita que SQLite derrame temporales fuera del
directorio del engagement, donde la purga no llegaría.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 4: Esquema de `engagement.db`

**Files:**
- Create: `src-tauri/migrations/engagement/0001_init.sql`
- Modify: `src-tauri/src/db.rs` (rellenar `ENGAGEMENT_MIGRATIONS`)
- Test: `src-tauri/tests/engagement_schema.rs`

**Interfaces:**
- Consumes: `db::open`, `db::migrate`, `db::ENGAGEMENT_MIGRATIONS`.
- Produces: el esquema completo de §5.3 de la spec.

- [ ] **Step 1: Escribir el test que falla**

`src-tauri/tests/engagement_schema.rs`:

```rust
use auscan_lib::db;
use rusqlite::Connection;

fn migrated() -> (tempfile::TempDir, Connection) {
    let dir = tempfile::tempdir().unwrap();
    let conn = db::open(&dir.path().join("engagement.db")).unwrap();
    db::migrate(&conn, db::ENGAGEMENT_MIGRATIONS).unwrap();
    (dir, conn)
}

fn tablas(conn: &Connection) -> Vec<String> {
    let mut st = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap();
    let v = st
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    v
}

#[test]
fn estan_todas_las_tablas() {
    let (_d, conn) = migrated();
    let t = tablas(&conn);
    for esperada in [
        "engagement", "scope_entry", "tool_run", "host", "host_tag",
        "service", "observation",
    ] {
        assert!(t.contains(&esperada.to_string()), "falta la tabla {esperada}");
    }
}

#[test]
fn engagement_admite_exactamente_una_fila() {
    let (_d, conn) = migrated();
    conn.execute(
        "INSERT INTO engagement (id, codename, created_at, state)
         VALUES ('a','CLAVEL','2026-01-01T00:00:00Z','draft')",
        [],
    )
    .unwrap();
    let segunda = conn.execute(
        "INSERT INTO engagement (id, codename, created_at, state)
         VALUES ('b','ROMERO','2026-01-01T00:00:00Z','draft')",
        [],
    );
    assert!(segunda.is_err(), "el CHECK(rowid=1) debe impedir la segunda fila");
}

#[test]
fn observation_no_tiene_columna_de_severidad() {
    let (_d, conn) = migrated();
    let mut st = conn.prepare("PRAGMA table_info(observation)").unwrap();
    let cols: Vec<String> = st
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    for prohibida in ["severity", "severidad", "risk", "riesgo", "score", "cvss"] {
        assert!(
            !cols.iter().any(|c| c.eq_ignore_ascii_case(prohibida)),
            "observation no debe tener columna {prohibida}: la valoración la hace el consultor"
        );
    }
}

#[test]
fn borrar_un_host_arrastra_sus_servicios() {
    let (_d, conn) = migrated();
    conn.execute(
        "INSERT INTO host (id, ip, state) VALUES (1, '198.51.100.5', 'up')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO service (id, host_id, port, proto, state)
         VALUES (1, 1, 443, 'tcp', 'open')",
        [],
    )
    .unwrap();
    conn.execute("DELETE FROM host WHERE id = 1", []).unwrap();
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM service", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0, "foreign_keys=ON debe propagar el borrado");
}

#[test]
fn service_es_unico_por_host_puerto_protocolo() {
    let (_d, conn) = migrated();
    conn.execute("INSERT INTO host (id, ip, state) VALUES (1,'198.51.100.5','up')", []).unwrap();
    conn.execute(
        "INSERT INTO service (host_id, port, proto, state) VALUES (1,443,'tcp','open')",
        [],
    )
    .unwrap();
    let dup = conn.execute(
        "INSERT INTO service (host_id, port, proto, state) VALUES (1,443,'tcp','open')",
        [],
    );
    assert!(dup.is_err());
}
```

- [ ] **Step 2: Ejecutar el test y verificar que falla**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test engagement_schema`
Expected: FAIL — `ENGAGEMENT_MIGRATIONS` está vacío, no existe ninguna tabla.

- [ ] **Step 3: Escribir la migración**

`src-tauri/migrations/engagement/0001_init.sql` — transcripción literal de §5.3 de la spec:

```sql
CREATE TABLE engagement (
  id TEXT PRIMARY KEY,
  codename TEXT NOT NULL,
  authorized_by TEXT,
  authorization_ref TEXT,
  export_dir TEXT,
  created_at TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN
    ('draft','scoped','running','exported','purged')),
  CHECK (rowid = 1)
);

CREATE TABLE scope_entry (
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('allow','deny')),
  family TEXT NOT NULL CHECK (family IN ('v4','v6')),
  cidr TEXT NOT NULL,
  note TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (kind, cidr)
);

CREATE TABLE tool_run (
  id INTEGER PRIMARY KEY,
  seq INTEGER NOT NULL UNIQUE,
  tool TEXT NOT NULL,
  tool_version TEXT NOT NULL,
  tool_path TEXT NOT NULL,
  phase TEXT NOT NULL,
  argv_json TEXT NOT NULL,
  privileged INTEGER NOT NULL CHECK (privileged IN (0,1)),
  targets_json TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  exit_code INTEGER,
  status TEXT NOT NULL CHECK (status IN ('running','ok','failed','cancelled')),
  raw_path TEXT,
  raw_sha256 TEXT,
  stderr_path TEXT
);

CREATE TABLE host (
  id INTEGER PRIMARY KEY,
  ip TEXT NOT NULL UNIQUE,
  hostname TEXT,
  mac TEXT,
  vendor TEXT,
  os_guess TEXT,
  os_accuracy INTEGER,
  state TEXT,
  first_seen_run INTEGER REFERENCES tool_run(id),
  last_seen_run  INTEGER REFERENCES tool_run(id)
);

CREATE TABLE host_tag (
  host_id INTEGER NOT NULL REFERENCES host(id) ON DELETE CASCADE,
  tag TEXT NOT NULL,
  PRIMARY KEY (host_id, tag)
);

CREATE TABLE service (
  id INTEGER PRIMARY KEY,
  host_id INTEGER NOT NULL REFERENCES host(id) ON DELETE CASCADE,
  port INTEGER NOT NULL CHECK (port BETWEEN 0 AND 65535),
  proto TEXT NOT NULL CHECK (proto IN ('tcp','udp','sctp')),
  state TEXT NOT NULL,
  service TEXT,
  product TEXT,
  version TEXT,
  extrainfo TEXT,
  tunnel TEXT,
  cpe TEXT,
  banner TEXT,
  first_seen_run INTEGER REFERENCES tool_run(id),
  last_seen_run  INTEGER REFERENCES tool_run(id),
  UNIQUE (host_id, port, proto)
);

-- Sin columna de severidad, y no por convención: aquí no existe el sitio
-- donde ponerla. La valoración la hace el consultor al redactar.
CREATE TABLE observation (
  id INTEGER PRIMARY KEY,
  tool_run_id INTEGER NOT NULL REFERENCES tool_run(id),
  host_id    INTEGER REFERENCES host(id)    ON DELETE CASCADE,
  service_id INTEGER REFERENCES service(id) ON DELETE CASCADE,
  kind      TEXT NOT NULL,
  subject   TEXT NOT NULL,
  statement TEXT NOT NULL,
  evidence     TEXT,
  evidence_ref TEXT,
  meta_json    TEXT,
  observed_at  TEXT NOT NULL,
  UNIQUE (tool_run_id, kind, subject, statement)
);

CREATE INDEX idx_service_host ON service (host_id);
CREATE INDEX idx_observation_kind ON observation (kind);
CREATE INDEX idx_observation_host ON observation (host_id);
```

- [ ] **Step 4: Registrar la migración en `db.rs`**

```rust
pub const ENGAGEMENT_MIGRATIONS: &[(&str, &str)] = &[(
    "0001_init",
    include_str!("../migrations/engagement/0001_init.sql"),
)];
```

- [ ] **Step 5: Ejecutar el test y verificar que pasa**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test engagement_schema`
Expected: PASS, 5 tests.

- [ ] **Step 6: Commit**

```bash
git add src-tauri/migrations/engagement src-tauri/src/db.rs \
        src-tauri/tests/engagement_schema.rs
git commit -m "$(cat <<'MSG'
feat: esquema de engagement.db

Incluye un test que falla si alguien añade una columna de severidad a
observation: la valoración la hace el consultor, no la app.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 5: Ciclo de vida del engagement — crear, listar, abrir

**Files:**
- Create: `src-tauri/src/engagement.rs`
- Modify: `src-tauri/src/lib.rs`
- Test: `src-tauri/tests/engagement.rs`

**Interfaces:**
- Consumes: `paths::*`, `db::open`, `db::open_index`, `db::migrate`, `db::ENGAGEMENT_MIGRATIONS`, `db::now_iso`.
- Produces:
  - `struct EngagementRef { id: String, codename: String, created_at: String, state: String, purged_at: Option<String> }` — `Serialize`, `Deserialize`, `Clone`, `Debug`, `PartialEq`.
  - `engagement::create(root: &Path, codename: &str) -> Result<EngagementRef>`
  - `engagement::list(root: &Path) -> Result<Vec<EngagementRef>>`
  - `engagement::open(root: &Path, id: &str) -> Result<Connection>`
  - `engagement::get(root: &Path, id: &str) -> Result<EngagementRef>`

- [ ] **Step 1: Escribir el test que falla**

`src-tauri/tests/engagement.rs`:

```rust
use auscan_lib::{engagement, paths};

#[test]
fn create_deja_directorio_base_y_fila_en_el_indice() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let e = engagement::create(root, "CLAVEL").unwrap();

    assert_eq!(e.codename, "CLAVEL");
    assert_eq!(e.state, "draft");
    assert!(e.purged_at.is_none());

    assert!(paths::engagement_dir(root, &e.id).unwrap().is_dir());
    assert!(paths::engagement_db_path(root, &e.id).unwrap().is_file());
    assert!(paths::raw_dir(root, &e.id).unwrap().is_dir());

    let listados = engagement::list(root).unwrap();
    assert_eq!(listados.len(), 1);
    assert_eq!(listados[0].id, e.id);
}

#[test]
fn el_indice_no_guarda_nada_que_identifique_al_cliente() {
    let dir = tempfile::tempdir().unwrap();
    let conn = auscan_lib::db::open_index(dir.path()).unwrap();
    let mut st = conn.prepare("PRAGMA table_info(engagement_ref)").unwrap();
    let cols: Vec<String> = st
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    let mut esperadas = vec!["id", "codename", "created_at", "state", "purged_at"];
    esperadas.sort();
    let mut reales: Vec<&str> = cols.iter().map(String::as_str).collect();
    reales.sort();
    assert_eq!(reales, esperadas,
        "index.db solo puede contener estas columnas: alcance, autorizante y \
         ruta de exportación viven dentro del engagement y mueren con él");
}

#[test]
fn el_engagement_db_trae_su_esquema_migrado() {
    let dir = tempfile::tempdir().unwrap();
    let e = engagement::create(dir.path(), "ROMERO").unwrap();
    let conn = engagement::open(dir.path(), &e.id).unwrap();
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='observation'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1);
}

#[test]
fn engagement_db_tiene_su_propia_fila_de_engagement() {
    let dir = tempfile::tempdir().unwrap();
    let e = engagement::create(dir.path(), "ROMERO").unwrap();
    let conn = engagement::open(dir.path(), &e.id).unwrap();
    let (id, codename): (String, String) = conn
        .query_row("SELECT id, codename FROM engagement", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(id, e.id);
    assert_eq!(codename, "ROMERO");
}

#[test]
fn list_devuelve_del_mas_reciente_al_mas_antiguo() {
    let dir = tempfile::tempdir().unwrap();
    let a = engagement::create(dir.path(), "UNO").unwrap();
    let b = engagement::create(dir.path(), "DOS").unwrap();
    let l = engagement::list(dir.path()).unwrap();
    assert_eq!(l.len(), 2);
    assert!(l.iter().any(|e| e.id == a.id));
    assert!(l.iter().any(|e| e.id == b.id));
}

#[test]
fn open_de_un_id_inexistente_falla() {
    let dir = tempfile::tempdir().unwrap();
    let inexistente = "7f3a4c2e-0b1d-4e5f-8a9b-1c2d3e4f5a6b";
    assert!(engagement::open(dir.path(), inexistente).is_err());
}

#[test]
fn create_rechaza_un_codename_vacio() {
    let dir = tempfile::tempdir().unwrap();
    assert!(engagement::create(dir.path(), "   ").is_err());
}
```

- [ ] **Step 2: Ejecutar el test y verificar que falla**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test engagement`
Expected: FAIL — no existe el módulo `engagement`.

- [ ] **Step 3: Implementar `engagement.rs`**

```rust
use std::path::Path;

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db;
use crate::error::{AppError, Result};
use crate::paths;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngagementRef {
    pub id: String,
    pub codename: String,
    pub created_at: String,
    pub state: String,
    pub purged_at: Option<String>,
}

pub fn create(root: &Path, codename: &str) -> Result<EngagementRef> {
    let codename = codename.trim();
    if codename.is_empty() {
        return Err(AppError::InvalidEngagementId(
            "el nombre en clave no puede estar vacío".to_string(),
        ));
    }

    let id = Uuid::new_v4().to_string();
    let created_at = db::now_iso();

    // Primero el directorio y su base: si algo falla, el índice no
    // acaba apuntando a un engagement que no existe en disco.
    std::fs::create_dir_all(paths::raw_dir(root, &id)?)?;
    let conn = db::open(&paths::engagement_db_path(root, &id)?)?;
    db::migrate(&conn, db::ENGAGEMENT_MIGRATIONS)?;
    conn.execute(
        "INSERT INTO engagement (id, codename, created_at, state)
         VALUES (?1, ?2, ?3, 'draft')",
        rusqlite::params![id, codename, created_at],
    )?;
    drop(conn);

    let index = db::open_index(root)?;
    index.execute(
        "INSERT INTO engagement_ref (id, codename, created_at, state)
         VALUES (?1, ?2, ?3, 'draft')",
        rusqlite::params![id, codename, created_at],
    )?;

    Ok(EngagementRef {
        id,
        codename: codename.to_string(),
        created_at,
        state: "draft".to_string(),
        purged_at: None,
    })
}

pub fn list(root: &Path) -> Result<Vec<EngagementRef>> {
    let index = db::open_index(root)?;
    let mut st = index.prepare(
        "SELECT id, codename, created_at, state, purged_at
         FROM engagement_ref ORDER BY created_at DESC, id DESC",
    )?;
    let filas = st.query_map([], |r| {
        Ok(EngagementRef {
            id: r.get(0)?,
            codename: r.get(1)?,
            created_at: r.get(2)?,
            state: r.get(3)?,
            purged_at: r.get(4)?,
        })
    })?;
    Ok(filas.collect::<std::result::Result<Vec<_>, _>>()?)
}

pub fn get(root: &Path, id: &str) -> Result<EngagementRef> {
    list(root)?
        .into_iter()
        .find(|e| e.id == id)
        .ok_or_else(|| AppError::EngagementNotFound(id.to_string()))
}

/// Abre la base de un engagement existente. No la crea: si el fichero no
/// está, es que el engagement no existe o ya se purgó.
pub fn open(root: &Path, id: &str) -> Result<Connection> {
    let ruta = paths::engagement_db_path(root, id)?;
    if !ruta.is_file() {
        return Err(AppError::EngagementNotFound(id.to_string()));
    }
    let conn = db::open(&ruta)?;
    db::migrate(&conn, db::ENGAGEMENT_MIGRATIONS)?;
    Ok(conn)
}
```

- [ ] **Step 4: Declarar el módulo en `lib.rs`**

```rust
pub mod engagement;
```

- [ ] **Step 5: Ejecutar el test y verificar que pasa**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test engagement`
Expected: PASS, 7 tests.

- [ ] **Step 6: Commit**

```bash
git add src-tauri/src/engagement.rs src-tauri/src/lib.rs src-tauri/tests/engagement.rs
git commit -m "$(cat <<'MSG'
feat: ciclo de vida del engagement (crear, listar, abrir)

Un test fija las columnas de engagement_ref: el índice global no puede
crecer con datos que identifiquen al cliente.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 6: Purga verificable y lápida

**Files:**
- Modify: `src-tauri/src/engagement.rs`
- Test: `src-tauri/tests/purge.rs`

**Interfaces:**
- Consumes: todo lo de la Tarea 5.
- Produces: `engagement::purge(root: &Path, id: &str) -> Result<EngagementRef>` — devuelve la lápida resultante.

**Por qué la fila no se borra:** poder demostrar *cuándo* se purgó vale más que la coartada de no tener ni el registro. Sobreviven `id`, `codename`, `created_at`, `purged_at` y `state='purged'`; nada más.

- [ ] **Step 1: Escribir el test que falla**

`src-tauri/tests/purge.rs`:

```rust
use auscan_lib::{db, engagement, paths};

#[test]
fn purge_borra_el_directorio_entero() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let e = engagement::create(root, "CLAVEL").unwrap();

    // Simular trabajo hecho: un fichero en raw/ y datos en la base.
    let raw = paths::raw_dir(root, &e.id).unwrap();
    std::fs::write(raw.join("0001-nmap-sn.xml"), b"<nmaprun/>").unwrap();
    {
        let conn = engagement::open(root, &e.id).unwrap();
        conn.execute(
            "INSERT INTO host (ip, state) VALUES ('198.51.100.5','up')",
            [],
        )
        .unwrap();
    }

    let ruta = paths::engagement_dir(root, &e.id).unwrap();
    assert!(ruta.exists());

    engagement::purge(root, &e.id).unwrap();

    assert!(!ruta.exists(), "el directorio del engagement debe desaparecer");
}

#[test]
fn purge_no_deja_ficheros_wal_ni_shm() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let e = engagement::create(root, "CLAVEL").unwrap();
    {
        let conn = engagement::open(root, &e.id).unwrap();
        conn.execute("INSERT INTO host (ip, state) VALUES ('198.51.100.9','up')", [])
            .unwrap();
    }
    engagement::purge(root, &e.id).unwrap();

    let restos: Vec<_> = walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|x| x.ok())
        .map(|x| x.path().display().to_string())
        .filter(|p| p.contains(&e.id))
        .collect();
    assert!(restos.is_empty(), "quedan restos: {restos:?}");
}

#[test]
fn purge_deja_lapida_en_el_indice() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let e = engagement::create(root, "CLAVEL").unwrap();

    let lapida = engagement::purge(root, &e.id).unwrap();

    assert_eq!(lapida.id, e.id);
    assert_eq!(lapida.codename, "CLAVEL");
    assert_eq!(lapida.state, "purged");
    assert!(lapida.purged_at.is_some(), "debe registrarse cuándo se purgó");

    // Y sigue apareciendo al listar: la lápida es visible a propósito.
    let l = engagement::list(root).unwrap();
    assert_eq!(l.len(), 1);
    assert_eq!(l[0].state, "purged");
}

#[test]
fn purge_es_idempotente() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let e = engagement::create(root, "CLAVEL").unwrap();
    engagement::purge(root, &e.id).unwrap();
    let segunda = engagement::purge(root, &e.id).unwrap();
    assert_eq!(segunda.state, "purged");
}

#[test]
fn purge_no_toca_a_los_demas_engagements() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let a = engagement::create(root, "UNO").unwrap();
    let b = engagement::create(root, "DOS").unwrap();

    engagement::purge(root, &a.id).unwrap();

    assert!(!paths::engagement_dir(root, &a.id).unwrap().exists());
    assert!(paths::engagement_dir(root, &b.id).unwrap().is_dir());
    assert!(engagement::open(root, &b.id).is_ok());
}

#[test]
fn purge_de_un_id_invalido_falla_sin_borrar_nada() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let e = engagement::create(root, "CLAVEL").unwrap();

    assert!(engagement::purge(root, "../..").is_err());
    assert!(engagement::purge(root, "no-soy-un-uuid").is_err());

    assert!(paths::engagement_dir(root, &e.id).unwrap().is_dir());
    let _ = db::open_index(root).unwrap();
}
```

- [ ] **Step 2: Añadir `walkdir` como dependencia de test**

```bash
cargo add --manifest-path src-tauri/Cargo.toml --dev walkdir
```

- [ ] **Step 3: Ejecutar el test y verificar que falla**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test purge`
Expected: FAIL — no existe `engagement::purge`.

- [ ] **Step 4: Implementar `purge`**

Añadir a `src-tauri/src/engagement.rs`:

```rust
/// Borra todo rastro local del engagement y deja una lápida en el índice.
///
/// La carpeta de exportación NO se toca: es el entregable y vive fuera
/// del control de la app. La UI debe decirlo explícitamente.
pub fn purge(root: &Path, id: &str) -> Result<EngagementRef> {
    // engagement_dir valida el identificador: nada que no sea un UUID
    // llega a un remove_dir_all.
    let ruta = paths::engagement_dir(root, id)?;

    if ruta.exists() {
        std::fs::remove_dir_all(&ruta)?;
    }

    // Verificar, no confiar.
    if ruta.exists() {
        return Err(AppError::PurgeIncomplete(ruta.display().to_string()));
    }

    let purged_at = db::now_iso();
    let index = db::open_index(root)?;
    let filas = index.execute(
        "UPDATE engagement_ref
            SET state = 'purged', purged_at = COALESCE(purged_at, ?2)
          WHERE id = ?1",
        rusqlite::params![id, purged_at],
    )?;
    if filas == 0 {
        return Err(AppError::EngagementNotFound(id.to_string()));
    }

    get(root, id)
}
```

- [ ] **Step 5: Ejecutar el test y verificar que pasa**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test purge`
Expected: PASS, 6 tests.

- [ ] **Step 6: Ejecutar la suite completa**

Run: `npm run check`
Expected: PASS en las cuatro etapas.

- [ ] **Step 7: Commit**

```bash
git add src-tauri/src/engagement.rs src-tauri/tests/purge.rs \
        src-tauri/Cargo.toml src-tauri/Cargo.lock
git commit -m "$(cat <<'MSG'
feat: purga verificable con lápida en el índice

Borra el directorio, comprueba que ya no existe y registra cuándo se
purgó. La carpeta de exportación no se toca: es el entregable.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 7: Alcance — parseo y canonicalización de entradas

**Files:**
- Create: `src-tauri/src/scope.rs`
- Modify: `src-tauri/src/lib.rs`
- Test: `src-tauri/tests/scope_entries.rs`

**Interfaces:**
- Consumes: `error::{AppError, Result}`.
- Produces:
  - `enum ScopeKind { Allow, Deny }` — `Serialize`/`Deserialize` en minúsculas.
  - `scope::canonical_ip(ip: IpAddr) -> IpAddr`
  - `scope::parse_entry(s: &str) -> Result<IpNet>`
  - `scope::family_of(net: &IpNet) -> &'static str` — devuelve `"v4"` o `"v6"` para la columna `family`.

**Por qué se rechaza `198.51.100.5/24`:** es ambiguo. ¿Autoriza el host o la red entera? Aceptarlo en silencio y quedarse con la red sería autorizar 254 direcciones que el consultor no escribió. Se exige `198.51.100.0/24` o `198.51.100.5/32`.

- [ ] **Step 1: Añadir la dependencia**

```bash
cargo add --manifest-path src-tauri/Cargo.toml ipnet --features serde
```

- [ ] **Step 2: Escribir el test que falla**

`src-tauri/tests/scope_entries.rs`:

```rust
use auscan_lib::scope;
use std::net::IpAddr;

#[test]
fn acepta_redes_canonicas() {
    for s in ["198.51.100.0/24", "192.0.2.0/25", "2001:db8::/32", "203.0.113.7"] {
        assert!(scope::parse_entry(s).is_ok(), "debería aceptar {s}");
    }
}

#[test]
fn rechaza_cidr_con_bits_de_host() {
    for s in ["198.51.100.5/24", "192.0.2.130/25", "2001:db8::1/32"] {
        let e = scope::parse_entry(s).unwrap_err();
        assert!(
            matches!(e, auscan_lib::error::AppError::AmbiguousCidr(_)),
            "{s} debería ser ambiguo, fue {e:?}"
        );
    }
}

#[test]
fn rechaza_basura() {
    for s in ["", "   ", "no-soy-una-red", "198.51.100.0/33", "999.1.1.1"] {
        assert!(scope::parse_entry(s).is_err(), "debería rechazar {s:?}");
    }
}

#[test]
fn una_ip_suelta_se_convierte_en_prefijo_completo() {
    let n = scope::parse_entry("203.0.113.7").unwrap();
    assert_eq!(n.prefix_len(), 32);
    let n6 = scope::parse_entry("2001:db8::1").unwrap();
    assert_eq!(n6.prefix_len(), 128);
}

#[test]
fn las_v4_mapeadas_se_canonicalizan_a_v4() {
    let mapeada: IpAddr = "::ffff:198.51.100.5".parse().unwrap();
    assert_eq!(
        scope::canonical_ip(mapeada),
        "198.51.100.5".parse::<IpAddr>().unwrap()
    );
}

#[test]
fn family_of_distingue_las_dos_familias() {
    assert_eq!(scope::family_of(&scope::parse_entry("198.51.100.0/24").unwrap()), "v4");
    assert_eq!(scope::family_of(&scope::parse_entry("2001:db8::/32").unwrap()), "v6");
}
```

- [ ] **Step 3: Ejecutar el test y verificar que falla**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test scope_entries`
Expected: FAIL — no existe el módulo `scope`.

- [ ] **Step 4: Implementar la mitad de parseo de `scope.rs`**

```rust
//! Autoridad única del alcance.
//!
//! Este módulo es el ÚNICO sitio del programa capaz de construir un
//! `ScopedTarget`. Cualquier ruta de ejecución que quiera tocar un
//! objetivo tiene que pedirle uno aquí, y aquí se le dice que no.

use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScopeKind {
    Allow,
    Deny,
}

impl ScopeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScopeKind::Allow => "allow",
            ScopeKind::Deny => "deny",
        }
    }
}

/// Normaliza `::ffff:a.b.c.d` a su v4 equivalente, para que el veredicto
/// no dependa de en qué forma llegó escrita la dirección.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Parsea una entrada de alcance a su forma canónica.
///
/// Rechaza CIDR con bits de host puestos: `198.51.100.5/24` no dice si
/// se autoriza el host o los 254 vecinos, y adivinarlo sería peor que
/// pedir que se escriba bien.
pub fn parse_entry(s: &str) -> Result<IpNet> {
    let s = s.trim();
    if s.is_empty() {
        return Err(AppError::InvalidAddress(s.to_string()));
    }

    if s.contains('/') {
        let net: IpNet = s
            .parse()
            .map_err(|_| AppError::InvalidAddress(s.to_string()))?;
        if net.addr() != net.network() {
            return Err(AppError::AmbiguousCidr(s.to_string()));
        }
        Ok(net)
    } else {
        let ip = canonical_ip(
            s.parse::<IpAddr>()
                .map_err(|_| AppError::InvalidAddress(s.to_string()))?,
        );
        Ok(match ip {
            IpAddr::V4(a) => IpNet::V4(
                Ipv4Net::new(a, 32).map_err(|_| AppError::InvalidAddress(s.to_string()))?,
            ),
            IpAddr::V6(a) => IpNet::V6(
                Ipv6Net::new(a, 128).map_err(|_| AppError::InvalidAddress(s.to_string()))?,
            ),
        })
    }
}

pub fn family_of(net: &IpNet) -> &'static str {
    match net {
        IpNet::V4(_) => "v4",
        IpNet::V6(_) => "v6",
    }
}
```

- [ ] **Step 5: Declarar el módulo en `lib.rs`**

```rust
pub mod scope;
```

- [ ] **Step 6: Ejecutar el test y verificar que pasa**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test scope_entries`
Expected: PASS, 6 tests.

- [ ] **Step 7: Commit**

```bash
git add src-tauri/src/scope.rs src-tauri/src/lib.rs src-tauri/tests/scope_entries.rs \
        src-tauri/Cargo.toml src-tauri/Cargo.lock
git commit -m "$(cat <<'MSG'
feat: parseo y canonicalización de entradas de alcance

Un CIDR con bits de host se rechaza en vez de adivinarse: 198.51.100.5/24
no dice si se autoriza el host o los 254 vecinos.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 8: El guard — `Scope::validate` y `ScopedTarget`

**Files:**
- Modify: `src-tauri/src/scope.rs`
- Test: `src-tauri/tests/scope_guard.rs`

**Interfaces:**
- Consumes: `scope::{parse_entry, canonical_ip, ScopeKind}` (Tarea 7).
- Produces:
  - `struct ScopedTarget` — campo privado, con `ip(&self) -> IpAddr` y `Display`.
  - `struct Scope` con `Scope::from_entries(&[(ScopeKind, String)]) -> Result<Scope>`, `Scope::new(allow: Vec<IpNet>, deny: Vec<IpNet>) -> Scope`, `Scope::is_empty(&self) -> bool`, `Scope::validate_ip(&self, IpAddr) -> Result<ScopedTarget>`, `Scope::validate(&self, &str) -> Result<ScopedTarget>`.

- [ ] **Step 1: Escribir el test que falla**

`src-tauri/tests/scope_guard.rs`:

```rust
use auscan_lib::error::AppError;
use auscan_lib::scope::{Scope, ScopeKind};

fn scope(allow: &[&str], deny: &[&str]) -> Scope {
    let mut e: Vec<(ScopeKind, String)> = Vec::new();
    for a in allow {
        e.push((ScopeKind::Allow, (*a).to_string()));
    }
    for d in deny {
        e.push((ScopeKind::Deny, (*d).to_string()));
    }
    Scope::from_entries(&e).unwrap()
}

#[test]
fn los_limites_del_cidr_caen_del_lado_correcto() {
    let s = scope(&["198.51.100.0/24"], &[]);
    assert!(s.validate("198.51.100.0").is_ok(), "la dirección de red está dentro");
    assert!(s.validate("198.51.100.255").is_ok(), "el broadcast está dentro");
    assert!(s.validate("198.51.99.255").is_err(), "la anterior está fuera");
    assert!(s.validate("198.51.101.0").is_err(), "la siguiente está fuera");
}

#[test]
fn deny_gana_sobre_allow_aunque_sea_menos_especifico() {
    let s = scope(&["198.51.100.0/25"], &["198.51.100.0/24"]);
    assert!(
        matches!(s.validate("198.51.100.5"), Err(AppError::OutOfScope(_))),
        "deny gana siempre, sin importar la especificidad"
    );
}

#[test]
fn deny_anidado_dentro_de_allow_recorta_el_alcance() {
    let s = scope(&["198.51.100.0/24"], &["198.51.100.128/25"]);
    assert!(s.validate("198.51.100.127").is_ok());
    assert!(s.validate("198.51.100.128").is_err());
    assert!(s.validate("198.51.100.200").is_err());
}

#[test]
fn un_alcance_sin_allow_rechaza_todo() {
    let vacio = scope(&[], &[]);
    assert!(matches!(vacio.validate("198.51.100.5"), Err(AppError::EmptyScope)));

    // Aunque haya exclusiones: sin autorización explícita no hay nada autorizado.
    let solo_deny = scope(&[], &["198.51.100.0/24"]);
    assert!(matches!(
        solo_deny.validate("203.0.113.9"),
        Err(AppError::EmptyScope)
    ));
}

#[test]
fn ipv6_funciona_igual_en_forma_comprimida_y_expandida() {
    let s = scope(&["2001:db8::/32"], &["2001:db8:dead::/48"]);
    assert!(s.validate("2001:db8::1").is_ok());
    assert!(s.validate("2001:0db8:0000:0000:0000:0000:0000:0001").is_ok());
    assert!(s.validate("2001:db8:dead:beef::1").is_err());
    assert!(s.validate("2001:db9::1").is_err());
}

#[test]
fn una_v4_mapeada_se_juzga_contra_el_alcance_v4() {
    let s = scope(&["192.0.2.0/24"], &[]);
    assert!(
        s.validate("::ffff:192.0.2.65").is_ok(),
        "escrita como v6 mapeada sigue siendo la misma dirección"
    );
    assert!(s.validate("::ffff:203.0.113.1").is_err());
}

#[test]
fn un_alcance_v4_no_autoriza_direcciones_v6() {
    let s = scope(&["192.0.2.0/24"], &[]);
    assert!(s.validate("2001:db8::1").is_err());
}

#[test]
fn lo_que_no_es_una_direccion_se_rechaza_como_invalido() {
    let s = scope(&["198.51.100.0/24"], &[]);
    for basura in ["", "  ", "no-soy-una-ip", "198.51.100.5/24", "198.51.100"] {
        assert!(
            matches!(s.validate(basura), Err(AppError::InvalidAddress(_))),
            "{basura:?} debería ser inválido"
        );
    }
}

#[test]
fn el_objetivo_validado_conserva_la_direccion_canonica() {
    let s = scope(&["192.0.2.0/24"], &[]);
    let t = s.validate("::ffff:192.0.2.65").unwrap();
    assert_eq!(t.to_string(), "192.0.2.65", "se pasa a la herramienta ya canónica");
}
```

- [ ] **Step 2: Ejecutar el test y verificar que falla**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test scope_guard`
Expected: FAIL — no existen `Scope` ni `ScopedTarget`.

- [ ] **Step 3: Implementar el guard**

Añadir a `src-tauri/src/scope.rs`:

```rust
/// Un objetivo que YA pasó por el guard.
///
/// El campo es privado y no hay constructor público: fuera de este
/// módulo es imposible fabricar uno. Cualquier función que reciba un
/// `ScopedTarget` sabe, por el tipo, que la dirección está autorizada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopedTarget(IpAddr);

impl ScopedTarget {
    pub fn ip(&self) -> IpAddr {
        self.0
    }
}

impl std::fmt::Display for ScopedTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Scope {
    allow: Vec<IpNet>,
    deny: Vec<IpNet>,
}

impl Scope {
    pub fn new(allow: Vec<IpNet>, deny: Vec<IpNet>) -> Self {
        Self { allow, deny }
    }

    pub fn from_entries(entries: &[(ScopeKind, String)]) -> Result<Self> {
        let mut allow = Vec::new();
        let mut deny = Vec::new();
        for (kind, raw) in entries {
            let net = parse_entry(raw)?;
            match kind {
                ScopeKind::Allow => allow.push(net),
                ScopeKind::Deny => deny.push(net),
            }
        }
        Ok(Self { allow, deny })
    }

    /// Sin ninguna entrada `allow` el alcance está vacío. El estado por
    /// defecto es "nada autorizado", nunca "todo autorizado".
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty()
    }

    pub fn allow(&self) -> &[IpNet] {
        &self.allow
    }

    pub fn deny(&self) -> &[IpNet] {
        &self.deny
    }

    /// El guard. Único constructor de `ScopedTarget` del programa.
    ///
    /// Orden deliberado: alcance vacío, luego exclusiones, luego
    /// autorizaciones. `deny` gana siempre, sin importar la especificidad.
    pub fn validate_ip(&self, ip: IpAddr) -> Result<ScopedTarget> {
        let ip = canonical_ip(ip);

        if self.allow.is_empty() {
            return Err(AppError::EmptyScope);
        }
        if self.deny.iter().any(|n| n.contains(&ip)) {
            return Err(AppError::OutOfScope(ip.to_string()));
        }
        if self.allow.iter().any(|n| n.contains(&ip)) {
            return Ok(ScopedTarget(ip));
        }
        Err(AppError::OutOfScope(ip.to_string()))
    }

    pub fn validate(&self, target: &str) -> Result<ScopedTarget> {
        let t = target.trim();
        let ip: IpAddr = t
            .parse()
            .map_err(|_| AppError::InvalidAddress(target.to_string()))?;
        self.validate_ip(ip)
    }
}
```

**Si el compilador se queja de `contains`:** el método vive en el trait `ipnet::Contains`; añadir `use ipnet::Contains;` a los imports del módulo.

- [ ] **Step 4: Ejecutar el test y verificar que pasa**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test scope_guard`
Expected: PASS, 9 tests.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/scope.rs src-tauri/tests/scope_guard.rs
git commit -m "$(cat <<'MSG'
feat: guard de alcance con ScopedTarget infabricable

El campo de ScopedTarget es privado y no hay constructor público: fuera
de scope.rs es imposible fabricar uno. Deny gana sobre allow y un
alcance sin entradas allow rechaza todo.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 9: Resolución de nombres con resolver inyectable

**Files:**
- Modify: `src-tauri/src/scope.rs`
- Test: `src-tauri/tests/scope_resolve.rs`

**Interfaces:**
- Consumes: `Scope::validate_ip` (Tarea 8).
- Produces:
  - `trait Resolver { fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>>; }` — `Send + Sync`.
  - `struct SystemResolver` que lo implementa vía `ToSocketAddrs`.
  - `Scope::validate_target(&self, target: &str, r: &dyn Resolver) -> Result<Vec<ScopedTarget>>`.

**Por qué el resolver se inyecta:** para que los tests no hagan DNS de verdad. Un test que depende de la red es un test que falla en un avión y miente en CI.

**Por qué todo o nada:** un nombre que resuelve a dos direcciones, una dentro y otra fuera, es exactamente el caso que no se puede resolver "a medias". Se rechaza entero.

- [ ] **Step 1: Escribir el test que falla**

`src-tauri/tests/scope_resolve.rs`:

```rust
use std::collections::HashMap;
use std::net::IpAddr;

use auscan_lib::error::AppError;
use auscan_lib::scope::{Resolver, Scope, ScopeKind};

struct FakeResolver(HashMap<String, Vec<IpAddr>>);

impl FakeResolver {
    fn con(pares: &[(&str, &[&str])]) -> Self {
        let mut m = HashMap::new();
        for (host, ips) in pares {
            m.insert(
                (*host).to_string(),
                ips.iter().map(|s| s.parse().unwrap()).collect(),
            );
        }
        Self(m)
    }
}

impl Resolver for FakeResolver {
    fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        self.0.get(host).cloned().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "sin registro")
        })
    }
}

fn scope(allow: &[&str], deny: &[&str]) -> Scope {
    let mut e: Vec<(ScopeKind, String)> = Vec::new();
    for a in allow {
        e.push((ScopeKind::Allow, (*a).to_string()));
    }
    for d in deny {
        e.push((ScopeKind::Deny, (*d).to_string()));
    }
    Scope::from_entries(&e).unwrap()
}

#[test]
fn una_ip_literal_no_pasa_por_el_resolver() {
    let s = scope(&["198.51.100.0/24"], &[]);
    let r = FakeResolver::con(&[]);
    let t = s.validate_target("198.51.100.5", &r).unwrap();
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].to_string(), "198.51.100.5");
}

#[test]
fn un_nombre_dentro_de_alcance_se_acepta() {
    let s = scope(&["198.51.100.0/24"], &[]);
    let r = FakeResolver::con(&[("srv.example", &["198.51.100.5"])]);
    let t = s.validate_target("srv.example", &r).unwrap();
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].to_string(), "198.51.100.5");
}

#[test]
fn un_nombre_con_varias_ips_todas_dentro_devuelve_todas() {
    let s = scope(&["198.51.100.0/24"], &[]);
    let r = FakeResolver::con(&[("multi.example", &["198.51.100.5", "198.51.100.6"])]);
    let t = s.validate_target("multi.example", &r).unwrap();
    assert_eq!(t.len(), 2);
}

#[test]
fn si_una_sola_ip_cae_fuera_se_rechaza_el_nombre_entero() {
    let s = scope(&["198.51.100.0/24"], &[]);
    let r = FakeResolver::con(&[("mixto.example", &["198.51.100.5", "203.0.113.9"])]);
    assert!(
        matches!(s.validate_target("mixto.example", &r), Err(AppError::OutOfScope(_))),
        "dentro y fuera a la vez no se resuelve a medias: se rechaza"
    );
}

#[test]
fn un_nombre_que_no_resuelve_falla_con_su_propio_error() {
    let s = scope(&["198.51.100.0/24"], &[]);
    let r = FakeResolver::con(&[]);
    assert!(matches!(
        s.validate_target("fantasma.example", &r),
        Err(AppError::UnresolvableHost(_))
    ));
}

#[test]
fn un_nombre_que_resuelve_a_nada_tambien_falla() {
    let s = scope(&["198.51.100.0/24"], &[]);
    let r = FakeResolver::con(&[("vacio.example", &[])]);
    assert!(matches!(
        s.validate_target("vacio.example", &r),
        Err(AppError::UnresolvableHost(_))
    ));
}
```

- [ ] **Step 2: Ejecutar el test y verificar que falla**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test scope_resolve`
Expected: FAIL — no existen `Resolver` ni `validate_target`.

- [ ] **Step 3: Implementar**

Añadir a `src-tauri/src/scope.rs`:

```rust
/// Resolución de nombres, inyectable para que los tests no toquen la red.
pub trait Resolver: Send + Sync {
    fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>>;
}

pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        use std::net::ToSocketAddrs;
        Ok((host, 0u16).to_socket_addrs()?.map(|sa| sa.ip()).collect())
    }
}

impl Scope {
    /// Resuelve el objetivo y exige que TODAS sus direcciones estén en
    /// alcance.
    ///
    /// A las herramientas se les pasan las IPs que salen de aquí, nunca
    /// el nombre: así ninguna puede volver a resolver por su cuenta y
    /// acabar tocando algo que el guard nunca llegó a ver.
    pub fn validate_target(&self, target: &str, r: &dyn Resolver) -> Result<Vec<ScopedTarget>> {
        let t = target.trim();
        if t.is_empty() {
            return Err(AppError::InvalidAddress(target.to_string()));
        }

        if let Ok(ip) = t.parse::<IpAddr>() {
            return Ok(vec![self.validate_ip(ip)?]);
        }

        let ips = r
            .resolve(t)
            .map_err(|_| AppError::UnresolvableHost(t.to_string()))?;
        if ips.is_empty() {
            return Err(AppError::UnresolvableHost(t.to_string()));
        }

        // collect sobre Result corta en el primer error: todo o nada.
        ips.into_iter().map(|ip| self.validate_ip(ip)).collect()
    }
}
```

- [ ] **Step 4: Ejecutar el test y verificar que pasa**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test scope_resolve`
Expected: PASS, 6 tests.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/scope.rs src-tauri/tests/scope_resolve.rs
git commit -m "$(cat <<'MSG'
feat: resolución de nombres en el guard, todo o nada

Un nombre que resuelve dentro y fuera a la vez se rechaza entero. El
resolver se inyecta para que los tests no dependan de la red.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 10: Persistencia del alcance, estado compartido y comandos Tauri

**Files:**
- Create: `src-tauri/src/state.rs`
- Modify: `src-tauri/src/scope.rs`, `src-tauri/src/lib.rs`
- Test: `src-tauri/tests/scope_store.rs`

**Interfaces:**
- Consumes: todo lo anterior.
- Produces:
  - `struct ScopeEntry { id: i64, kind: ScopeKind, family: String, cidr: String, note: Option<String>, created_at: String }` — `Serialize`.
  - `scope::add_entry(conn: &Connection, kind: ScopeKind, raw: &str, note: Option<&str>) -> Result<ScopeEntry>`
  - `scope::remove_entry(conn: &Connection, id: i64) -> Result<()>`
  - `scope::list_entries(conn: &Connection) -> Result<Vec<ScopeEntry>>`
  - `scope::load(conn: &Connection) -> Result<Scope>`
  - `state::AppState { root: PathBuf, open: Mutex<Option<OpenEngagement>> }`
  - Comandos: `engagement_create`, `engagement_list`, `engagement_open`, `engagement_purge`, `scope_list`, `scope_add`, `scope_remove`, `scope_check`.

- [ ] **Step 1: Escribir el test que falla**

`src-tauri/tests/scope_store.rs`:

```rust
use auscan_lib::scope::{self, ScopeKind};
use auscan_lib::{db, engagement};

fn engagement_abierto() -> (tempfile::TempDir, rusqlite::Connection) {
    let dir = tempfile::tempdir().unwrap();
    let e = engagement::create(dir.path(), "CLAVEL").unwrap();
    let conn = engagement::open(dir.path(), &e.id).unwrap();
    (dir, conn)
}

#[test]
fn add_entry_guarda_la_forma_canonica_y_la_familia() {
    let (_d, conn) = engagement_abierto();
    let e = scope::add_entry(&conn, ScopeKind::Allow, " 198.51.100.0/24 ", None).unwrap();
    assert_eq!(e.cidr, "198.51.100.0/24", "se guarda ya normalizada y sin espacios");
    assert_eq!(e.family, "v4");
    assert_eq!(e.kind, ScopeKind::Allow);

    let v6 = scope::add_entry(&conn, ScopeKind::Deny, "2001:db8::/32", Some("laboratorio")).unwrap();
    assert_eq!(v6.family, "v6");
    assert_eq!(v6.note.as_deref(), Some("laboratorio"));
}

#[test]
fn add_entry_rechaza_lo_que_el_parser_rechaza() {
    let (_d, conn) = engagement_abierto();
    assert!(scope::add_entry(&conn, ScopeKind::Allow, "198.51.100.5/24", None).is_err());
    assert!(scope::add_entry(&conn, ScopeKind::Allow, "basura", None).is_err());
    assert_eq!(scope::list_entries(&conn).unwrap().len(), 0, "nada se guardó");
}

#[test]
fn load_reconstruye_un_scope_que_decide_igual() {
    let (_d, conn) = engagement_abierto();
    scope::add_entry(&conn, ScopeKind::Allow, "198.51.100.0/24", None).unwrap();
    scope::add_entry(&conn, ScopeKind::Deny, "198.51.100.128/25", None).unwrap();

    let s = scope::load(&conn).unwrap();
    assert!(s.validate("198.51.100.10").is_ok());
    assert!(s.validate("198.51.100.200").is_err());
}

#[test]
fn load_de_una_base_sin_entradas_da_un_scope_vacio() {
    let (_d, conn) = engagement_abierto();
    let s = scope::load(&conn).unwrap();
    assert!(s.is_empty());
    assert!(s.validate("198.51.100.10").is_err());
}

#[test]
fn remove_entry_reduce_el_alcance() {
    let (_d, conn) = engagement_abierto();
    let a = scope::add_entry(&conn, ScopeKind::Allow, "198.51.100.0/24", None).unwrap();
    assert!(scope::load(&conn).unwrap().validate("198.51.100.10").is_ok());

    scope::remove_entry(&conn, a.id).unwrap();
    assert!(scope::load(&conn).unwrap().validate("198.51.100.10").is_err());
}

#[test]
fn no_se_puede_duplicar_una_entrada() {
    let (_d, conn) = engagement_abierto();
    scope::add_entry(&conn, ScopeKind::Allow, "198.51.100.0/24", None).unwrap();
    assert!(scope::add_entry(&conn, ScopeKind::Allow, "198.51.100.0/24", None).is_err());
}
```

- [ ] **Step 2: Ejecutar el test y verificar que falla**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test scope_store`
Expected: FAIL — no existe `scope::add_entry`.

- [ ] **Step 3: Implementar la persistencia en `scope.rs`**

```rust
use rusqlite::Connection;

use crate::db;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeEntry {
    pub id: i64,
    pub kind: ScopeKind,
    pub family: String,
    pub cidr: String,
    pub note: Option<String>,
    pub created_at: String,
}

pub fn add_entry(
    conn: &Connection,
    kind: ScopeKind,
    raw: &str,
    note: Option<&str>,
) -> Result<ScopeEntry> {
    // Se valida ANTES de tocar la base: una entrada que no parsea no
    // llega nunca a persistirse.
    let net = parse_entry(raw)?;
    let cidr = net.to_string();
    let family = family_of(&net).to_string();
    let created_at = db::now_iso();

    conn.execute(
        "INSERT INTO scope_entry (kind, family, cidr, note, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![kind.as_str(), family, cidr, note, created_at],
    )?;

    Ok(ScopeEntry {
        id: conn.last_insert_rowid(),
        kind,
        family,
        cidr,
        note: note.map(str::to_string),
        created_at,
    })
}

pub fn remove_entry(conn: &Connection, id: i64) -> Result<()> {
    conn.execute("DELETE FROM scope_entry WHERE id = ?1", [id])?;
    Ok(())
}

pub fn list_entries(conn: &Connection) -> Result<Vec<ScopeEntry>> {
    let mut st = conn.prepare(
        "SELECT id, kind, family, cidr, note, created_at
         FROM scope_entry ORDER BY kind, cidr",
    )?;
    let filas = st.query_map([], |r| {
        let kind: String = r.get(1)?;
        Ok(ScopeEntry {
            id: r.get(0)?,
            kind: if kind == "deny" { ScopeKind::Deny } else { ScopeKind::Allow },
            family: r.get(2)?,
            cidr: r.get(3)?,
            note: r.get(4)?,
            created_at: r.get(5)?,
        })
    })?;
    Ok(filas.collect::<std::result::Result<Vec<_>, _>>()?)
}

/// Reconstruye el `Scope` a partir de lo persistido.
pub fn load(conn: &Connection) -> Result<Scope> {
    let entradas: Vec<(ScopeKind, String)> = list_entries(conn)?
        .into_iter()
        .map(|e| (e.kind, e.cidr))
        .collect();
    Scope::from_entries(&entradas)
}
```

- [ ] **Step 4: Ejecutar el test y verificar que pasa**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test scope_store`
Expected: PASS, 6 tests.

- [ ] **Step 5: Implementar `state.rs`**

```rust
use std::path::PathBuf;
use std::sync::Mutex;

use rusqlite::Connection;

use crate::error::{AppError, Result};

pub struct OpenEngagement {
    pub id: String,
    pub conn: Connection,
}

pub struct AppState {
    pub root: PathBuf,
    pub open: Mutex<Option<OpenEngagement>>,
}

impl AppState {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            open: Mutex::new(None),
        }
    }

    /// Ejecuta `f` sobre la conexión del engagement abierto.
    pub fn with_open<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let guard = self.open.lock().expect("mutex envenenado");
        let abierto = guard.as_ref().ok_or(AppError::NoEngagementOpen)?;
        f(&abierto.conn)
    }

    /// Cierra el engagement abierto, si lo hay.
    ///
    /// Imprescindible antes de purgar: en Windows no se puede borrar un
    /// fichero con un descriptor abierto.
    pub fn close(&self) {
        let mut guard = self.open.lock().expect("mutex envenenado");
        *guard = None;
    }
}
```

- [ ] **Step 6: Cablear los comandos en `lib.rs`**

```rust
pub mod db;
pub mod engagement;
pub mod error;
pub mod paths;
pub mod scope;
pub mod state;

use tauri::{Manager, State};

use engagement::EngagementRef;
use error::Result;
use scope::{ScopeEntry, ScopeKind, SystemResolver};
use state::{AppState, OpenEngagement};

#[tauri::command]
fn engagement_create(state: State<AppState>, codename: String) -> Result<EngagementRef> {
    engagement::create(&state.root, &codename)
}

#[tauri::command]
fn engagement_list(state: State<AppState>) -> Result<Vec<EngagementRef>> {
    engagement::list(&state.root)
}

#[tauri::command]
fn engagement_open(state: State<AppState>, id: String) -> Result<EngagementRef> {
    let conn = engagement::open(&state.root, &id)?;
    let referencia = engagement::get(&state.root, &id)?;
    let mut guard = state.open.lock().expect("mutex envenenado");
    *guard = Some(OpenEngagement { id, conn });
    Ok(referencia)
}

#[tauri::command]
fn engagement_purge(state: State<AppState>, id: String) -> Result<EngagementRef> {
    // Cerrar antes de borrar: en Windows un fichero abierto no se borra.
    {
        let mut guard = state.open.lock().expect("mutex envenenado");
        if guard.as_ref().is_some_and(|o| o.id == id) {
            *guard = None;
        }
    }
    engagement::purge(&state.root, &id)
}

#[tauri::command]
fn scope_list(state: State<AppState>) -> Result<Vec<ScopeEntry>> {
    state.with_open(scope::list_entries)
}

#[tauri::command]
fn scope_add(
    state: State<AppState>,
    kind: ScopeKind,
    entry: String,
    note: Option<String>,
) -> Result<ScopeEntry> {
    state.with_open(|c| scope::add_entry(c, kind, &entry, note.as_deref()))
}

#[tauri::command]
fn scope_remove(state: State<AppState>, id: i64) -> Result<()> {
    state.with_open(|c| scope::remove_entry(c, id))
}

/// Comprueba un objetivo contra el alcance vigente. Devuelve las IPs
/// autorizadas o un error explicando por qué no.
#[tauri::command]
fn scope_check(state: State<AppState>, target: String) -> Result<Vec<String>> {
    state.with_open(|c| {
        let s = scope::load(c)?;
        let t = s.validate_target(&target, &SystemResolver)?;
        Ok(t.iter().map(ToString::to_string).collect())
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let root = app.path().app_data_dir()?;
            std::fs::create_dir_all(&root)?;
            app.manage(AppState::new(root));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            engagement_create,
            engagement_list,
            engagement_open,
            engagement_purge,
            scope_list,
            scope_add,
            scope_remove,
            scope_check,
        ])
        .run(tauri::generate_context!())
        .expect("error al arrancar AUscan");
}
```

```bash
cargo add --manifest-path src-tauri/Cargo.toml tauri-plugin-dialog
```

- [ ] **Step 7: Comprobar que compila y que la app arranca**

Run: `npm run check && npm run tauri:dev`
Expected: compila, se abre la ventana. Cerrarla.

- [ ] **Step 8: Commit**

```bash
git add src-tauri/src/scope.rs src-tauri/src/state.rs src-tauri/src/lib.rs \
        src-tauri/tests/scope_store.rs src-tauri/Cargo.toml src-tauri/Cargo.lock
git commit -m "$(cat <<'MSG'
feat: persistencia del alcance, estado compartido y comandos Tauri

engagement_purge cierra la conexión antes de borrar: en Windows un
fichero con descriptor abierto no se puede eliminar.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 11: Corpus compartido, espejo TypeScript y test de paridad

**Files:**
- Create: `fixtures/scope/corpus.json`, `src/domain/scope/inScope.ts`, `src/domain/scope/inScope.test.ts`
- Create: `src-tauri/tests/scope_parity.rs`

**Interfaces:**
- Consumes: `Scope::validate`, `scope::parse_entry` (Rust); nada previo en TS.
- Produces: `inScope(spec: ScopeSpec, target: string): Verdict` y `parseEntry(s: string)` en TS, más el corpus que ambos lados consumen.

**Cómo funciona la paridad:** el corpus declara casos con su veredicto esperado. Rust lo lee y afirma; TypeScript lo lee y afirma. Ninguno de los dos llama al otro — ambos se miden contra la misma verdad escrita. Si una implementación deriva, su test se pone rojo y el corpus dice exactamente en qué caso.

- [ ] **Step 1: Escribir el corpus**

`fixtures/scope/corpus.json` — solo direcciones de documentación, según las Global Constraints:

```json
{
  "_nota": "Corpus compartido por src-tauri/tests/scope_parity.rs y src/domain/scope/inScope.test.ts. Solo rangos RFC 5737 y RFC 3849.",
  "scopes": {
    "basico":   { "allow": ["198.51.100.0/24"], "deny": ["198.51.100.128/25"] },
    "vacio":    { "allow": [], "deny": [] },
    "soloDeny": { "allow": [], "deny": ["198.51.100.0/24"] },
    "unHost":   { "allow": ["203.0.113.7"], "deny": [] },
    "anchoV4":  { "allow": ["198.51.100.0/24"], "deny": ["198.51.100.0/25"] },
    "v6":       { "allow": ["2001:db8::/32"], "deny": ["2001:db8:dead::/48"] },
    "mixto":    { "allow": ["192.0.2.0/24", "2001:db8::/32"], "deny": ["192.0.2.66"] }
  },
  "cases": [
    { "scope": "basico",   "target": "198.51.100.0",   "expect": "in" },
    { "scope": "basico",   "target": "198.51.100.1",   "expect": "in" },
    { "scope": "basico",   "target": "198.51.100.127", "expect": "in" },
    { "scope": "basico",   "target": "198.51.100.128", "expect": "out" },
    { "scope": "basico",   "target": "198.51.100.255", "expect": "out" },
    { "scope": "basico",   "target": "198.51.99.255",  "expect": "out" },
    { "scope": "basico",   "target": "198.51.101.0",   "expect": "out" },
    { "scope": "basico",   "target": "no-soy-una-ip",  "expect": "invalid" },
    { "scope": "basico",   "target": "198.51.100.5/24","expect": "invalid" },
    { "scope": "basico",   "target": "198.51.100",     "expect": "invalid" },
    { "scope": "basico",   "target": "",               "expect": "invalid" },
    { "scope": "vacio",    "target": "198.51.100.5",   "expect": "empty-scope" },
    { "scope": "soloDeny", "target": "203.0.113.9",    "expect": "empty-scope" },
    { "scope": "soloDeny", "target": "198.51.100.5",   "expect": "empty-scope" },
    { "scope": "unHost",   "target": "203.0.113.7",    "expect": "in" },
    { "scope": "unHost",   "target": "203.0.113.8",    "expect": "out" },
    { "scope": "anchoV4",  "target": "198.51.100.5",   "expect": "out" },
    { "scope": "anchoV4",  "target": "198.51.100.200", "expect": "in" },
    { "scope": "v6",       "target": "2001:db8::1",    "expect": "in" },
    { "scope": "v6",       "target": "2001:0db8:0000:0000:0000:0000:0000:0001", "expect": "in" },
    { "scope": "v6",       "target": "2001:db8:dead:beef::1", "expect": "out" },
    { "scope": "v6",       "target": "2001:db9::1",    "expect": "out" },
    { "scope": "v6",       "target": "192.0.2.1",      "expect": "out" },
    { "scope": "mixto",    "target": "192.0.2.65",     "expect": "in" },
    { "scope": "mixto",    "target": "192.0.2.66",     "expect": "out" },
    { "scope": "mixto",    "target": "::ffff:192.0.2.65", "expect": "in" },
    { "scope": "mixto",    "target": "::ffff:192.0.2.66", "expect": "out" },
    { "scope": "mixto",    "target": "2001:db8::5",    "expect": "in" }
  ],
  "entries": [
    { "input": "198.51.100.0/24", "expect": "ok" },
    { "input": "203.0.113.7",     "expect": "ok" },
    { "input": "2001:db8::/32",   "expect": "ok" },
    { "input": "2001:db8::1",     "expect": "ok" },
    { "input": "198.51.100.5/24", "expect": "ambiguous" },
    { "input": "192.0.2.130/25",  "expect": "ambiguous" },
    { "input": "2001:db8::1/32",  "expect": "ambiguous" },
    { "input": "198.51.100.0/33", "expect": "invalid" },
    { "input": "no-soy-una-red",  "expect": "invalid" },
    { "input": "",                "expect": "invalid" }
  ]
}
```

**Restricción del corpus:** las v4-mapeadas se escriben solo en forma con puntos (`::ffff:192.0.2.65`), nunca hexadecimal (`::ffff:c000:241`). Rust normaliza ambas; el espejo TypeScript solo la primera, y meter la segunda haría fallar la paridad por una diferencia que no le importa a nadie.

- [ ] **Step 2: Escribir el test de paridad en Rust**

`src-tauri/tests/scope_parity.rs`:

```rust
use std::collections::HashMap;

use auscan_lib::error::AppError;
use auscan_lib::scope::{self, Scope, ScopeKind};
use serde::Deserialize;

#[derive(Deserialize)]
struct Corpus {
    scopes: HashMap<String, SpecJson>,
    cases: Vec<CaseJson>,
    entries: Vec<EntryJson>,
}

#[derive(Deserialize)]
struct SpecJson {
    allow: Vec<String>,
    deny: Vec<String>,
}

#[derive(Deserialize)]
struct CaseJson {
    scope: String,
    target: String,
    expect: String,
}

#[derive(Deserialize)]
struct EntryJson {
    input: String,
    expect: String,
}

const CORPUS: &str = include_str!("../../fixtures/scope/corpus.json");

fn construir(spec: &SpecJson) -> Scope {
    let mut e: Vec<(ScopeKind, String)> = Vec::new();
    for a in &spec.allow {
        e.push((ScopeKind::Allow, a.clone()));
    }
    for d in &spec.deny {
        e.push((ScopeKind::Deny, d.clone()));
    }
    Scope::from_entries(&e).expect("el corpus solo trae entradas válidas")
}

fn veredicto(s: &Scope, target: &str) -> &'static str {
    match s.validate(target) {
        Ok(_) => "in",
        Err(AppError::OutOfScope(_)) => "out",
        Err(AppError::EmptyScope) => "empty-scope",
        Err(AppError::InvalidAddress(_)) => "invalid",
        Err(otro) => panic!("veredicto inesperado: {otro:?}"),
    }
}

#[test]
fn el_guard_coincide_con_el_corpus() {
    let c: Corpus = serde_json::from_str(CORPUS).expect("corpus mal formado");
    for caso in &c.cases {
        let spec = c.scopes.get(&caso.scope).expect("scope inexistente en el corpus");
        let s = construir(spec);
        assert_eq!(
            veredicto(&s, &caso.target),
            caso.expect,
            "scope {} · objetivo {:?}",
            caso.scope,
            caso.target
        );
    }
}

#[test]
fn el_parser_de_entradas_coincide_con_el_corpus() {
    let c: Corpus = serde_json::from_str(CORPUS).expect("corpus mal formado");
    for e in &c.entries {
        let real = match scope::parse_entry(&e.input) {
            Ok(_) => "ok",
            Err(AppError::AmbiguousCidr(_)) => "ambiguous",
            Err(AppError::InvalidAddress(_)) => "invalid",
            Err(otro) => panic!("veredicto inesperado: {otro:?}"),
        };
        assert_eq!(real, e.expect, "entrada {:?}", e.input);
    }
}
```

```bash
cargo add --manifest-path src-tauri/Cargo.toml serde_json
```

- [ ] **Step 3: Ejecutar el test de Rust y verificar que pasa**

Run: `cargo test --manifest-path src-tauri/Cargo.toml --test scope_parity`
Expected: PASS, 2 tests. Si falla, es que el corpus y la implementación de la Tarea 8 discrepan: gana el que tenga razón, y se corrige el otro.

- [ ] **Step 4: Escribir el test del espejo TypeScript, que falla**

`src/domain/scope/inScope.test.ts`:

```ts
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { inScope, parseEntry, type ScopeSpec, type Verdict } from "./inScope";

type Corpus = {
  scopes: Record<string, ScopeSpec>;
  cases: { scope: string; target: string; expect: Verdict }[];
  entries: { input: string; expect: "ok" | "ambiguous" | "invalid" }[];
};

const corpus: Corpus = JSON.parse(
  readFileSync("fixtures/scope/corpus.json", "utf8"),
) as Corpus;

describe("espejo del guard", () => {
  it("coincide con el corpus en todos los casos", () => {
    for (const caso of corpus.cases) {
      const spec = corpus.scopes[caso.scope];
      expect(spec, `scope ${caso.scope} no está en el corpus`).toBeDefined();
      expect(
        inScope(spec!, caso.target),
        `scope ${caso.scope} · objetivo ${JSON.stringify(caso.target)}`,
      ).toBe(caso.expect);
    }
  });

  it("coincide con el corpus al parsear entradas", () => {
    for (const e of corpus.entries) {
      const r = parseEntry(e.input);
      const real = "net" in r ? "ok" : r.error;
      expect(real, `entrada ${JSON.stringify(e.input)}`).toBe(e.expect);
    }
  });
});
```

- [ ] **Step 5: Ejecutar el test y verificar que falla**

Run: `npx vitest run src/domain/scope/inScope.test.ts`
Expected: FAIL — no existe `./inScope`.

- [ ] **Step 6: Implementar el espejo**

`src/domain/scope/inScope.ts`:

```ts
// ESPEJO DEL GUARD. NO ES LA AUTORIDAD.
//
// Existe solo para dar feedback mientras se escribe un CIDR en la UI.
// La decisión real la toma src-tauri/src/scope.rs, y es la única que
// determina si una herramienta se lanza. Si este fichero y aquel
// divergen, el test de paridad contra fixtures/scope/corpus.json pone
// CI en rojo — que es exactamente lo que tiene que pasar.

export type ScopeSpec = { allow: string[]; deny: string[] };
export type Verdict = "in" | "out" | "empty-scope" | "invalid";
export type EntryError = "ambiguous" | "invalid";

type Addr = { v: bigint; bits: 32 | 128 };
type Net = { base: bigint; prefix: number; bits: 32 | 128 };

function parseIpv4(s: string): Addr | null {
  const p = s.split(".");
  if (p.length !== 4) return null;
  let v = 0n;
  for (const o of p) {
    if (!/^\d{1,3}$/.test(o)) return null;
    const n = Number(o);
    if (n > 255) return null;
    v = (v << 8n) | BigInt(n);
  }
  return { v, bits: 32 };
}

function parseIpv6(s: string): Addr | null {
  // v4-mapeadas: se canonicalizan a v4, igual que Ipv6Addr::to_ipv4_mapped
  // en Rust. Solo la forma con puntos; el corpus no usa la hexadecimal.
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(s);
  if (mapped) return parseIpv4(mapped[1]!);

  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];

  let groups: string[];
  if (halves.length === 1) {
    if (head.length !== 8) return null;
    groups = head;
  } else {
    const fill = 8 - head.length - tail.length;
    if (fill < 1) return null;
    groups = [...head, ...Array<string>(fill).fill("0"), ...tail];
  }

  let v = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
    v = (v << 16n) | BigInt(parseInt(g, 16));
  }
  return { v, bits: 128 };
}

export function parseAddr(s: string): Addr | null {
  const t = s.trim();
  if (!t) return null;
  return t.includes(":") ? parseIpv6(t) : parseIpv4(t);
}

function maskOf(prefix: number, bits: 32 | 128): bigint {
  const total = BigInt(bits);
  return ((1n << total) - 1n) ^ ((1n << (total - BigInt(prefix))) - 1n);
}

export function parseEntry(s: string): { net: Net } | { error: EntryError } {
  const t = s.trim();
  if (!t) return { error: "invalid" };

  const slash = t.indexOf("/");
  if (slash === -1) {
    const a = parseAddr(t);
    if (!a) return { error: "invalid" };
    return { net: { base: a.v, prefix: a.bits, bits: a.bits } };
  }

  const a = parseAddr(t.slice(0, slash));
  const pStr = t.slice(slash + 1);
  if (!a || !/^\d{1,3}$/.test(pStr)) return { error: "invalid" };

  const prefix = Number(pStr);
  if (prefix > a.bits) return { error: "invalid" };

  const base = a.v & maskOf(prefix, a.bits);
  // Bits de host puestos: ambiguo, se rechaza igual que en Rust.
  if (base !== a.v) return { error: "ambiguous" };

  return { net: { base, prefix, bits: a.bits } };
}

function contains(net: Net, a: Addr): boolean {
  if (net.bits !== a.bits) return false;
  return (a.v & maskOf(net.prefix, net.bits)) === net.base;
}

export function inScope(spec: ScopeSpec, target: string): Verdict {
  const a = parseAddr(target);
  if (!a) return "invalid";

  const allow: Net[] = [];
  for (const s of spec.allow) {
    const r = parseEntry(s);
    if ("net" in r) allow.push(r.net);
  }
  // Sin autorización explícita no hay nada autorizado.
  if (allow.length === 0) return "empty-scope";

  for (const s of spec.deny) {
    const r = parseEntry(s);
    if ("net" in r && contains(r.net, a)) return "out";
  }

  return allow.some((n) => contains(n, a)) ? "in" : "out";
}
```

- [ ] **Step 7: Ejecutar el test y verificar que pasa**

Run: `npx vitest run src/domain/scope/inScope.test.ts`
Expected: PASS, 2 tests.

- [ ] **Step 8: Comprobar la paridad de verdad**

Cambiar a mano el orden de las comprobaciones en `inScope` (poner el bucle de `deny` antes del `if (allow.length === 0)`) y ejecutar el test: **debe fallar** en el caso `soloDeny`. Deshacer el cambio.

Esto no es ceremonia: confirma que el test detecta una divergencia real en vez de pasar por casualidad.

- [ ] **Step 9: Commit**

```bash
git add fixtures/scope/corpus.json src/domain/scope src-tauri/tests/scope_parity.rs \
        src-tauri/Cargo.toml src-tauri/Cargo.lock
git commit -m "$(cat <<'MSG'
test: corpus compartido y paridad entre el guard y su espejo

Rust y TypeScript se miden contra el mismo corpus sin llamarse entre
ellos. Si una implementación deriva, el corpus dice en qué caso.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 12: Interfaz — Engagements y Alcance, con i18n

**Files:**
- Create: `src/i18n/index.ts`, `src/i18n/locales/es.json`, `src/i18n/locales/en.json`
- Create: `src/domain/model/types.ts`, `src/data/engagements.ts`, `src/store/useAppStore.ts`
- Create: `src/pages/Engagements.tsx`, `src/pages/Scope.tsx`
- Modify: `src/App.tsx`, `src/main.tsx`
- Test: `src/pages/Engagements.test.tsx`, `src/pages/Scope.test.tsx`

**Interfaces:**
- Consumes: comandos de la Tarea 10, `inScope` de la Tarea 11.
- Produces: `EngagementRef`, `ScopeEntry` (tipos TS), `useAppStore` con `{ engagements, current, scopeEntries, load(), create(codename), open(id), purge(id), addScope(kind, entry), removeScope(id) }`.

- [ ] **Step 1: Escribir los tipos y el envoltorio de `invoke`**

`src/domain/model/types.ts`:

```ts
export type EngagementState =
  | "draft" | "scoped" | "running" | "exported" | "purged";

export type EngagementRef = {
  id: string;
  codename: string;
  createdAt: string;
  state: EngagementState;
  purgedAt: string | null;
};

export type ScopeKind = "allow" | "deny";

export type ScopeEntry = {
  id: number;
  kind: ScopeKind;
  family: "v4" | "v6";
  cidr: string;
  note: string | null;
  createdAt: string;
};
```

`src/data/engagements.ts`:

```ts
import { invoke } from "@tauri-apps/api/core";

import type { EngagementRef, ScopeEntry, ScopeKind } from "../domain/model/types";

export const api = {
  list: () => invoke<EngagementRef[]>("engagement_list"),
  create: (codename: string) =>
    invoke<EngagementRef>("engagement_create", { codename }),
  open: (id: string) => invoke<EngagementRef>("engagement_open", { id }),
  purge: (id: string) => invoke<EngagementRef>("engagement_purge", { id }),
  scopeList: () => invoke<ScopeEntry[]>("scope_list"),
  scopeAdd: (kind: ScopeKind, entry: string, note?: string) =>
    invoke<ScopeEntry>("scope_add", { kind, entry, note: note ?? null }),
  scopeRemove: (id: number) => invoke<void>("scope_remove", { id }),
  scopeCheck: (target: string) => invoke<string[]>("scope_check", { target }),
};
```

- [ ] **Step 2: Escribir los ficheros de idioma**

`src/i18n/locales/es.json`:

```json
{
  "app": { "name": "AUscan" },
  "nav": { "engagements": "Engagements", "scope": "Alcance" },
  "engagements": {
    "title": "Engagements",
    "codename": "Nombre en clave",
    "codenameHint": "Un alias. Nunca el nombre real del cliente.",
    "create": "Crear",
    "open": "Abrir",
    "purge": "Purgar",
    "empty": "Todavía no hay ningún engagement.",
    "purgedAt": "Purgado el {{date}}",
    "confirmPurge": "Se borrarán todos los datos locales de «{{codename}}». La carpeta de exportación NO se toca: es tu entregable y vive fuera de la app.",
    "confirm": "Purgar definitivamente",
    "cancel": "Cancelar"
  },
  "scope": {
    "title": "Alcance",
    "allow": "Autorizado",
    "deny": "Excluido",
    "add": "Añadir",
    "remove": "Quitar",
    "placeholder": "198.51.100.0/24",
    "empty": "Sin ninguna entrada autorizada no se puede lanzar nada.",
    "check": "Comprobar objetivo",
    "verdict": {
      "in": "Dentro de alcance",
      "out": "Fuera de alcance",
      "empty-scope": "Alcance vacío: no hay nada autorizado",
      "invalid": "No es una dirección válida"
    },
    "entryError": {
      "ambiguous": "Ambiguo: usa la dirección de red o /32",
      "invalid": "No es una red válida"
    }
  }
}
```

`src/i18n/locales/en.json` — **las mismas claves**, traducidas:

```json
{
  "app": { "name": "AUscan" },
  "nav": { "engagements": "Engagements", "scope": "Scope" },
  "engagements": {
    "title": "Engagements",
    "codename": "Code name",
    "codenameHint": "An alias. Never the client's real name.",
    "create": "Create",
    "open": "Open",
    "purge": "Purge",
    "empty": "No engagements yet.",
    "purgedAt": "Purged on {{date}}",
    "confirmPurge": "All local data for \"{{codename}}\" will be deleted. The export folder is NOT touched: it is your deliverable and lives outside the app.",
    "confirm": "Purge permanently",
    "cancel": "Cancel"
  },
  "scope": {
    "title": "Scope",
    "allow": "Allowed",
    "deny": "Excluded",
    "add": "Add",
    "remove": "Remove",
    "placeholder": "198.51.100.0/24",
    "empty": "With no allowed entry, nothing can be launched.",
    "check": "Check target",
    "verdict": {
      "in": "In scope",
      "out": "Out of scope",
      "empty-scope": "Empty scope: nothing is authorised",
      "invalid": "Not a valid address"
    },
    "entryError": {
      "ambiguous": "Ambiguous: use the network address or /32",
      "invalid": "Not a valid network"
    }
  }
}
```

`src/i18n/index.ts`:

```ts
import i18n from "i18next";
import { initReactI18next } from "react-i18next";

import en from "./locales/en.json";
import es from "./locales/es.json";

// Idioma fijo, sin detector de entorno: en jsdom el detector elegiría
// "en" y los tests que afirman texto en español fallarían por una razón
// que no tiene nada que ver con lo que prueban. El selector de idioma
// llega cuando haya una pantalla de ajustes que lo justifique.
void i18n.use(initReactI18next).init({
  resources: { es: { translation: es }, en: { translation: en } },
  lng: "es",
  fallbackLng: "es",
  interpolation: { escapeValue: false },
});

export default i18n;
```

- [ ] **Step 3: Escribir el test de la pantalla de Engagements, que falla**

`src/pages/Engagements.test.tsx`:

```tsx
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import "../i18n";
import { Engagements } from "./Engagements";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

describe("Engagements", () => {
  beforeEach(() => {
    invoke.mockReset();
  });

  it("muestra los engagements existentes", async () => {
    invoke.mockImplementation((cmd: string) =>
      cmd === "engagement_list"
        ? Promise.resolve([
            {
              id: "7f3a4c2e-0b1d-4e5f-8a9b-1c2d3e4f5a6b",
              codename: "CLAVEL",
              createdAt: "2026-08-22T10:00:00Z",
              state: "draft",
              purgedAt: null,
            },
          ])
        : Promise.resolve(null),
    );

    render(<Engagements />);
    expect(await screen.findByText("CLAVEL")).toBeInTheDocument();
  });

  it("crea un engagement con el nombre en clave escrito", async () => {
    invoke.mockImplementation((cmd: string) =>
      cmd === "engagement_list" ? Promise.resolve([]) : Promise.resolve({
        id: "7f3a4c2e-0b1d-4e5f-8a9b-1c2d3e4f5a6b",
        codename: "ROMERO",
        createdAt: "2026-08-22T10:00:00Z",
        state: "draft",
        purgedAt: null,
      }),
    );

    render(<Engagements />);
    await userEvent.type(await screen.findByLabelText(/nombre en clave/i), "ROMERO");
    await userEvent.click(screen.getByRole("button", { name: /crear/i }));

    await waitFor(() => {
      expect(invoke).toHaveBeenCalledWith("engagement_create", { codename: "ROMERO" });
    });
  });

  it("pide confirmación antes de purgar y avisa de que la exportación no se toca", async () => {
    invoke.mockImplementation((cmd: string) =>
      cmd === "engagement_list"
        ? Promise.resolve([
            {
              id: "7f3a4c2e-0b1d-4e5f-8a9b-1c2d3e4f5a6b",
              codename: "CLAVEL",
              createdAt: "2026-08-22T10:00:00Z",
              state: "draft",
              purgedAt: null,
            },
          ])
        : Promise.resolve(null),
    );

    render(<Engagements />);
    await userEvent.click(await screen.findByRole("button", { name: /^purgar$/i }));

    expect(screen.getByText(/carpeta de exportación NO se toca/i)).toBeInTheDocument();
    expect(invoke).not.toHaveBeenCalledWith("engagement_purge", expect.anything());
  });
});
```

- [ ] **Step 4: Ejecutar el test y verificar que falla**

Run: `npx vitest run src/pages/Engagements.test.tsx`
Expected: FAIL — no existe `./Engagements`.

- [ ] **Step 5: Implementar el store y la pantalla**

`src/store/useAppStore.ts`:

```ts
import { create } from "zustand";

import { api } from "../data/engagements";
import type { EngagementRef, ScopeEntry, ScopeKind } from "../domain/model/types";

type AppStore = {
  engagements: EngagementRef[];
  current: EngagementRef | null;
  scopeEntries: ScopeEntry[];
  error: string | null;
  load: () => Promise<void>;
  create: (codename: string) => Promise<void>;
  open: (id: string) => Promise<void>;
  purge: (id: string) => Promise<void>;
  loadScope: () => Promise<void>;
  addScope: (kind: ScopeKind, entry: string) => Promise<void>;
  removeScope: (id: number) => Promise<void>;
};

const mensaje = (e: unknown): string =>
  typeof e === "string" ? e : e instanceof Error ? e.message : String(e);

export const useAppStore = create<AppStore>((set, get) => ({
  engagements: [],
  current: null,
  scopeEntries: [],
  error: null,

  load: async () => {
    try {
      set({ engagements: await api.list(), error: null });
    } catch (e) {
      set({ error: mensaje(e) });
    }
  },

  create: async (codename) => {
    try {
      await api.create(codename);
      await get().load();
    } catch (e) {
      set({ error: mensaje(e) });
    }
  },

  open: async (id) => {
    try {
      const current = await api.open(id);
      set({ current, error: null });
      await get().loadScope();
    } catch (e) {
      set({ error: mensaje(e) });
    }
  },

  purge: async (id) => {
    try {
      await api.purge(id);
      if (get().current?.id === id) set({ current: null, scopeEntries: [] });
      await get().load();
    } catch (e) {
      set({ error: mensaje(e) });
    }
  },

  loadScope: async () => {
    try {
      set({ scopeEntries: await api.scopeList(), error: null });
    } catch (e) {
      set({ error: mensaje(e) });
    }
  },

  addScope: async (kind, entry) => {
    try {
      await api.scopeAdd(kind, entry);
      await get().loadScope();
    } catch (e) {
      set({ error: mensaje(e) });
    }
  },

  removeScope: async (id) => {
    try {
      await api.scopeRemove(id);
      await get().loadScope();
    } catch (e) {
      set({ error: mensaje(e) });
    }
  },
}));
```

`src/pages/Engagements.tsx`:

```tsx
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { useAppStore } from "../store/useAppStore";

export function Engagements() {
  const { t } = useTranslation();
  const { engagements, load, create, open, purge, error } = useAppStore();
  const [codename, setCodename] = useState("");
  const [porPurgar, setPorPurgar] = useState<string | null>(null);

  useEffect(() => {
    void load();
  }, [load]);

  const objetivo = engagements.find((e) => e.id === porPurgar) ?? null;

  return (
    <section>
      <h1>{t("engagements.title")}</h1>
      {error && <p role="alert">{error}</p>}

      <form
        onSubmit={(ev) => {
          ev.preventDefault();
          if (codename.trim()) {
            void create(codename.trim());
            setCodename("");
          }
        }}
      >
        <label htmlFor="codename">{t("engagements.codename")}</label>
        <input
          id="codename"
          value={codename}
          onChange={(ev) => setCodename(ev.target.value)}
        />
        <small>{t("engagements.codenameHint")}</small>
        <button type="submit">{t("engagements.create")}</button>
      </form>

      {engagements.length === 0 ? (
        <p>{t("engagements.empty")}</p>
      ) : (
        <ul>
          {engagements.map((e) => (
            <li key={e.id}>
              <span>{e.codename}</span>
              <span>{e.state}</span>
              {e.state !== "purged" && (
                <>
                  <button type="button" onClick={() => void open(e.id)}>
                    {t("engagements.open")}
                  </button>
                  <button type="button" onClick={() => setPorPurgar(e.id)}>
                    {t("engagements.purge")}
                  </button>
                </>
              )}
            </li>
          ))}
        </ul>
      )}

      {objetivo && (
        <div role="dialog" aria-modal="true">
          <p>{t("engagements.confirmPurge", { codename: objetivo.codename })}</p>
          <button
            type="button"
            onClick={() => {
              void purge(objetivo.id);
              setPorPurgar(null);
            }}
          >
            {t("engagements.confirm")}
          </button>
          <button type="button" onClick={() => setPorPurgar(null)}>
            {t("engagements.cancel")}
          </button>
        </div>
      )}
    </section>
  );
}
```

- [ ] **Step 6: Ejecutar el test y verificar que pasa**

Run: `npx vitest run src/pages/Engagements.test.tsx`
Expected: PASS, 3 tests.

- [ ] **Step 7: Implementar la pantalla de Alcance con validación en vivo**

`src/pages/Scope.tsx` — usa el espejo de la Tarea 11 para dar veredicto mientras se escribe, y `api.scopeCheck` para la comprobación autoritativa contra Rust:

```tsx
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { api } from "../data/engagements";
import { inScope, parseEntry, type Verdict } from "../domain/scope/inScope";
import { useAppStore } from "../store/useAppStore";

export function Scope() {
  const { t } = useTranslation();
  const { scopeEntries, addScope, removeScope } = useAppStore();
  const [borrador, setBorrador] = useState("");
  const [objetivo, setObjetivo] = useState("");
  const [veredictoReal, setVeredictoReal] = useState<string | null>(null);

  const spec = useMemo(
    () => ({
      allow: scopeEntries.filter((e) => e.kind === "allow").map((e) => e.cidr),
      deny: scopeEntries.filter((e) => e.kind === "deny").map((e) => e.cidr),
    }),
    [scopeEntries],
  );

  const entradaParseada = borrador.trim() ? parseEntry(borrador) : null;
  const errorEntrada =
    entradaParseada && "error" in entradaParseada ? entradaParseada.error : null;

  // Feedback inmediato. NO es la decisión: la toma Rust en scope_check.
  const previsualizacion: Verdict | null = objetivo.trim()
    ? inScope(spec, objetivo)
    : null;

  return (
    <section>
      <h1>{t("scope.title")}</h1>

      <form
        onSubmit={(ev) => {
          ev.preventDefault();
          if (entradaParseada && "net" in entradaParseada) {
            void addScope("allow", borrador.trim());
            setBorrador("");
          }
        }}
      >
        <label htmlFor="entrada">{t("scope.allow")}</label>
        <input
          id="entrada"
          placeholder={t("scope.placeholder")}
          value={borrador}
          onChange={(ev) => setBorrador(ev.target.value)}
        />
        {errorEntrada && <p role="alert">{t(`scope.entryError.${errorEntrada}`)}</p>}
        <button type="submit" disabled={!entradaParseada || "error" in entradaParseada}>
          {t("scope.add")}
        </button>
      </form>

      {spec.allow.length === 0 && <p>{t("scope.empty")}</p>}

      <ul>
        {scopeEntries.map((e) => (
          <li key={e.id}>
            <span>{t(`scope.${e.kind}`)}</span>
            <code>{e.cidr}</code>
            <button type="button" onClick={() => void removeScope(e.id)}>
              {t("scope.remove")}
            </button>
          </li>
        ))}
      </ul>

      <div>
        <label htmlFor="objetivo">{t("scope.check")}</label>
        <input
          id="objetivo"
          value={objetivo}
          onChange={(ev) => {
            setObjetivo(ev.target.value);
            setVeredictoReal(null);
          }}
        />
        {previsualizacion && <p>{t(`scope.verdict.${previsualizacion}`)}</p>}
        <button
          type="button"
          onClick={() => {
            void api
              .scopeCheck(objetivo)
              .then((ips) => setVeredictoReal(ips.join(", ")))
              .catch((e: unknown) => setVeredictoReal(String(e)));
          }}
        >
          {t("scope.check")}
        </button>
        {veredictoReal && <output>{veredictoReal}</output>}
      </div>
    </section>
  );
}
```

`src/pages/Scope.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import "../i18n";
import { useAppStore } from "../store/useAppStore";
import { Scope } from "./Scope";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

describe("Scope", () => {
  it("avisa de que un CIDR con bits de host es ambiguo", async () => {
    render(<Scope />);
    await userEvent.type(screen.getByLabelText(/autorizado/i), "198.51.100.5/24");
    expect(await screen.findByRole("alert")).toHaveTextContent(/ambiguo/i);
  });

  it("previsualiza el veredicto con el espejo, sin llamar a Rust", async () => {
    useAppStore.setState({
      scopeEntries: [
        {
          id: 1, kind: "allow", family: "v4",
          cidr: "198.51.100.0/24", note: null,
          createdAt: "2026-08-22T10:00:00Z",
        },
      ],
    });
    invoke.mockReset();

    render(<Scope />);
    await userEvent.type(screen.getByLabelText(/comprobar objetivo/i), "198.51.100.9");

    expect(await screen.findByText(/dentro de alcance/i)).toBeInTheDocument();
    expect(invoke).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 8: Cablear la navegación en `App.tsx`**

```tsx
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { Engagements } from "./pages/Engagements";
import { Scope } from "./pages/Scope";

type Pantalla = "engagements" | "scope";

export default function App() {
  const { t } = useTranslation();
  const [pantalla, setPantalla] = useState<Pantalla>("engagements");

  return (
    <main>
      <nav>
        <button type="button" onClick={() => setPantalla("engagements")}>
          {t("nav.engagements")}
        </button>
        <button type="button" onClick={() => setPantalla("scope")}>
          {t("nav.scope")}
        </button>
      </nav>
      {pantalla === "engagements" ? <Engagements /> : <Scope />}
    </main>
  );
}
```

En `src/main.tsx`, importar `./i18n` antes de renderizar.

- [ ] **Step 9: Ejecutar la comprobación completa y probar a mano**

Run: `npm run check`
Expected: PASS.

Run: `npm run tauri:dev` — crear un engagement, abrirlo, añadir `198.51.100.0/24`, comprobar `198.51.100.9` (dentro) y `203.0.113.1` (fuera), purgar y confirmar que el aviso sobre la carpeta de exportación aparece.

- [ ] **Step 10: Commit**

```bash
git add src package.json package-lock.json
git commit -m "$(cat <<'MSG'
feat: pantallas de Engagements y Alcance con i18n es/en

El espejo del guard da veredicto mientras se escribe; la comprobación
autoritativa sigue viajando a Rust.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 13: CI y comprobaciones mecánicas

**Files:**
- Create: `scripts/checks/fixtures.mjs`, `scripts/checks/no-http-client.mjs`, `scripts/checks/i18n-parity.mjs`
- Create: `scripts/checks/checks.test.mjs`
- Create: `.github/workflows/ci.yml`
- Modify: `package.json`

**Interfaces:**
- Produces: `findForbiddenAddresses(text: string): string[]`, `findHttpClients(lockText: string): string[]`, `keyDiff(a: object, b: object): string[]`, cada una con un envoltorio CLI que sale con código 1 si encuentra algo.

**Por qué cada comprobación es una función pura con su test:** un script de CI que no se testea es un script que un día deja de comprobar nada y nadie se entera.

- [ ] **Step 1: Escribir los tests que fallan**

`scripts/checks/checks.test.mjs` — en JavaScript a propósito: los módulos
comprobados son `.mjs` y `tsc --noEmit` fallaría al no encontrarles
declaraciones de tipos. Añadir `"scripts"` a `exclude` en `tsconfig.json`.

```js
import { describe, expect, it } from "vitest";

import { findForbiddenAddresses } from "./fixtures.mjs";
import { keyDiff } from "./i18n-parity.mjs";
import { findHttpClients } from "./no-http-client.mjs";

describe("comprobación de fixtures", () => {
  it("acepta los rangos de documentación", () => {
    const ok = `198.51.100.5 192.0.2.1 203.0.113.9 2001:db8::1 02:00:5e:10:00:01`;
    expect(findForbiddenAddresses(ok)).toEqual([]);
  });

  it("rechaza direcciones RFC 1918, que podrían ser reales", () => {
    expect(findForbiddenAddresses("192.168.1.10")).toContain("192.168.1.10");
    expect(findForbiddenAddresses("10.0.0.5")).toContain("10.0.0.5");
    expect(findForbiddenAddresses("172.16.4.2")).toContain("172.16.4.2");
  });

  it("rechaza direcciones públicas", () => {
    expect(findForbiddenAddresses("8.8.8.8")).toContain("8.8.8.8");
  });

  it("rechaza IPv6 fuera del rango de documentación", () => {
    expect(findForbiddenAddresses("fe80::1234:5678:9abc:def0")).not.toEqual([]);
  });

  it("rechaza MAC que no sean localmente administradas", () => {
    expect(findForbiddenAddresses("00:1a:2b:3c:4d:5e")).toContain("00:1a:2b:3c:4d:5e");
  });
});

describe("comprobación de cliente HTTP", () => {
  it("detecta reqwest en Cargo.lock", () => {
    expect(findHttpClients('name = "reqwest"\nversion = "0.12.0"')).toContain("reqwest");
  });

  it("detecta axios en package-lock.json", () => {
    expect(findHttpClients('"node_modules/axios": { "version": "1.0.0" }')).toContain("axios");
  });

  it("no se inventa hallazgos", () => {
    expect(findHttpClients('name = "serde"\nname = "rusqlite"')).toEqual([]);
  });
});

describe("paridad de claves i18n", () => {
  it("no informa de nada cuando coinciden", () => {
    expect(keyDiff({ a: { b: 1 } }, { a: { b: 2 } })).toEqual([]);
  });

  it("informa de las claves que faltan a cada lado", () => {
    const d = keyDiff({ a: 1, b: 2 }, { a: 1, c: 3 });
    expect(d.join(" ")).toContain("b");
    expect(d.join(" ")).toContain("c");
  });

  it("detecta diferencias anidadas", () => {
    expect(keyDiff({ a: { b: 1, c: 2 } }, { a: { b: 1 } })).not.toEqual([]);
  });
});
```

- [ ] **Step 2: Ejecutar y verificar que falla**

Run: `npx vitest run scripts/checks/checks.test.mjs`
Expected: FAIL — no existen los módulos.

- [ ] **Step 3: Implementar `scripts/checks/fixtures.mjs`**

```js
// Comprueba que fixtures/ solo contiene direcciones de documentación.
// Un 192.168.1.x real y uno inventado son indistinguibles a simple
// vista, así que RFC 1918 está prohibido igual que las públicas.

const V4_PERMITIDOS = ["192.0.2.", "198.51.100.", "203.0.113."];
// Excepciones exactas: si hace falta añadir una, que se vea en el diff.
const V4_EXACTOS = ["0.0.0.0", "127.0.0.1"];

const RE_V4 = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
const RE_V6 = /\b[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){2,7}\b/gi;
const RE_MAC = /\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b/gi;

export function findForbiddenAddresses(text) {
  const malas = [];

  for (const m of text.matchAll(RE_V4)) {
    const ip = m[0];
    if (V4_EXACTOS.includes(ip)) continue;
    if (V4_PERMITIDOS.some((p) => ip.startsWith(p))) continue;
    malas.push(ip);
  }

  for (const m of text.matchAll(RE_MAC)) {
    const mac = m[0].toLowerCase();
    // Localmente administrada: segundo dígito hex del primer octeto en 2,6,a,e.
    if ("26ae".includes(mac[1])) continue;
    malas.push(m[0]);
  }

  for (const m of text.matchAll(RE_V6)) {
    const v6 = m[0].toLowerCase();
    if (RE_MAC.test(m[0])) continue;
    if (v6.startsWith("2001:db8")) continue;
    malas.push(m[0]);
  }

  return [...new Set(malas)];
}

// Envoltorio CLI
if (import.meta.url === `file://${process.argv[1]}`) {
  const { readdirSync, readFileSync, statSync } = await import("node:fs");
  const { join } = await import("node:path");

  const ficheros = [];
  const recorrer = (d) => {
    for (const e of readdirSync(d)) {
      const p = join(d, e);
      if (statSync(p).isDirectory()) recorrer(p);
      else ficheros.push(p);
    }
  };
  recorrer("fixtures");

  let fallos = 0;
  for (const f of ficheros) {
    const malas = findForbiddenAddresses(readFileSync(f, "utf8"));
    if (malas.length > 0) {
      console.error(`${f}: direcciones prohibidas → ${malas.join(", ")}`);
      fallos += malas.length;
    }
  }
  if (fallos > 0) {
    console.error(
      "\nfixtures/ solo admite RFC 5737 (192.0.2/24, 198.51.100/24, 203.0.113/24),\n" +
        "2001:db8::/32 y MAC localmente administradas.",
    );
    process.exit(1);
  }
  console.log("fixtures: sin direcciones prohibidas");
}
```

**Nota sobre los hostnames:** no se comprueban con expresión regular. Un patrón lo bastante amplio para pillar `srv.cliente.com` también pilla `package.json` y `v1.2.3`, y una comprobación que cría lobos deja de leerse. Los nombres se vigilan en revisión, y así se dice en `SECURITY.md`.

- [ ] **Step 4: Implementar `scripts/checks/no-http-client.mjs`**

```js
// La app no habla con la red: solo lo hacen las herramientas que lanza.
// Si aparece un cliente HTTP en los lockfiles, o es un descuido o es un
// cambio de diseño que merece discutirse en el PR.

const PROHIBIDOS = ["reqwest", "ureq", "isahc", "axios", "node-fetch"];

export function findHttpClients(lockText) {
  return PROHIBIDOS.filter((p) =>
    new RegExp(`["/]${p}["/@]|name = "${p}"`).test(lockText),
  );
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { readFileSync, existsSync } = await import("node:fs");
  let fallos = 0;
  for (const lock of ["src-tauri/Cargo.lock", "package-lock.json"]) {
    if (!existsSync(lock)) continue;
    const hallados = findHttpClients(readFileSync(lock, "utf8"));
    if (hallados.length > 0) {
      console.error(`${lock}: cliente HTTP encontrado → ${hallados.join(", ")}`);
      fallos += hallados.length;
    }
  }
  if (fallos > 0) {
    console.error("\nSi es intencionado, justifícalo en el PR y añade la excepción aquí.");
    process.exit(1);
  }
  console.log("sin clientes HTTP");
}
```

- [ ] **Step 5: Implementar `scripts/checks/i18n-parity.mjs`**

```js
export function keyDiff(a, b) {
  const claves = (o, prefijo = "") =>
    Object.entries(o).flatMap(([k, v]) =>
      v && typeof v === "object" && !Array.isArray(v)
        ? claves(v, `${prefijo}${k}.`)
        : [`${prefijo}${k}`],
    );

  const ca = new Set(claves(a));
  const cb = new Set(claves(b));

  return [
    ...[...ca].filter((k) => !cb.has(k)).map((k) => `falta en el segundo: ${k}`),
    ...[...cb].filter((k) => !ca.has(k)).map((k) => `falta en el primero: ${k}`),
  ];
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { readFileSync } = await import("node:fs");
  const es = JSON.parse(readFileSync("src/i18n/locales/es.json", "utf8"));
  const en = JSON.parse(readFileSync("src/i18n/locales/en.json", "utf8"));
  const d = keyDiff(es, en);
  if (d.length > 0) {
    console.error("Las claves de es.json y en.json no coinciden:");
    for (const l of d) console.error(`  ${l}`);
    process.exit(1);
  }
  console.log("i18n: claves en paridad");
}
```

- [ ] **Step 6: Ejecutar los tests y verificar que pasan**

Run: `npx vitest run scripts/checks/checks.test.mjs`
Expected: PASS, 11 tests.

- [ ] **Step 7: Enganchar las comprobaciones al pipeline**

En `package.json`:

```json
{
  "check:fixtures": "node scripts/checks/fixtures.mjs",
  "check:nohttp": "node scripts/checks/no-http-client.mjs",
  "check:i18n": "node scripts/checks/i18n-parity.mjs",
  "check": "npm run typecheck && npm run lint && npm run test && npm run check:rust && npm run check:fixtures && npm run check:nohttp && npm run check:i18n"
}
```

Run: `npm run check`
Expected: PASS. Si `check:fixtures` se queja del corpus de la Tarea 11, el corpus está mal y hay que arreglarlo — para eso está.

- [ ] **Step 8: Escribir el workflow de CI**

`.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  check:
    strategy:
      fail-fast: false
      matrix:
        os: [macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm

      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt

      - uses: Swatinem/rust-cache@v2
        with:
          workspaces: src-tauri

      - run: npm ci

      - name: Comprobaciones
        run: npm run check

      - name: Clippy
        run: cargo clippy --manifest-path src-tauri/Cargo.toml -- -D warnings

      - name: Formato de Rust
        run: cargo fmt --manifest-path src-tauri/Cargo.toml -- --check

      - name: Build
        run: npm run build && cargo build --manifest-path src-tauri/Cargo.toml
```

- [ ] **Step 9: Commit**

```bash
git add scripts .github package.json
git commit -m "$(cat <<'MSG'
ci: comprobaciones mecánicas de fixtures, cliente HTTP y paridad i18n

Cada comprobación es una función pura con sus tests: un script de CI que
no se testea acaba dejando de comprobar sin que nadie se entere.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Task 14: Documentación, ADRs y licencia

**Files:**
- Create: `README.md`, `SECURITY.md`, `LICENSE`, `docs/THREAT-MODEL.md`, `docs/DATA-POLICY.md`
- Create: `docs/adr/0001-no-empaquetar-binarios-de-terceros.md` … `0005-la-base-de-datos-la-posee-rust.md`

**Interfaces:** ninguna. Es la tarea que convierte las decisiones en algo que un tercero puede auditar sin leerse el código.

- [ ] **Step 1: Escribir los cinco ADRs**

Cada uno sigue la misma plantilla corta, con el contenido de §3 y §8 de la spec:

```markdown
# ADR-000N: <título>

**Fecha:** 2026-08-22 · **Estado:** aceptada

## Contexto
<el problema, en 3-5 líneas>

## Decisión
<qué se hace>

## Alternativas consideradas
<las que se descartaron, y por qué>

## Consecuencias
<lo que esto implica, incluido lo incómodo>
```

Los cinco, con su contenido en la spec:

| ADR | Fuente en la spec |
|---|---|
| `0001-no-empaquetar-binarios-de-terceros.md` | §3, más la licencia NPSL de nmap y la de Npcap |
| `0002-datos-efimeros-carpeta-por-engagement.md` | §5.1, §5.2, §10.3 |
| `0003-filevault-como-frontera-de-cifrado.md` | §3, §12 T10 |
| `0004-privilegios-en-macos.md` | §8 entera, incluido el resultado del spike de la Fase 0 |
| `0005-la-base-de-datos-la-posee-rust.md` | §4 «Divergencias respecto a saldio» |

**ADR-0004 se escribe con el resultado real del spike.** Si la Fase 0 no está hecha todavía, se deja el ADR en estado `propuesta` con las alternativas descritas y sin decisión, y se cierra cuando haya datos. Es la única excepción a la regla de no dejar nada pendiente, y es deliberada: escribir una decisión que aún no se ha tomado sería peor.

- [ ] **Step 2: Escribir `docs/DATA-POLICY.md`**

Qué se guarda, dónde y durante cuánto tiempo. Contenido de §5.1, §5.2, §10.3 de la spec, incluyendo explícitamente:

- La disposición en disco completa, con la ruta real en macOS y Windows.
- Que `index.db` solo contiene `id`, `codename`, `created_at`, `state`, `purged_at`.
- Que la lápida sobrevive a la purga, y **por qué**: demostrar cuándo se purgó vale más que no tener el registro.
- Que la carpeta de exportación no se purga nunca.
- Que no hay telemetría, ni cuentas, ni servidor, ni actualizaciones automáticas.
- Recomendación de excluir el app-data dir de Time Machine e iCloud.

- [ ] **Step 3: Escribir `docs/THREAT-MODEL.md`**

La tabla T1–T10 de §12 de la spec, con un párrafo por amenaza explicando la mitigación y **dónde está en el código** (`scope.rs`, `paths.rs`, `engagement.rs::purge`, `scripts/checks/`). Un modelo de amenazas que no apunta al código es una lista de intenciones.

- [ ] **Step 4: Escribir `SECURITY.md`**

- Cómo reportar un fallo de seguridad y en cuánto se responde.
- Qué está y qué no está en el alcance del proyecto.
- La regla de fixtures (§11 de la spec) y el aviso de que los hostnames se vigilan en revisión, no por expresión regular.
- Que AUscan solo hace detección: sin explotación, sin fuerza bruta, sin pruebas destructivas — y que añadir una capacidad activa exige tocar `allowed_flags`, que es visible en el diff.

- [ ] **Step 5: Escribir `README.md`**

Secciones, en este orden:

1. **Qué es y qué no es.** Recolección, no informe. La valoración la hace el consultor.
2. **Aviso legal.** Solo para auditorías con autorización expresa y escrita. Escanear sin permiso es ilegal en la mayoría de jurisdicciones. Sin excusas ni cursiva simpática.
3. **Requisitos.** Las herramientas no vienen empaquetadas: por qué (ADR-0001) y cómo instalarlas.
4. **Privilegios.** La decisión de §8, con lo que se pierde en modo sin privilegios dicho de forma concreta: *un host silencioso desaparece del inventario*.
5. **Política de datos.** Resumen de tres líneas con enlace a `DATA-POLICY.md`.
6. **Modelo de amenazas.** Resumen con enlace a `THREAT-MODEL.md`.
7. **Arquitectura.** El diagrama de §4 y la frase que la resume: *el adaptador describe y parsea; el núcleo ejecuta*.
8. **Desarrollo.** `npm run check`, `npm run tauri:dev`, y la regla de fixtures.
9. **Licencia.**

- [ ] **Step 6: Añadir la licencia**

MIT, con `nonnamme` como titular y 2026 como año.

```bash
curl -sL https://raw.githubusercontent.com/licenses/license-templates/master/templates/mit.txt \
  | sed 's/{{ year }}/2026/; s/{{ organization }}/nonnamme/' > LICENSE
```

Si no hay red, escribir el texto MIT a mano. **Esta elección es reversible y conviene confirmarla**: MIT permite que cualquiera reempaquete la herramienta sin devolver nada; una licencia copyleft como GPL-3.0 obligaría a publicar las modificaciones. Para un proyecto de portfolio, MIT maximiza la difusión; para una herramienta de seguridad, hay quien prefiere lo segundo.

- [ ] **Step 7: Comprobar que la documentación no se contradice con el código**

Recorrer `THREAT-MODEL.md` y confirmar, mitigación por mitigación, que el fichero y la función que cita existen de verdad:

```bash
grep -o 'src-tauri/src/[a-z_]*\.rs\|scripts/checks/[a-z-]*\.mjs' docs/THREAT-MODEL.md \
  | sort -u | while read -r f; do
      [ -e "$f" ] || echo "FALTA: $f"
    done
```

Expected: sin salida.

- [ ] **Step 8: Ejecutar la comprobación completa y commit**

Run: `npm run check`
Expected: PASS.

```bash
git add README.md SECURITY.md LICENSE docs/
git commit -m "$(cat <<'MSG'
docs: README, modelo de amenazas, política de datos, ADRs y licencia

El modelo de amenazas apunta al fichero y la función que implementan
cada mitigación: sin eso sería una lista de intenciones.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
)"
```

---

## Al terminar este plan

Tendrás una app que arranca, crea y abre engagements con su base propia, define y valida un alcance con el guard completamente testeado, purga de forma verificable y publica el porqué de cada decisión. No lanza ninguna herramienta todavía: eso es el plan siguiente.

**Lo que la spec pide y este plan no incluye, a propósito:** el vocabulario
cerrado de `observation.kind` (§5.5) es un `enum` de Rust cuyo único consumidor
son los adaptadores. Crearlo ahora sería un tipo sin nadie que lo use; entra
con el trait de adaptador. La columna ya existe y la restricción está escrita.

**Plan siguiente — Ejecución (Fases 3–5):** trait de adaptador y la verja de tres comprobaciones, preflight con detección de herramientas y matriz de capacidades, adaptador de nmap con parser XML y fixtures sintéticos, y la UI de ejecución con streaming, progreso y cancelación real.
