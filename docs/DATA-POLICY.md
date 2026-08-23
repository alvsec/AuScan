# Política de datos

Qué guarda AUscan, dónde y durante cuánto tiempo. Sin letra pequeña.

## Resumen

AUscan no tiene servidor, ni cuentas, ni telemetría, ni actualizaciones
automáticas. **La app no hace ninguna conexión de red.** Las únicas conexiones
que existen durante una auditoría las hacen las herramientas externas, contra el
alcance que tú autorizas.

## Dónde vive todo

```
macOS    ~/Library/Application Support/AUscan/
Windows  %APPDATA%\AUscan\

AUscan/
├─ index.db                    registro global (ver abajo)
└─ engagements/
   └─ <uuid>/
      ├─ engagement.db         alcance, ejecuciones, hosts, servicios,
      │                        observaciones
      └─ raw/                  salida original de cada herramienta
```

## Qué contiene `index.db`

Cinco columnas, y ninguna más:

| Columna | Contenido |
|---|---|
| `id` | UUID, que es también el nombre del directorio |
| `codename` | El nombre en clave que tú eliges. Nunca el del cliente |
| `created_at` | Fecha de creación, ISO-8601 UTC |
| `state` | `draft`, `scoped`, `running`, `exported` o `purged` |
| `purged_at` | Cuándo se purgó, o vacío |

Esto es deliberado y está fijado por un test
(`el_indice_no_guarda_nada_que_identifique_al_cliente`, en
`src-tauri/tests/engagement.rs`). El alcance, la persona que autorizó y la ruta
de exportación **no** están aquí: viven dentro del directorio del engagement y
mueren con él. Un path como `~/Clientes/ACME/` identifica a un cliente igual de
bien que su nombre.

## Qué contiene `engagement.db`

Alcance autorizado y exclusiones, quién autorizó y con qué referencia
documental, carpeta de exportación, y todo lo recolectado: ejecuciones con su
comando exacto, hosts, servicios y observaciones.

Una observación es un hecho neutro observado por una herramienta —"TLS 1.0
habilitado en host:puerto"—. **No lleva severidad, y no por convención: en el
esquema no existe la columna.** La valoración la haces tú al redactar el informe.

## Cuánto tiempo

Mientras tú quieras. La app propone purgar tras exportar, pero no purga sola.

## Qué pasa al purgar

1. Se cierra la conexión a la base.
2. Se borra el directorio del engagement entero, recursivamente.
3. Se comprueba que ya no existe. Si algo quedara, la purga falla con error.
4. La fila del índice **no se borra**: se convierte en lápida.

### Por qué queda una lápida

Tras purgar sobreviven `id`, `codename`, `created_at`, `purged_at` y el estado
`purged`. Nada más. Es el único rastro, y sobrevive a propósito: **poder
demostrar cuándo purgaste vale más que la coartada de no tener ni el registro.**

### Qué NO se purga

**La carpeta de exportación.** Es tu entregable, la eliges tú y vive fuera del
control de la app. La app no la toca nunca, y el diálogo de purga lo dice
explícitamente para que nadie confunda "he purgado" con "he borrado el trabajo".

## Temporales

Toda conexión se abre con `PRAGMA temp_store = MEMORY`. Sin eso, SQLite derrama
ficheros temporales en `/var/folders`, fuera del directorio del engagement, donde
la purga no llegaría. No es una optimización: es esta política aplicada al motor.

## Cifrado

No hay cifrado de aplicación. La frontera es el cifrado de disco del sistema.
El razonamiento completo está en [ADR-0003](adr/0003-filevault-como-frontera-de-cifrado.md),
y la consecuencia hay que decirla claramente: **en una máquina sin FileVault o
BitLocker, los datos del engagement están en claro en disco.**

## Recomendaciones

- Ten activado el cifrado de disco.
- Excluye el app-data dir de Time Machine, iCloud Drive y cualquier
  sincronización. Un backup automático deshace la purga sin que te enteres.
- Usa nombres en clave de verdad. `CLAVEL` es un nombre en clave; `ACME-2026` no.
