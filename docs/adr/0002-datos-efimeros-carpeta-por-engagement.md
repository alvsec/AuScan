# ADR-0002: Datos efímeros, un directorio por engagement

**Fecha:** 2026-08-22 · **Estado:** aceptada

## Contexto

Los datos de una auditoría son de un cliente concreto y solo deben existir
mientras dure el encargo. La regla de privacidad exige poder purgarlos, y
"purgar" tiene que ser algo demostrable, no una intención.

## Decisión

Cada engagement es un directorio propio bajo el app-data dir, con su
`engagement.db` y su `raw/` dentro. Purgar es borrar ese directorio y comprobar
que ya no existe. Un `index.db` global guarda solo id, nombre en clave, fecha,
estado y marca de purga.

## Alternativas consideradas

**Una base global con `engagement_id` en cada tabla.** Más simple de consultar y
de migrar, pero purgar pasa a ser un `DELETE` cuya completitud depende de que
ningún índice, WAL o página libre retenga restos. Demostrarlo es difícil; en la
práctica nadie lo demuestra. Además datos de varios clientes conviven en el mismo
fichero.

**Guardar la salida cruda como BLOB en la base.** Un solo fichero que purgar,
pero un `-sV` sobre un rango grande hincha la base a decenas de megas y se pierde
poder hacer `grep` directo sobre `raw/` durante el trabajo.

## Consecuencias

El test de purga puede afirmar algo tan fuerte como "este path no existe"
(`src-tauri/tests/purge.rs`). Los datos de dos clientes nunca comparten fichero.
A cambio, listar engagements necesita el índice aparte, y hace falta
`PRAGMA temp_store = MEMORY` para que SQLite no derrame temporales fuera del
directorio, donde la purga no llegaría.
