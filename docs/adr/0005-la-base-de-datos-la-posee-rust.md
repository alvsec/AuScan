# ADR-0005: La base de datos la posee Rust

**Fecha:** 2026-08-22 · **Estado:** aceptada

## Contexto

El proyecto reutiliza la arquitectura de una app anterior donde el SQL vivía en
TypeScript vía `tauri-plugin-sql`. Aquí hay una restricción que allí no existía:
ninguna herramienta puede lanzarse contra un objetivo que no haya pasado por el
guard de alcance.

## Decisión

Rust posee la conexión y expone comandos. El frontend nunca ve SQL.
`src/data/` es una capa de tipos sobre `invoke`, no un cliente de base de datos.

## Alternativas consideradas

**`tauri-plugin-sql` con el SQL en TypeScript.** Más rápido de escribir y
coherente con el proyecto anterior. Pero la ejecución de herramientas, el
streaming, la cancelación y la purga ya están en Rust; separar las escrituras del
guard regalaría un camino por el que colar un objetivo sin validar, y la regla del
alcance solo es cierta si existe un único sitio que decide.

## Consecuencias

Cada operación necesita su comando en `lib.rs`, lo que es más ceremonia que
llamar a SQL desde el frontend. A cambio, `scope.rs` es la autoridad única y
`ScopedTarget` no se puede fabricar fuera de ese módulo. El espejo del alcance en
TypeScript existe solo para dar feedback mientras se escribe, va marcado como tal
en el propio fichero, y un corpus compartido obliga a que ambas implementaciones
coincidan (`fixtures/scope/corpus.json`).
