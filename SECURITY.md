# Política de seguridad

## Reportar un fallo

Escribe a **nonnamme@protonmail.com** con el asunto `[AUscan] seguridad`.
Respondo en un plazo de 7 días. No abras un issue público para un fallo que
afecte al aislamiento del alcance o a la privacidad de los datos.

Si tienes un caso reproducible, incluye la entrada exacta. **No incluyas datos de
ninguna auditoría real**: reprodúcelo con direcciones de documentación
(`198.51.100.0/24`, `2001:db8::/32`).

## Qué está en el alcance del proyecto

- Cualquier camino por el que una herramienta pueda lanzarse contra un objetivo
  que no haya pasado por el guard de alcance.
- Cualquier forma de fabricar un `ScopedTarget` fuera de `scope.rs`.
- Datos de un engagement que sobrevivan a una purga.
- Cualquier conexión de red iniciada por la propia app.
- Escritura fuera del directorio del engagement o del destino de exportación.

## Qué no

- La seguridad de nmap, httpx, nuclei o las demás herramientas. AUscan las
  orquesta, no las audita. Reporta esos fallos a sus proyectos.
- Un atacante que ya tiene ejecución de código en la máquina.
- Que el documento de autorización sea auténtico. La app impone el alcance que se
  le declara; no puede validar el papel que hay detrás.

## Solo detección

AUscan no explota, no hace fuerza bruta y no ejecuta pruebas destructivas. Esto
no es una promesa de buena voluntad: las herramientas se invocarán con una lista
cerrada de banderas permitidas, y cualquier argv que se salga de ella no llega a
ejecutarse. Añadir una capacidad activa exige tocar esa lista, que es corta y
aparece señalada en el diff de cualquier pull request.

Si envías un PR que añade una capacidad activa, dilo en el título.

## Regla de datos sintéticos

`fixtures/` solo admite direcciones de documentación:

| Tipo | Permitido |
|---|---|
| IPv4 | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737) |
| IPv6 | `2001:db8::/32` (RFC 3849) |
| Nombres | `.example`, `example.com`, `example.org` (RFC 2606) |
| MAC | Localmente administradas (`02:`, `06:`, `0a:`, `0e:`) |

**RFC 1918 está prohibido**, aunque sea inventado: un `192.168.1.x` real y uno
falso son indistinguibles a simple vista, y la regla solo sirve si es
comprobable. CI la comprueba en cada push.

Los **nombres de host no se comprueban automáticamente**, y es deliberado: un
patrón lo bastante amplio para pillar `srv.cliente.com` también pilla
`package.json` y `v1.2.3`, y una comprobación que cría lobos acaba ignorándose.
Los nombres se vigilan en revisión de código. Si envías un PR con fixtures,
confirma en la descripción que no proceden de ningún sistema real.
