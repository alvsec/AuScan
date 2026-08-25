# AUscan

Aplicación de escritorio que automatiza la **fase de recolección** de una
auditoría de seguridad de red autorizada. Le das un alcance, orquesta un conjunto
de herramientas maduras, normaliza sus salidas y exporta artefactos estructurados
a la carpeta que elijas.

**AUscan no redacta el informe.** Produce el material con el que lo redactas tú.
Esa frase no es una nota de alcance: es una restricción de diseño que se nota en
el modelo de datos, donde una observación es un hecho neutro —"TLS 1.0 habilitado
en host:puerto"— y **no existe ninguna columna de severidad**. La valoración la
haces tú.

macOS primero, Windows en paridad de compilación.

---

## ⚠️ Uso autorizado únicamente

Escanear una red sin autorización expresa y por escrito de su propietario **es
delito** en España y en la mayoría de jurisdicciones. AUscan no comprueba —ni
puede comprobar— que tengas ese permiso: impone el alcance que tú le declaras y
confía en que se corresponda con lo que firmaste.

El esquema reserva quién autorizó el trabajo y la referencia del documento —es
la primera cosa que te van a preguntar si algo va mal—, pero **capturarlos es
parte de la siguiente fase**: hoy esas columnas existen y están vacías.

---

## Estado

En construcción. Ahora mismo existe la fundación: modelo de datos, ciclo de vida
del engagement, purga verificable y el guard de alcance completo con sus tests.
**Todavía no lanza ninguna herramienta de auditoría** — eso llega en las Fases
4 y 5. El preflight sí ejecuta ya comandos propios, locales y de solo lectura
(la versión de cada herramienta instalada, `fdesetup status` para FileVault)
para informar al operador antes de empezar; ninguno es una herramienta de red
ni forma parte de una auditoría.

## Cómo está construido

**Tauri 2 (Rust) · React 19 · TypeScript strict · SQLite · Vite · Zustand ·
i18next (es/en)**

La regla que ordena la arquitectura: *el adaptador describe y parsea; el núcleo
ejecuta*. Un adaptador de herramienta declara cómo detectarla, cómo construir su
comando y cómo interpretar su salida, pero **no la ejecuta**. Si cada adaptador
ejecutase, habría tantos sitios capaces de lanzar un proceso como herramientas, y
por tanto tantos sitios donde saltarse el guard de alcance. La regla del alcance
solo es cierta si existe un único sitio que lanza.

```
src/          React · lógica de dominio pura · espejo del alcance (solo UX)
src-tauri/    Rust · scope.rs es la autoridad · migraciones append-only
fixtures/     salidas sintéticas. Jamás de un cliente
docs/adr/     las decisiones grandes, con sus alternativas
```

## El alcance es lo importante

`scope.rs` es el corazón del proyecto y el único módulo capaz de construir un
`ScopedTarget`. El campo es privado y no hay constructor público: fuera de ahí es
imposible fabricar uno, así que cualquier función que reciba un `ScopedTarget`
sabe **por el tipo** que la dirección está autorizada.

- `deny` gana sobre `allow` siempre, sin importar la especificidad.
- Un alcance sin ninguna entrada `allow` rechaza **todo**. El defecto es "nada
  autorizado".
- Un `/0` se rechaza: autorizar todo el espacio de direcciones no es un alcance.
- Los objetivos viajan como IP, nunca como nombre. Un nombre se resuelve antes y,
  si una sola de sus direcciones cae fuera, se rechaza la petición entera.

Hay un espejo del guard en TypeScript para dar feedback mientras escribes un
CIDR. **No decide nada**, va marcado como tal en el propio fichero, y un corpus
compartido obliga a que ambas implementaciones lleguen al mismo veredicto: si
divergen, CI se pone roja y el corpus dice en qué caso exacto.

## Privilegios

nmap necesita root en macOS para el escaneo SYN, la detección de sistema
operativo y el descubrimiento por ARP. **Sin privilegios, el descubrimiento pasa
de ARP —que ve todo lo que tiene interfaz en el segmento— a sondas TCP, que ven
lo que responde. Un host silencioso, como una impresora con los puertos cerrados
o un PLC, desaparece del inventario.**

El diseño por defecto es sin privilegios, con elevación explícita por ejecución
si hace falta, y la app nunca corre entera como root. Lo que decide si "hace
falta" es un experimento pendiente, y hasta tenerlo la decisión sigue abierta a
propósito: [ADR-0004](docs/adr/0004-privilegios-en-macos.md).

El detalle que más condiciona el diseño no es la comodidad, es la cancelación: si
nmap corre como root y la app no, la app no puede matarlo.

## Datos

Sin telemetría, sin cuentas, sin servidor. **La app no abre ninguna conexión de
red por su cuenta**: las conexiones contra el alcance las hacen las herramientas
que lanza. Dos excepciones previstas, las dos explícitas y acotadas:

- La resolución de nombres, solo cuando lances una ejecución contra un
  objetivo escrito como nombre en vez de como IP; la comprobación de alcance
  de la pantalla acepta solo direcciones literales precisamente para no
  convertirse en un canal de salida.
- La instalación de una herramienta que falte: usa el gestor de paquetes del
  propio sistema (`brew install` en macOS, `winget install` en Windows), lo
  que implica descarga por red, pero solo cuando el operador confirma
  expresamente instalarla — nunca automática, nunca silenciosa.

Cada engagement vive en su propio directorio, con su base y su salida cruda
dentro. Purgar es borrar ese directorio y comprobar que no queda nada — un test
lo afirma. Queda una lápida con la fecha de purga, a propósito: poder demostrar
cuándo purgaste vale más que no tener ni el registro.

La carpeta de exportación **no se purga nunca**: es tu entregable.

Detalle completo en [DATA-POLICY.md](docs/DATA-POLICY.md). Amenazas de la propia
app, con el fichero y la función que mitigan cada una, en
[THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Herramientas: no vienen incluidas

AUscan no empaqueta binarios de terceros y detecta lo que tengas instalado. nmap
se distribuye bajo la NPSL, una licencia propia que restringe la redistribución;
Npcap en Windows tiene la suya y además es un driver de kernel. Depender de lo
instalado en el sistema es la decisión correcta:
[ADR-0001](docs/adr/0001-no-empaquetar-binarios-de-terceros.md).

## Desarrollo

```bash
npm install
npm run check      # typecheck · lint · vitest · cargo test · checks de CI
npm run tauri:dev
```

`npm run check` debe quedar en verde. Incluye tres comprobaciones mecánicas que
convierten reglas del proyecto en propiedades verificadas:

- **`check:fixtures`** — `fixtures/` solo admite direcciones de documentación.
  RFC 1918 prohibido, aunque sea inventado.
- **`check:nohttp`** — ningún cliente HTTP en el grafo de dependencias. Si no
  puede comprobarlo, falla en vez de pasar.
- **`check:i18n`** — paridad de claves entre `es.json` y `en.json`.

Antes de enviar fixtures, lee la regla de datos sintéticos en
[SECURITY.md](SECURITY.md).

## Licencia

MIT. Ver [LICENSE](LICENSE).
