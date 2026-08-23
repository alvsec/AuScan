# ADR-0001: No empaquetar binarios de terceros

**Fecha:** 2026-08-22 · **Estado:** aceptada

## Contexto

AUscan orquesta herramientas maduras (nmap, httpx, nuclei) en vez de
reimplementarlas. La opción cómoda sería empaquetarlas en el bundle para que la
app funcione nada más instalarse.

## Decisión

No se empaqueta ningún binario de terceros. La app detecta lo que hay instalado
en el sistema, comprueba su versión y deshabilita con explicación las fases cuya
herramienta falte.

## Alternativas consideradas

**Empaquetar nmap.** Se distribuye bajo la NPSL, una licencia propia que no es
la GPL y que restringe la redistribución. Empaquetarla en un producto obligaría a
un análisis legal que no aporta nada al usuario.

**Empaquetar Npcap en Windows.** Además de tener su propia licencia restrictiva,
es un driver de kernel. Instalar un driver desde el bundle de una app de
auditoría es exactamente el tipo de decisión que merece escrutinio, y con razón.

## Consecuencias

El usuario tiene que instalar las herramientas por su cuenta; el preflight le da
el comando exacto y puede ejecutarlo con confirmación explícita. A cambio, el
repositorio no distribuye código de terceros, no hay que auditar licencias
ajenas en cada release, y la superficie de instalación es cero.
