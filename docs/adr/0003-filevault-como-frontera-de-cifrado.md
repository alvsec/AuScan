# ADR-0003: FileVault como frontera de cifrado

**Fecha:** 2026-08-22 · **Estado:** aceptada

## Contexto

`engagement.db` contiene inventario de red de un cliente. La reacción instintiva
es cifrarlo a nivel de aplicación.

## Decisión

No hay cifrado de aplicación. El cifrado de disco del sistema —FileVault en
macOS, BitLocker en Windows— es la frontera, y se documenta como tal. El control
de privacidad fuerte de este proyecto es **no conservar los datos**, no cifrarlos.

## Alternativas consideradas

**Clave en el Keychain, cifrado transparente.** Cero fricción, pero su ganancia
real es estrecha: protege backups y discos sin cifrar, y no protege absolutamente
nada frente a un atacante que ya tiene la sesión abierta, porque la app lee la
clave y él también. Da sensación de seguridad sin aportarla. Además liga el
arranque a la identidad de firma del bundle, lo que rompe los builds sin firmar.

**Passphrase por engagement con Argon2id.** Es el único diseño que sí protege con
la máquina desbloqueada y la app cerrada, y sigue sobre la mesa para el futuro. Se
descarta en v1 por la fricción en cada apertura y porque perder la passphrase
significa perder el engagement a medias, sin recuperación posible.

## Consecuencias

Hay que decirlo con todas las letras en el README en vez de esconderlo: en una
máquina sin cifrado de disco, los datos del engagement están en claro. El
preflight avisará de ello. A cambio, no se transmite una falsa sensación de
seguridad y la purga sigue siendo el control principal.
