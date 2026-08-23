# ADR-0004: Privilegios en macOS

**Fecha:** 2026-08-22 · **Estado:** PROPUESTA — pendiente del spike

> Este ADR se cierra cuando exista el resultado empírico del spike descrito
> abajo. Escribir ahora una decisión que aún no se ha tomado sería peor que
> dejarlo abierto.

## Contexto

nmap necesita root en macOS para el escaneo SYN (`-sS`), la detección de sistema
operativo (`-O`) y el descubrimiento por ARP, que es lo que hace útil `-sn` en un
segmento local. Sin privilegios, el descubrimiento pasa de ARP —que ve todo lo
que tiene interfaz en el segmento— a sondas TCP, que ven lo que responde. **Un
host silencioso, como una impresora con los puertos cerrados o un PLC, desaparece
del inventario.** Es un agujero en el entregable, no una limitación cosmética.

El portátil Mac es la única máquina que pisa una auditoría, así que es donde la
capacidad completa importa.

## El discriminador no es la comodidad, es la cancelación

Si nmap corre como root y la app no, **la app no puede matarlo**: `kill(2)`
devuelve `EPERM`. La cancelación real, que es requisito, deja de funcionar en
cuanto se eleva, salvo que se diseñe explícitamente. Windows no mejora el
problema: un proceso de integridad media no puede abrir uno de integridad alta
con `PROCESS_TERMINATE`, y además `ShellExecuteEx` con el verbo `runas` no
permite redirigir stdio.

## Alternativas

**A. Sin privilegios.** `-sT`, `-sn` por TCP, más leer la caché ARP del sistema
(`arp -an`) tras el barrido, que devuelve MAC y fabricante de lo que el sistema
ya ha visto. Streaming, cancelación y trazabilidad triviales. El adaptador
`arp-scan` nace muerto y el inventario tiene el agujero de arriba.

**B. Elevación por ejecución** vía `osascript … with administrator privileges`.
El diálogo lo pinta el sistema y la contraseña nunca pasa por el proceso. Nada
queda instalado. La cancelación exige un wrapper centinela: el proceso root
vigila un fichero y mata a su hijo cuando aparece.

**C. Helper privilegiado launchd + XPC.** La forma canónica: cancelación por API,
una sola autenticación. A cambio deja un demonio root instalado permanentemente y
exige firma Developer ID. Superficie desproporcionada. **Descartada.**

## Spike que decide

Existe una vía que no se da por buena sin verificar: ChmodBPF, el `launchd` que
instala Wireshark, abre `/dev/bpf*` a un grupo y, combinado con `--send-eth`,
podría permitir SYN y ARP sin root en el segmento local. Su equivalente en
Windows es instalar Npcap sin la opción de restringir el driver a
administradores, que es una casilla soportada del instalador.

Procedimiento, en red propia:

1. Instalar ChmodBPF y confirmar pertenencia al grupo `access_bpf`.
2. `nmap -sn -PR --send-eth <rango propio>` sin `sudo`. ¿Hace ARP o cae a TCP?
3. Comparar el recuento de hosts con el mismo comando bajo `sudo`.
4. Anotar versión de nmap, versión de macOS y salida literal de ambos comandos.

**Si coinciden:** macOS trabaja sin privilegios de verdad y B queda como camino
raro. **Si no:** B deja de ser opcional.

## Invariantes que se mantienen pase lo que pase

- `-oX -` a stdout, nunca `-oX fichero`. Aunque nmap corra como root, en `raw/`
  no aparece un fichero propiedad de root que luego exija autenticarse para
  purgar.
- El guard se evalúa antes de construir el argv. Elevar no amplía el alcance:
  son ejes independientes.
- La app nunca corre entera como root.
