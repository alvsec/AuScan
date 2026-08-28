# ADR-0004: Privilegios en macOS

**Fecha:** 2026-08-22 · **Resuelto:** 2026-08-27 · **Estado:** RESUELTA — B (elevación por ejecución) es necesaria

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

## Resultado del spike

Ejecutado en red propia (198.51.100.0/24 en esta ADR — direcciones de
documentación RFC 5737, la red real era un /24 doméstico normal), 2026-08-27.
macOS 26.5.2 (25F84), nmap 7.991. ChmodBPF instalado y verificado (usuario en
el grupo `access_bpf`, `/dev/bpf*` con permisos de grupo).

**Sin privilegios:**

```
$ nmap -sn -PR --send-eth 198.51.100.0/24
Nmap scan report for 198.51.100.1
Host is up (0.012s latency).
Nmap scan report for 198.51.100.136
Host is up (0.0023s latency).
Nmap done: 256 IP addresses (2 hosts up) scanned in 22.56 seconds
```

**Con privilegios (`sudo`), mismo comando:**

```
$ sudo nmap -sn -PR --send-eth 198.51.100.0/24
Nmap scan report for 198.51.100.1
Host is up (0.059s latency).
MAC Address: 02:1A:2B:00:01:01 (Synthetic Devices)
Nmap scan report for 198.51.100.133
Host is up (0.13s latency).
MAC Address: 82:F7:6B:74:DE:92 (Unknown)
Nmap scan report for 198.51.100.140
Host is up (0.13s latency).
MAC Address: 02:1A:2B:00:01:02 (Synthetic Devices)
Nmap scan report for 198.51.100.170
Host is up (0.17s latency).
MAC Address: 02:1A:2B:00:01:03 (Synthetic Devices)
Nmap scan report for 198.51.100.136
Host is up.
Nmap done: 256 IP addresses (5 hosts up) scanned in 4.93 seconds
```

Direcciones IP y MAC de fabricante real sustituidas por sus equivalentes de
documentación (RFC 5737) y sintéticas — la `82:F7:6B:74:DE:92` no se toca
porque ya es una MAC administrada localmente (bit U/L real, no una asignación
de fabricante), que es precisamente por lo que nmap la reporta como
"Unknown": no identifica nada real que redactar. La conclusión del spike
depende del recuento de hosts, de si aparece MAC/fabricante y de la
velocidad — ninguno de los tres cambia por esta sustitución.

**No coinciden, en tres sentidos:**

1. **Recuento.** 2 hosts sin privilegios frente a 5 con `sudo` — tres
   dispositivos reales del segmento (`.133`, `.140`, `.170`) desaparecen sin
   root. Es exactamente el agujero de inventario que este ADR anticipaba.
2. **Identidad.** Ninguno de los dos hosts que sí aparecen sin privilegios
   trae MAC ni fabricante; los cinco con `sudo` sí. Esa es la firma de que
   `--send-eth` no está construyendo tramas Ethernet reales sin root:
   ChmodBPF no bastó para dárselo a nmap en esta máquina.
3. **Velocidad.** 22.56 s sin privilegios frente a 4.93 s con `sudo`, pese a
   que este último encuentra más hosts. Un ARP real barre un /24 en segundos;
   22 segundos con menos resultados es la firma de una sonda TCP/ICMP de
   reserva, no de ARP.

## Decisión

**B (elevación por ejecución) deja de ser opcional.** ChmodBPF por sí solo no
da a nmap acceso a paquetes crudos sin root en esta configuración. La fase de
elevación —antes condicional y numerada "Fase 9"— sube en el plan a justo
detrás de la Fase 5 (§14 de la spec), tal y como este mismo ADR preveía para
este resultado.

Esto no cambia nada de lo ya diseñado para la Fase 5: `PlanContext.privileged`
sigue saliendo de `running_privileged()` real, que en la práctica seguirá
siendo `false` hasta que la fase de elevación exista. La Fase 5 se implementa
igual que si el spike no se hubiera corrido; lo único que cambia es qué fase
viene justo después.

No se ha probado el equivalente en Windows (Npcap sin restricción a
administradores) — sigue pendiente si en algún momento se retoma trabajo de
descubrimiento en esa plataforma, aunque no es donde se hacen las auditorías.

## Invariantes que se mantienen pase lo que pase

- `-oX -` a stdout, nunca `-oX fichero`. Aunque nmap corra como root, en `raw/`
  no aparece un fichero propiedad de root que luego exija autenticarse para
  purgar.
- El guard se evalúa antes de construir el argv. Elevar no amplía el alcance:
  son ejes independientes.
- La app nunca corre entera como root.
