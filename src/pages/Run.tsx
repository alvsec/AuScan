import { useState } from "react";
import { useTranslation } from "react-i18next";

import { api } from "../data/runs";
import { useRunStore } from "../store/useRunStore";

const FASES = ["discovery", "portsweep", "services"] as const;

const mensaje = (e: unknown): string =>
  typeof e === "string" ? e : e instanceof Error ? e.message : String(e);

export function Run() {
  const { t } = useTranslation();
  const { estado, lineas, runsTerminados, recuentoFinal, error, iniciar, cancelar } = useRunStore();
  const [fase, setFase] = useState<(typeof FASES)[number]>("discovery");
  const [objetivosTexto, setObjetivosTexto] = useState("");
  const [elevar, setElevar] = useState(false);
  const [confirmando, setConfirmando] = useState(false);
  const [previsualizacion, setPrevisualizacion] = useState<string[] | null>(null);
  // Error propio, separado del `error` de la tienda: aquel habla de una
  // ejecución que ya arrancó y falló; este, de una que ni siquiera llegó
  // a pedirse. Confundirlos haría que un objetivo fuera de alcance
  // rechazado en la vista previa se leyera como un escaneo fallido.
  const [errorPrevisualizacion, setErrorPrevisualizacion] = useState<string | null>(null);
  // `run_preview` cruza la frontera al backend y valida el alcance, lo
  // que incluye resolución DNS: puede tardar. Sin esta bandera el botón
  // seguía pulsable durante toda la ida y vuelta -- solo se sustituía por
  // el diálogo DESPUÉS de que la promesa resolviera -- así que un
  // operador impaciente encadenaba varias vistas previas en vuelo.
  const [cargandoPrevisualizacion, setCargandoPrevisualizacion] = useState(false);

  const objetivos = objetivosTexto
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  // El argv que se enseña lo calcula el backend con el mismo
  // `planificar` que usa la ejecución. Si `run_preview` falla -- un
  // objetivo fuera de alcance, sobre todo -- NO se abre el diálogo: el
  // operador se entera antes de autorizar algo que no podría correr.
  const pedirConfirmacion = async () => {
    setErrorPrevisualizacion(null);
    setCargandoPrevisualizacion(true);
    try {
      const lineas = await api.preview(fase, "nmap", objetivos, elevar);
      setPrevisualizacion(lineas);
      setConfirmando(true);
    } catch (e) {
      setErrorPrevisualizacion(mensaje(e));
      setConfirmando(false);
    } finally {
      // En `finally`, no al final del `try`: si la vista previa falla
      // -- un objetivo fuera de alcance, el caso más frecuente -- el
      // botón tiene que volver a estar pulsable para poder corregir el
      // objetivo y reintentar.
      setCargandoPrevisualizacion(false);
    }
  };

  const lanzar = async () => {
    setConfirmando(false);
    await iniciar(fase, "nmap", objetivos, elevar);
  };

  return (
    <section>
      <h1>{t("run.titulo")}</h1>

      {/* htmlFor/id explícitos, no envoltura implícita: es el patrón que
          ya usa Scope.tsx para todas sus etiquetas (p.ej. "entrada",
          "objetivo"), a diferencia de <label>texto<select/></label>. */}
      {/* `confirmando` bloquea la fase y los objetivos además de
          `corriendo`: el diálogo tiene que ser MODAL de verdad. `lanzar()`
          lee el `fase`/`objetivos` VIVOS, no aquellos con los que se
          calculó `previsualizacion`, así que si estos siguieran editables
          el operador podría previsualizar el objetivo A, ver el argv de A,
          cambiar el textarea a B con el diálogo abierto y pulsar
          «Ejecutar»: lanzaría B habiendo autorizado A. Sería la misma
          mentira que la vista previa con argv real existe para cerrar,
          solo que un paso más tarde. Con el diálogo abierto solo se puede
          confirmar o cancelar. */}
      <label htmlFor="fase">{t("run.fase")}</label>
      <select
        id="fase"
        value={fase}
        onChange={(e) => setFase(e.target.value as (typeof FASES)[number])}
        disabled={estado === "corriendo" || confirmando || cargandoPrevisualizacion}
      >
        {FASES.map((f) => (
          <option key={f} value={f}>
            {f}
          </option>
        ))}
      </select>

      <label htmlFor="objetivos">{t("run.objetivos")}</label>
      <textarea
        id="objetivos"
        value={objetivosTexto}
        onChange={(e) => setObjetivosTexto(e.target.value)}
        disabled={estado === "corriendo" || confirmando || cargandoPrevisualizacion}
      />

      {/* `elevar` es una PETICIÓN de elevación, nunca una prueba de
          privilegio: el backend la verifica él mismo. Se congela con las
          mismas tres condiciones que fase/objetivos porque cambia el argv
          tanto como ellos -- si se pudiera tocar con el diálogo abierto,
          el operador confirmaría un argv que ya no es el que se lanza. */}
      <label htmlFor="elevar">
        <input
          id="elevar"
          type="checkbox"
          checked={elevar}
          onChange={(e) => setElevar(e.target.checked)}
          disabled={estado === "corriendo" || confirmando || cargandoPrevisualizacion}
        />
        {t("run.elevar")}
      </label>

      {!confirmando && (
        <button
          type="button"
          onClick={() => void pedirConfirmacion()}
          disabled={estado === "corriendo" || objetivos.length === 0 || cargandoPrevisualizacion}
        >
          {t("run.lanzarBoton")}
        </button>
      )}

      {cargandoPrevisualizacion && <p>{t("run.previsualizando")}</p>}

      {errorPrevisualizacion && <p role="alert">{errorPrevisualizacion}</p>}

      {confirmando && previsualizacion && (
        <div role="dialog" aria-label={t("run.confirmarTitulo")}>
          <p>{t("run.confirmarTitulo")}</p>
          {/* Una línea por invocación, no un párrafo: una fase Services
              planifica una invocación por host y el operador tiene que
              ver TODAS las que está autorizando, no la primera. */}
          <ul data-testid="previsualizacion">
            {previsualizacion.map((linea, i) => (
              // Índice como clave a propósito: dos invocaciones de una
              // misma fase pueden tener argv idéntico, y la lista ni se
              // reordena ni se edita -- se pinta y se descarta.
              <li key={i}>{linea}</li>
            ))}
          </ul>
          <button type="button" onClick={() => void lanzar()}>
            {t("run.confirmarBoton")}
          </button>
          <button type="button" onClick={() => setConfirmando(false)}>
            {t("run.cancelarBoton")}
          </button>
        </div>
      )}

      {estado === "corriendo" && (
        <>
          <p>{t("run.corriendo")}</p>
          <button type="button" onClick={() => void cancelar()}>
            {t("run.cancelarEjecucionBoton")}
          </button>
        </>
      )}

      {error && <p role="alert">{error}</p>}

      {/* Lo que la fase archivó, no cuántas líneas escupió: el número de
          líneas de log no le dice al operador nada sobre el expediente.
          Con `error` puesto NO se enseña recuento ninguno: el camino de
          error de `run_start` emite "run:fase-terminada" con ceros
          cableados, pero una fase que falla en su n-ésima invocación ya
          ha archivado hosts, servicios y observaciones reales de las
          n-1 anteriores. Enseñar «0 hosts, 0 servicios, 0 observaciones»
          bajo el error sería falso sobre lo que hay en el expediente, y
          este programa no es más que ese expediente. Callar el número
          -- y que el operador mire el expediente -- es lo honesto; sacar
          los totales parciales por el camino de error costaría mucha
          fontanería para un caso que solo ocurre al fallar. */}
      {!error && recuentoFinal && (
        <p>
          {t("run.recuento", {
            hosts: recuentoFinal.hosts,
            servicios: recuentoFinal.servicios,
            observaciones: recuentoFinal.observaciones,
          })}
        </p>
      )}
      <pre data-testid="log">
        {lineas.length === 0
          ? t("run.sinLineas")
          : lineas.map((l) => `[${l.origen}] ${l.texto}`).join("\n")}
      </pre>

      {runsTerminados.length > 0 && (
        <ul>
          {runsTerminados.map((r) => (
            <li key={r.seq}>
              #{r.seq}: {r.status}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
