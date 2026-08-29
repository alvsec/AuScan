import { useState } from "react";
import { useTranslation } from "react-i18next";

import { api } from "../data/runs";
import { useRunStore } from "../store/useRunStore";

const FASES = ["discovery", "portsweep", "services"] as const;

const mensaje = (e: unknown): string =>
  typeof e === "string" ? e : e instanceof Error ? e.message : String(e);

export function Run() {
  const { t } = useTranslation();
  const { estado, lineas, runsTerminados, error, iniciar, cancelar } = useRunStore();
  const [fase, setFase] = useState<(typeof FASES)[number]>("discovery");
  const [objetivosTexto, setObjetivosTexto] = useState("");
  const [confirmando, setConfirmando] = useState(false);
  const [previsualizacion, setPrevisualizacion] = useState<string[] | null>(null);
  // Error propio, separado del `error` de la tienda: aquel habla de una
  // ejecución que ya arrancó y falló; este, de una que ni siquiera llegó
  // a pedirse. Confundirlos haría que un objetivo fuera de alcance
  // rechazado en la vista previa se leyera como un escaneo fallido.
  const [errorPrevisualizacion, setErrorPrevisualizacion] = useState<string | null>(null);

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
    try {
      const lineas = await api.preview(fase, "nmap", objetivos);
      setPrevisualizacion(lineas);
      setConfirmando(true);
    } catch (e) {
      setErrorPrevisualizacion(mensaje(e));
      setConfirmando(false);
    }
  };

  const lanzar = async () => {
    setConfirmando(false);
    await iniciar(fase, "nmap", objetivos);
  };

  return (
    <section>
      <h1>{t("run.titulo")}</h1>

      {/* htmlFor/id explícitos, no envoltura implícita: es el patrón que
          ya usa Scope.tsx para todas sus etiquetas (p.ej. "entrada",
          "objetivo"), a diferencia de <label>texto<select/></label>. */}
      <label htmlFor="fase">{t("run.fase")}</label>
      <select
        id="fase"
        value={fase}
        onChange={(e) => setFase(e.target.value as (typeof FASES)[number])}
        disabled={estado === "corriendo"}
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
        disabled={estado === "corriendo"}
      />

      {!confirmando && (
        <button
          type="button"
          onClick={() => void pedirConfirmacion()}
          disabled={estado === "corriendo" || objetivos.length === 0}
        >
          {t("run.lanzarBoton")}
        </button>
      )}

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

      <p>{t("run.recuento", { n: lineas.length })}</p>
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
