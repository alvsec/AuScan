import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useRunStore } from "../store/useRunStore";

const FASES = ["discovery", "portsweep", "services"] as const;

export function Run() {
  const { t } = useTranslation();
  const { estado, lineas, runsTerminados, error, iniciar, cancelar } = useRunStore();
  const [fase, setFase] = useState<(typeof FASES)[number]>("discovery");
  const [objetivosTexto, setObjetivosTexto] = useState("");
  const [confirmando, setConfirmando] = useState(false);

  const objetivos = objetivosTexto
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  const pedirConfirmacion = () => setConfirmando(true);

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
          onClick={pedirConfirmacion}
          disabled={estado === "corriendo" || objetivos.length === 0}
        >
          {t("run.lanzarBoton")}
        </button>
      )}

      {confirmando && (
        <div role="dialog" aria-label={t("run.confirmarTitulo")}>
          <p>{t("run.confirmarTitulo")}</p>
          <p>
            nmap {fase} {objetivos.join(" ")}
          </p>
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
