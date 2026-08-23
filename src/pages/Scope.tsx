import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { api } from "../data/engagements";
import { inScope, parseEntry, type Verdict } from "../domain/scope/inScope";
import { useAppStore } from "../store/useAppStore";

export function Scope() {
  const { t } = useTranslation();
  const { scopeEntries, addScope, removeScope } = useAppStore();
  const [borrador, setBorrador] = useState("");
  const [objetivo, setObjetivo] = useState("");
  const [veredictoReal, setVeredictoReal] = useState<string | null>(null);

  const spec = useMemo(
    () => ({
      allow: scopeEntries.filter((e) => e.kind === "allow").map((e) => e.cidr),
      deny: scopeEntries.filter((e) => e.kind === "deny").map((e) => e.cidr),
    }),
    [scopeEntries],
  );

  const entradaParseada = borrador.trim() ? parseEntry(borrador) : null;
  const errorEntrada =
    entradaParseada && "error" in entradaParseada ? entradaParseada.error : null;

  // Feedback inmediato mientras se escribe. NO es la decisión: la toma
  // Rust en scope_check, y es la única que gobierna si algo se lanza.
  const previsualizacion: Verdict | null = objetivo.trim()
    ? inScope(spec, objetivo)
    : null;

  return (
    <section>
      <h1>{t("scope.title")}</h1>

      <form
        onSubmit={(ev) => {
          ev.preventDefault();
          if (entradaParseada && "net" in entradaParseada) {
            void addScope("allow", borrador.trim());
            setBorrador("");
          }
        }}
      >
        <label htmlFor="entrada">{t("scope.allow")}</label>
        <input
          id="entrada"
          placeholder={t("scope.placeholder")}
          value={borrador}
          onChange={(ev) => setBorrador(ev.target.value)}
        />
        {errorEntrada && <p role="alert">{t(`scope.entryError.${errorEntrada}`)}</p>}
        <button
          type="submit"
          disabled={!entradaParseada || "error" in entradaParseada}
        >
          {t("scope.add")}
        </button>
      </form>

      {spec.allow.length === 0 && <p>{t("scope.empty")}</p>}

      <ul>
        {scopeEntries.map((e) => (
          <li key={e.id}>
            <span>{t(`scope.${e.kind}`)}</span>
            <code>{e.cidr}</code>
            <button type="button" onClick={() => void removeScope(e.id)}>
              {t("scope.remove")}
            </button>
          </li>
        ))}
      </ul>

      <div>
        <label htmlFor="objetivo">{t("scope.check")}</label>
        <input
          id="objetivo"
          value={objetivo}
          onChange={(ev) => {
            setObjetivo(ev.target.value);
            setVeredictoReal(null);
          }}
        />
        {previsualizacion && <p>{t(`scope.verdict.${previsualizacion}`)}</p>}
        <button
          type="button"
          onClick={() => {
            void api
              .scopeCheck(objetivo)
              .then((ips) => setVeredictoReal(ips.join(", ")))
              .catch((e: unknown) => setVeredictoReal(String(e)));
          }}
        >
          {t("scope.check")}
        </button>
        {veredictoReal && <output>{veredictoReal}</output>}
      </div>
    </section>
  );
}
