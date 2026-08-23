import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { useAppStore } from "../store/useAppStore";

export function Engagements() {
  const { t } = useTranslation();
  const { engagements, load, create, open, purge, error } = useAppStore();
  const [codename, setCodename] = useState("");
  const [porPurgar, setPorPurgar] = useState<string | null>(null);

  useEffect(() => {
    void load();
  }, [load]);

  const objetivo = engagements.find((e) => e.id === porPurgar) ?? null;

  return (
    <section>
      <h1>{t("engagements.title")}</h1>
      {error && <p role="alert">{error}</p>}

      <form
        onSubmit={(ev) => {
          ev.preventDefault();
          if (codename.trim()) {
            void create(codename.trim());
            setCodename("");
          }
        }}
      >
        <label htmlFor="codename">{t("engagements.codename")}</label>
        <input
          id="codename"
          value={codename}
          onChange={(ev) => setCodename(ev.target.value)}
        />
        <small>{t("engagements.codenameHint")}</small>
        <button type="submit">{t("engagements.create")}</button>
      </form>

      {engagements.length === 0 ? (
        <p>{t("engagements.empty")}</p>
      ) : (
        <ul>
          {engagements.map((e) => (
            <li key={e.id}>
              <span>{e.codename}</span>
              <span>{e.state}</span>
              {e.state !== "purged" && (
                <>
                  <button type="button" onClick={() => void open(e.id)}>
                    {t("engagements.open")}
                  </button>
                  <button type="button" onClick={() => setPorPurgar(e.id)}>
                    {t("engagements.purge")}
                  </button>
                </>
              )}
            </li>
          ))}
        </ul>
      )}

      {objetivo && (
        <div role="dialog" aria-modal="true">
          <p>{t("engagements.confirmPurge", { codename: objetivo.codename })}</p>
          <button
            type="button"
            onClick={() => {
              void purge(objetivo.id);
              setPorPurgar(null);
            }}
          >
            {t("engagements.confirm")}
          </button>
          <button type="button" onClick={() => setPorPurgar(null)}>
            {t("engagements.cancel")}
          </button>
        </div>
      )}
    </section>
  );
}
