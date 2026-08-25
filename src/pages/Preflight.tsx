import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { usePreflightStore } from "../store/usePreflightStore";

export function Preflight() {
  const { t } = useTranslation();
  const { report, loading, error, installing, run, install } = usePreflightStore();
  const [porInstalar, setPorInstalar] = useState<string | null>(null);

  useEffect(() => {
    void run();
  }, [run]);

  const objetivo = report?.tools.find((tool) => tool.toolId === porInstalar) ?? null;

  return (
    <section>
      <h1>{t("preflight.title")}</h1>
      {error && <p role="alert">{error}</p>}
      {loading && <p>{t("preflight.loading")}</p>}

      {report && (
        <>
          <p>
            {t("preflight.privileges")}: {report.privileged ? t("preflight.yes") : t("preflight.no")}
          </p>
          <p>
            {t("preflight.filevault")}: {t(`preflight.filevaultStatus.${report.filevault}`)}
          </p>

          {report.tools.length === 0 ? (
            <p>{t("preflight.empty")}</p>
          ) : (
            <ul>
              {report.tools.map((tool) => (
                <li key={tool.toolId}>
                  <span>{tool.toolId}</span>
                  <span>{t(`preflight.status.${tool.status.kind}`)}</span>
                  {tool.status.kind === "ok" && <span>{tool.status.version}</span>}
                  {(tool.status.kind === "missing" || tool.status.kind === "tooOld") && (
                    <>
                      <code>{tool.installCommand}</code>
                      <button
                        type="button"
                        onClick={() => void navigator.clipboard.writeText(tool.installCommand)}
                      >
                        {t("preflight.copy")}
                      </button>
                      <button type="button" onClick={() => setPorInstalar(tool.toolId)}>
                        {t("preflight.install")}
                      </button>
                    </>
                  )}
                </li>
              ))}
            </ul>
          )}
        </>
      )}

      {objetivo && (
        <div role="dialog" aria-modal="true">
          <p>{t("preflight.confirmInstall", { command: objetivo.installCommand })}</p>
          <button
            type="button"
            disabled={installing !== null}
            onClick={() => {
              void install(objetivo.toolId);
              setPorInstalar(null);
            }}
          >
            {t("preflight.confirm")}
          </button>
          <button type="button" onClick={() => setPorInstalar(null)}>
            {t("preflight.cancel")}
          </button>
        </div>
      )}
    </section>
  );
}
