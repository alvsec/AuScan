import { useState } from "react";
import { useTranslation } from "react-i18next";

import { Engagements } from "./pages/Engagements";
import { Preflight } from "./pages/Preflight";
import { Scope } from "./pages/Scope";

type Pantalla = "preflight" | "engagements" | "scope";

export default function App() {
  const { t } = useTranslation();
  const [pantalla, setPantalla] = useState<Pantalla>("preflight");

  return (
    <main>
      <nav>
        <button type="button" onClick={() => setPantalla("preflight")}>
          {t("nav.preflight")}
        </button>
        <button type="button" onClick={() => setPantalla("engagements")}>
          {t("nav.engagements")}
        </button>
        <button type="button" onClick={() => setPantalla("scope")}>
          {t("nav.scope")}
        </button>
      </nav>
      {pantalla === "preflight" && <Preflight />}
      {pantalla === "engagements" && <Engagements />}
      {pantalla === "scope" && <Scope />}
    </main>
  );
}
