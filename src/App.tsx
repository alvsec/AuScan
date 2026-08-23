import { useState } from "react";
import { useTranslation } from "react-i18next";

import { Engagements } from "./pages/Engagements";
import { Scope } from "./pages/Scope";

type Pantalla = "engagements" | "scope";

export default function App() {
  const { t } = useTranslation();
  const [pantalla, setPantalla] = useState<Pantalla>("engagements");

  return (
    <main>
      <nav>
        <button type="button" onClick={() => setPantalla("engagements")}>
          {t("nav.engagements")}
        </button>
        <button type="button" onClick={() => setPantalla("scope")}>
          {t("nav.scope")}
        </button>
      </nav>
      {pantalla === "engagements" ? <Engagements /> : <Scope />}
    </main>
  );
}
