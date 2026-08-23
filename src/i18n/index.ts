import i18n from "i18next";
import { initReactI18next } from "react-i18next";

import en from "./locales/en.json";
import es from "./locales/es.json";

// Idioma fijo, sin detector de entorno: en jsdom el detector elegiría
// "en" y los tests que afirman texto en español fallarían por una razón
// que no tiene nada que ver con lo que prueban. El selector de idioma
// llega cuando haya una pantalla de ajustes que lo justifique.
void i18n.use(initReactI18next).init({
  resources: { es: { translation: es }, en: { translation: en } },
  lng: "es",
  fallbackLng: "es",
  interpolation: { escapeValue: false },
});

export default i18n;
