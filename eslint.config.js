import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["dist", "src-tauri", "node_modules"],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2020,
    },
    rules: {
      // TypeScript ya detecta identificadores no declarados; no-undef
      // desconoce los globals de DOM/Node aportados por los tipos y
      // produce falsos positivos.
      "no-undef": "off",
    },
  },
  {
    // Los scripts de comprobación corren en Node, no en el navegador.
    // Se declaran sus globals en vez de apagar la regla: aquí no hay
    // TypeScript detrás que cubra los identificadores no declarados.
    files: ["scripts/**/*.mjs"],
    languageOptions: {
      globals: { process: "readonly", console: "readonly" },
    },
  },
);
