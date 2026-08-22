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
);
