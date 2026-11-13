import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

const typeChecked = [js.configs.recommended, ...tseslint.configs.strictTypeChecked];

export default tseslint.config(
  { ignores: ["node_modules"] },
  {
    files: ["src/**/*.{ts,tsx}"],
    extends: typeChecked,
    languageOptions: {
      globals: globals.browser,
      parserOptions: { project: "./tsconfig.json", tsconfigRootDir: import.meta.dirname },
    },
    plugins: { "react-hooks": reactHooks },
    rules: reactHooks.configs.recommended.rules,
  },
  {
    files: ["vite.config.ts", "playwright.config.ts", "e2e/**/*.ts"],
    extends: typeChecked,
    languageOptions: {
      globals: { ...globals.node, ...globals.browser },
      parserOptions: { project: "./tsconfig.node.json", tsconfigRootDir: import.meta.dirname },
    },
  },
  {
    files: ["eslint.config.js"],
    extends: [js.configs.recommended],
    languageOptions: { globals: globals.node },
  },
);
