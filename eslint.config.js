import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default [
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.ts"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: {
        console: "readonly",
        process: "readonly",
        setInterval: "readonly",
        clearInterval: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        Buffer: "readonly",
        URL: "readonly",
        URLSearchParams: "readonly",
        fetch: "readonly",
        globalThis: "readonly",
      },
    },
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "warn",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "@typescript-eslint/no-explicit-any": "warn",
      "no-console": "off",
    },
  },
  {
    // Security hardening & prompt-guard intentionally scan for control chars / misleading
    // character sequences (homoglyphs, zero-width joiners, ANSI escapes). Silence the
    // regex-lint rules for those specific files.
    files: ["src/hardening.ts", "src/guards/prompt-guard.ts"],
    rules: {
      "no-control-regex": "off",
      "no-misleading-character-class": "off",
    },
  },
  {
    ignores: ["dist/**", "node_modules/**", "benchmark/**", "demo/**", "skills/**", "hooks/**"],
  },
];
